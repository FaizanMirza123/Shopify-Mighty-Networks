import os
import json
import string
import secrets
import httpx
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

import database as db

# Load environment variables from base directory
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

MIGHTY_NETWORKS_API = os.getenv("MIGHTY_NETWORKS_API")
NETWORK_ID = os.getenv("NETWORK_ID")
SHOPIFY_X_ACCESS_TOKEN = os.getenv("SHOPIFY_X_ACCESS_TOKEN")
SHOPIFY_STORE_NAME = os.getenv("SHOPIFY_STORE_NAME")
ZAPIER_WEBHOOK_URL = os.getenv("ZAPIER_WEBHOOK_URL")

# Load SKU mapping
SKU_MAPPING_PATH = os.path.join(os.path.dirname(__file__), "sku_mapping.json")
with open(SKU_MAPPING_PATH, "r") as f:
    SKU_TO_PLAN_MAPPING = json.load(f)

app = FastAPI(title="Shopify-Mighty Networks Integration")

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://shopify-mighty-networks.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def generate_password(length=10):
    """Generate a random alphanumeric password."""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))


# ============== SHOPIFY WEBHOOK ==============

@app.post("/webhook/shopify/order-paid")
async def shopify_order_paid_webhook(request: Request):
    """
    Webhook endpoint for Shopify Order Paid events.
    Filters by SKUs defined in sku_mapping.json and creates users with plans.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    
    # Extract customer info
    customer = payload.get("customer", {})
    email = payload.get("email") or customer.get("email")
    
    if not email:
        return {"status": "skipped", "reason": "No email found in order"}
    
    first_name = customer.get("first_name", "")
    last_name = customer.get("last_name", "")
    phone = customer.get("phone", "")
    order_id = str(payload.get("id", ""))
    
    # Filter line items by tracked SKUs
    line_items = payload.get("line_items", [])
    matched_items = []
    
    for item in line_items:
        sku = item.get("sku", "")
        if sku in SKU_TO_PLAN_MAPPING:
            matched_items.append({
                "sku": sku,
                "plan_id": SKU_TO_PLAN_MAPPING[sku],
                "title": item.get("title", ""),
                "quantity": item.get("quantity", 1)
            })
    
    if not matched_items:
        return {"status": "skipped", "reason": "No tracked SKUs found in order"}
    
    # Check if user exists
    existing_user = db.get_user_by_email(email)
    
    if existing_user:
        user_id = existing_user["id"]
        # Add plans to existing user
        for item in matched_items:
            db.add_user_plan(
                user_id=user_id,
                sku=item["sku"],
                plan_id=item["plan_id"],
                plan_title=item["title"],
                quantity=item["quantity"],
                shopify_order_id=order_id
            )
        return {
            "status": "success",
            "message": "Plans added to existing user",
            "user_id": user_id,
            "plans_added": len(matched_items)
        }
    
    # Create new user with random password
    password = generate_password(10)
    user_id = db.create_user(
        email=email,
        password=password,
        first_name=first_name,
        last_name=last_name,
        phone=phone
    )
    
    # Add plans to user
    for item in matched_items:
        db.add_user_plan(
            user_id=user_id,
            sku=item["sku"],
            plan_id=item["plan_id"],
            plan_title=item["title"],
            quantity=item["quantity"],
            shopify_order_id=order_id
        )
    
    # Send to Zapier webhook
    zapier_payload = {
        "email": email,
        "name": first_name or email.split("@")[0],
        "password": password
    }
    
    try:
        async with httpx.AsyncClient() as client:
            await client.post(ZAPIER_WEBHOOK_URL, json=zapier_payload)
    except Exception as e:
        print(f"Failed to send to Zapier: {e}")
    
    return {
        "status": "success",
        "message": "New user created with plans",
        "user_id": user_id,
        "plans_added": len(matched_items)
    }


# ============== AUTH ENDPOINTS ==============

@app.post("/auth/login")
async def login(request: Request):
    """Login endpoint for frontend authentication."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    email = body.get("email")
    password = body.get("password")
    
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")
    
    user = db.get_user_by_email(email)
    
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return {
        "status": "success",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "first_name": user["first_name"],
            "last_name": user["last_name"]
        }
    }


# ============== USER PLANS ENDPOINTS ==============

@app.get("/users/{user_id}/plans")
async def get_user_plans(user_id: int):
    """Get all plans for a user with available quantities."""
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    plans = db.get_user_plans(user_id)
    
    return {
        "status": "success",
        "plans": [
            {
                "id": plan["id"],
                "sku": plan["sku"],
                "plan_id": plan["plan_id"],
                "plan_title": plan["plan_title"],
                "total_quantity": plan["total_quantity"],
                "used_quantity": plan["used_quantity"],
                "available_quantity": plan["total_quantity"] - plan["used_quantity"]
            }
            for plan in plans
        ]
    }


# ============== INVITES ENDPOINTS ==============

@app.post("/users/{user_id}/plans/{user_plan_id}/invite")
async def send_invite(user_id: int, user_plan_id: int, request: Request):
    """
    Send an invite to a person for a specific plan via Mighty Networks API.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    recipient_email = body.get("email")
    recipient_first_name = body.get("first_name", "")
    recipient_last_name = body.get("last_name", "")
    
    if not recipient_email:
        raise HTTPException(status_code=400, detail="Recipient email is required")
    
    # Verify user exists
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify plan exists and belongs to user
    user_plan = db.get_user_plan_by_id(user_plan_id)
    if not user_plan or user_plan["user_id"] != user_id:
        raise HTTPException(status_code=404, detail="Plan not found")
    
    # Check available quantity
    available = user_plan["total_quantity"] - user_plan["used_quantity"]
    if available <= 0:
        raise HTTPException(status_code=400, detail="No available invites for this plan")
    
    # Call Mighty Networks API - only email is required as query parameter
    mighty_url = f"https://api.mn.co/admin/v1/networks/{NETWORK_ID}/plans/{user_plan['plan_id']}/invites"
    headers = {
        "Authorization": f"Bearer {MIGHTY_NETWORKS_API}"
    }
    params = {
        "email": recipient_email
    }
    
    # Log the request details for debugging
    print(f"=== MIGHTY NETWORKS API REQUEST ===")
    print(f"URL: {mighty_url}")
    print(f"Headers: {headers}")
    print(f"Params: {params}")
    print(f"Authorization header length: {len(headers['Authorization'])}")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(mighty_url, headers=headers, params=params)
            
            print(f"Response Status: {response.status_code}")
            print(f"Response Headers: {dict(response.headers)}")
            print(f"Response Text: {response.text[:500]}")
            
            if response.status_code not in [200, 201]:
                try:
                    error_detail = response.json().get("error", "Unknown error from Mighty Networks")
                except Exception:
                    error_detail = f"Mighty Networks API error (Status {response.status_code}): {response.text}"
                raise HTTPException(status_code=response.status_code, detail=error_detail)
            
            mighty_response = response.json()
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Failed to connect to Mighty Networks: {str(e)}")
    
    # Store invite in database
    invite_id = db.create_invite(
        user_plan_id=user_plan_id,
        user_id=user_id,
        mighty_invite_id=str(mighty_response.get("id", "")),
        recipient_email=recipient_email,
        recipient_first_name=mighty_response.get("recipient_first_name", ""),
        recipient_last_name=mighty_response.get("recipient_last_name", ""),
        mighty_user_id=mighty_response.get("user_id")
    )
    
    # Increment used quantity
    db.increment_used_quantity(user_plan_id)
    
    return {
        "status": "success",
        "invite": {
            "id": invite_id,
            "mighty_invite_id": mighty_response.get("id"),
            "recipient_email": recipient_email,
            "recipient_first_name": mighty_response.get("recipient_first_name"),
            "recipient_last_name": mighty_response.get("recipient_last_name"),
            "created_at": mighty_response.get("created_at")
        }
    }


@app.delete("/users/{user_id}/invites/{invite_id}")
async def revoke_invite(user_id: int, invite_id: int):
    """
    Revoke an invite via Mighty Networks API.
    """
    # Verify user exists
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get invite
    invite = db.get_invite_by_id(invite_id)
    if not invite or invite["user_id"] != user_id:
        raise HTTPException(status_code=404, detail="Invite not found")
    
    if invite["status"] == "revoked":
        raise HTTPException(status_code=400, detail="Invite already revoked")
    
    # Get user plan to get the mighty plan_id
    user_plan = db.get_user_plan_by_id(invite["user_plan_id"])
    if not user_plan:
        raise HTTPException(status_code=404, detail="Associated plan not found")
    
    # Call Mighty Networks API to revoke
    mighty_url = f"https://api.mn.co/admin/v1/networks/{NETWORK_ID}/plans/{user_plan['plan_id']}/invites/{invite['mighty_invite_id']}"
    headers = {
        "Authorization": f"Bearer {MIGHTY_NETWORKS_API}"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.delete(mighty_url, headers=headers)
            
            if response.status_code not in [200, 204]:
                try:
                    error_detail = response.json().get("error", "Unknown error from Mighty Networks")
                except Exception:
                    error_detail = "Failed to revoke invite"
                raise HTTPException(status_code=response.status_code, detail=error_detail)
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Failed to connect to Mighty Networks: {str(e)}")
    
    # Update invite status in database
    db.revoke_invite(invite_id)
    
    # Decrement used quantity
    db.decrement_used_quantity(invite["user_plan_id"])
    
    return {
        "status": "success",
        "message": "Invite revoked successfully"
    }


@app.get("/users/{user_id}/invites")
async def get_user_invites(user_id: int):
    """Get all invites sent by a user."""
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    invites = db.get_invites_by_user(user_id)
    
    return {
        "status": "success",
        "invites": [
            {
                "id": inv["id"],
                "mighty_invite_id": inv["mighty_invite_id"],
                "recipient_email": inv["recipient_email"],
                "recipient_first_name": inv["recipient_first_name"],
                "recipient_last_name": inv["recipient_last_name"],
                "plan_title": inv["plan_title"],
                "plan_id": inv["mighty_plan_id"],
                "status": inv["status"],
                "created_at": inv["created_at"]
            }
            for inv in invites
        ]
    }


# ============== HEALTH CHECK ==============

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
