import os
import json
import string
import secrets
import httpx
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
import jwt
from passlib.context import CryptContext

import database as db

# Load environment variables from base directory
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

MIGHTY_NETWORKS_API = os.getenv("MIGHTY_NETWORKS_API")
NETWORK_ID = os.getenv("NETWORK_ID")
SHOPIFY_X_ACCESS_TOKEN = os.getenv("SHOPIFY_X_ACCESS_TOKEN")
SHOPIFY_STORE_NAME = os.getenv("SHOPIFY_STORE_NAME")
ZAPIER_WEBHOOK_URL = os.getenv("ZAPIER_WEBHOOK_URL")
ZAPIER_INVITE_WEBHOOK_URL = os.getenv("ZAPIER_INVITE_WEBHOOK_URL")

# JWT and Security Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "TEST")
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Load SKU mapping
SKU_MAPPING_PATH = os.path.join(os.path.dirname(__file__), "sku_mapping.json")
with open(SKU_MAPPING_PATH, "r") as f:
    SKU_TO_PLAN_MAPPING = json.load(f)

app = FastAPI(title="Shopify-Mighty Networks Integration",docs_url=None,
    redoc_url=None,
    openapi_url=None)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173","https://shopify-mighty-networks.vercel.app","https://workflow.parelli.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def generate_password(length=10):
    """Generate a random alphanumeric password."""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    """Decode and verify a JWT access token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")


async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    """Dependency to get the current authenticated user from JWT token."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header format")
    
    token = authorization.replace("Bearer ", "")
    payload = decode_access_token(token)
    
    user_id = payload.get("sub")
    email = payload.get("email")
    
    if not user_id or not email:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    
    # Verify user still exists
    user = db.get_user_by_id(int(user_id))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user


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


# ============== MIGHTY NETWORKS WEBHOOK ==============

@app.post("/webhook/mighty/member-joined")
async def mighty_member_joined_webhook(request: Request):
    """
    Webhook endpoint for Mighty Networks MemberJoined events.
    Updates invite status to 'joined' when an invited member joins.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    
    # Extract member info from webhook payload
    # The exact structure depends on Mighty Networks webhook format
    # Common fields: email, user_id, space_id, etc.
    email = payload.get("email")
    mighty_user_id = payload.get("user_id") or payload.get("id")
    
    if not email:
        return {"status": "skipped", "reason": "No email found in webhook payload"}
    
    # Check if there's a pending invite for this email
    invite = db.get_invite_by_email(email)
    
    if not invite:
        return {
            "status": "skipped", 
            "reason": f"No pending invite found for {email}"
        }
    
    # Update invite status to 'joined'
    rows_updated = db.mark_invite_joined(email, mighty_user_id)
    
    if rows_updated > 0:
        return {
            "status": "success",
            "message": f"Invite status updated to 'joined' for {email}",
            "invite_id": invite["id"],
            "mighty_user_id": mighty_user_id
        }
    else:
        return {
            "status": "skipped",
            "reason": f"No pending invites updated for {email}"
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
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Verify password (support both hashed and plain text for backwards compatibility)
    password_valid = False
    if user["password"].startswith("$2b$"):  # bcrypt hash
        password_valid = verify_password(password, user["password"])
    else:  # plain text (legacy)
        password_valid = (user["password"] == password)
        # If valid, update to hashed password
        if password_valid:
            db.update_user_password(user["id"], hash_password(password))
    
    if not password_valid:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create JWT token
    access_token = create_access_token(
        data={"sub": str(user["id"]), "email": user["email"]}
    )
    
    return {
        "status": "success",
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "first_name": user["first_name"],
            "last_name": user["last_name"]
        }
    }


# ============== USER PLANS ENDPOINTS ==============

@app.get("/users/{user_id}/plans")
async def get_user_plans(user_id: int, current_user: dict = Depends(get_current_user)):
    """Get all plans for a user with available quantities."""
    # Verify user can only access their own plans
    if current_user["id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
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
async def send_invite(user_id: int, user_plan_id: int, request: Request, current_user: dict = Depends(get_current_user)):
    """
    Send an invite to a person for a specific plan via Mighty Networks API.
    """
    # Verify user can only send invites for their own plans
    if current_user["id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    recipient_email = body.get("email")
    recipient_first_name = body.get("first_name", "")
    recipient_last_name = body.get("last_name", "")
    
    if not recipient_email:
        raise HTTPException(status_code=400, detail="Recipient email is required")
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
        "Authorization": f"Bearer {MIGHTY_NETWORKS_API}",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0"
    }
    params = {
        "email": recipient_email
    }
    # Note: first_name and last_name are not request parameters, they appear in the response
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(mighty_url, headers=headers, params=params)
            
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
async def revoke_invite(user_id: int, invite_id: int, current_user: dict = Depends(get_current_user)):
    """
    Revoke an invite via Mighty Networks API.
    Only allowed within 1 hour of sending the invite.
    """
    # Verify user can only revoke their own invites
    if current_user["id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    # Get invite
    invite = db.get_invite_by_id(invite_id)
    if not invite or invite["user_id"] != user_id:
        raise HTTPException(status_code=404, detail="Invite not found")
    
    if invite["status"] == "revoked":
        raise HTTPException(status_code=400, detail="Invite already revoked")
    
    # Check if 1 hour has passed since invite was created
    try:
        # Parse the timestamp - SQLite returns timestamps without timezone info
        created_at_str = invite["created_at"].replace(" ", "T") if " " in invite["created_at"] else invite["created_at"]
        # Remove any timezone suffix and treat as UTC
        if "+" in created_at_str:
            created_at_str = created_at_str.split("+")[0]
        if "Z" in created_at_str:
            created_at_str = created_at_str.replace("Z", "")
        
        invite_created_at = datetime.fromisoformat(created_at_str)
        time_elapsed = datetime.utcnow() - invite_created_at
    except (ValueError, AttributeError) as e:
        print(f"Error parsing timestamp: {invite['created_at']}, error: {e}")
        # If we can't parse, assume it's recent (allow revocation)
        time_elapsed = timedelta(seconds=0)
    
    if time_elapsed > timedelta(hours=1):
        raise HTTPException(
            status_code=400, 
            detail="Cannot revoke invite after 1 hour has passed"
        )
    
    # Get the user plan to retrieve the plan_id
    user_plan = db.get_user_plan_by_id(invite["user_plan_id"])
    if not user_plan:
        raise HTTPException(status_code=404, detail="Associated plan not found")
    
    # Call Mighty Networks API to revoke the invite
    mighty_invite_id = invite.get("mighty_invite_id")
    if not mighty_invite_id:
        raise HTTPException(status_code=400, detail="No Mighty Networks invite ID found")
    
    mighty_url = f"https://api.mn.co/admin/v1/networks/{NETWORK_ID}/plans/{user_plan['plan_id']}/invites/{mighty_invite_id}/"
    headers = {
        "Authorization": f"Bearer {MIGHTY_NETWORKS_API}",
        "User-Agent": "Mozilla/5.0"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.delete(mighty_url, headers=headers)
            
            if response.status_code == 204:
                # Successfully revoked
                pass
            elif response.status_code == 404:
                raise HTTPException(status_code=404, detail="Invite not found in Mighty Networks")
            elif response.status_code == 409:
                raise HTTPException(status_code=409, detail="Invite has already been accepted and cannot be revoked")
            else:
                try:
                    error_detail = response.json().get("error", "Unknown error from Mighty Networks")
                except Exception:
                    error_detail = f"Mighty Networks API error (Status {response.status_code}): {response.text}"
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
async def get_user_invites(user_id: int, current_user: dict = Depends(get_current_user)):
    """Get all invites sent by a user."""
    # Verify user can only access their own invites
    if current_user["id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    invites = db.get_invites_by_user(user_id)
    
    # Helper to normalize timestamp format
    def normalize_timestamp(ts):
        if not ts:
            return ts
        # Convert SQLite format to ISO format with Z suffix for UTC
        ts_str = str(ts).replace(" ", "T")
        if not ts_str.endswith("Z") and "+" not in ts_str:
            ts_str += "Z"
        return ts_str
    
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
                "created_at": normalize_timestamp(inv["created_at"])
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
