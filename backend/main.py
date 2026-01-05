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
    allow_origins=["https://shopify-mighty-networks.vercel.app","https://workflow.parelli.com"],
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

@app.post("/mighty")
async def mighty_networks_webhook(request: Request):
    """
    Webhook endpoint for Mighty Networks events.
    Handles MemberBadgeAdded and MemberBadgeRemoved events.
    """
    try:
        payload = await request.json()
        print(f"\n{'='*60}")
        print(f"[MIGHTY WEBHOOK] Received payload:")
        print(json.dumps(payload, indent=2))
        print(f"{'='*60}\n")
    except Exception as e:
        print(f"[MIGHTY WEBHOOK ERROR] Failed to parse JSON: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    
    event_type = payload.get("event")
    print(f"[MIGHTY WEBHOOK] Event type: {event_type}")
    
    # Only handle badge events
    if event_type not in ["MemberBadgeAdded", "MemberBadgeRemoved"]:
        print(f"[MIGHTY WEBHOOK] Skipping - event type not handled")
        return {"status": "skipped", "reason": f"Event type {event_type} not handled"}
    
    # Extract member and badge information
    data = payload.get("data", {})
    member = data.get("member", {})
    badge = data.get("badge", {})
    
    print(f"[MIGHTY WEBHOOK] Member data: {json.dumps(member, indent=2)}")
    print(f"[MIGHTY WEBHOOK] Badge data: {json.dumps(badge, indent=2)}")
    
    member_email = member.get("email")
    badge_name = badge.get("name")
    
    print(f"[MIGHTY WEBHOOK] Extracted - Email: {member_email}, Badge: {badge_name}")
    
    # Validate required fields
    if not member_email:
        print(f"[MIGHTY WEBHOOK] Skipping - no member email found")
        return {"status": "skipped", "reason": "No member email found"}
    
    if not badge_name:
        print(f"[MIGHTY WEBHOOK] Skipping - no badge name found")
        return {"status": "skipped", "reason": "No badge name found"}
    
    # Check if badge is one of the Parelli Program badges
    parelli_badges = [
        "Level 1 Parelli Program",
        "Level 2 Parelli Program",
        "Level 3 Parelli Program",
        "Level 4 Parelli Program"
    ]
    
    if badge_name not in parelli_badges:
        print(f"[MIGHTY WEBHOOK] Skipping - badge '{badge_name}' not in tracked badges")
        print(f"[MIGHTY WEBHOOK] Tracked badges: {parelli_badges}")
        return {"status": "skipped", "reason": f"Badge {badge_name} is not a tracked Parelli Program badge"}
    
    # Find the invite by recipient email
    print(f"[MIGHTY WEBHOOK] Searching for invite with email: {member_email}")
    invite = db.get_invite_by_email(member_email)
    
    if not invite:
        print(f"[MIGHTY WEBHOOK] No invite found for email: {member_email}")
        return {"status": "skipped", "reason": f"No invite found for email {member_email}"}
    
    print(f"[MIGHTY WEBHOOK] Found invite: ID={invite['id']}, Status={invite['status']}")
    
    # Update invite status based on event type
    if event_type == "MemberBadgeAdded":
        print(f"[MIGHTY WEBHOOK] Updating invite {invite['id']} status to 'joined'")
        db.update_invite_status(invite["id"], "joined")
        print(f"[MIGHTY WEBHOOK] Successfully updated invite status to 'joined'")
        return {
            "status": "success",
            "message": f"Invite status updated to 'joined' for {member_email}",
            "invite_id": invite["id"],
            "badge_name": badge_name
        }
    elif event_type == "MemberBadgeRemoved":
        print(f"[MIGHTY WEBHOOK] Updating invite {invite['id']} status to 'removed'")
        db.update_invite_status(invite["id"], "removed")
        print(f"[MIGHTY WEBHOOK] Successfully updated invite status to 'removed'")
        return {
            "status": "success",
            "message": f"Invite status updated to 'removed' for {member_email}",
            "invite_id": invite["id"],
            "badge_name": badge_name
        }
    
    print(f"[MIGHTY WEBHOOK] Unknown processing result - should not reach here")
    return {"status": "skipped", "reason": "Unknown event processing result"}


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
    
    # Send to Zapier webhook to handle invite creation
    zapier_invite_payload = {
        "email": recipient_email,
        "first_name": recipient_first_name,
        "last_name": recipient_last_name,
        "plan_name": user_plan["plan_title"]
    }
    
    try:
        async with httpx.AsyncClient() as client:
            zapier_response = await client.post(ZAPIER_INVITE_WEBHOOK_URL, json=zapier_invite_payload)
            if zapier_response.status_code not in [200, 201]:
                raise HTTPException(status_code=500, detail="Failed to send invite via Zapier")
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Failed to connect to Zapier: {str(e)}")
    
    # Store invite in database
    invite_id = db.create_invite(
        user_plan_id=user_plan_id,
        user_id=user_id,
        mighty_invite_id="",  # No mighty invite ID since handled by Zapier
        recipient_email=recipient_email,
        recipient_first_name=recipient_first_name,
        recipient_last_name=recipient_last_name,
        mighty_user_id=None
    )
    
    # Increment used quantity
    db.increment_used_quantity(user_plan_id)
    
    return {
        "status": "success",
        "invite": {
            "id": invite_id,
            "recipient_email": recipient_email,
            "recipient_first_name": recipient_first_name,
            "recipient_last_name": recipient_last_name,
            "plan_name": user_plan["plan_title"],
            "created_at": datetime.utcnow().isoformat() + "Z"
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
    
    # Update invite status in database (no Mighty Networks API call needed since Zapier handles it)
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
