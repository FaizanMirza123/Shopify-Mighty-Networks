import os
import json
import string
import secrets
import httpx
import smtplib
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
import jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
import base64
import hashlib

import database as db

# Load environment variables from base directory
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

MIGHTY_NETWORKS_API = os.getenv("MIGHTY_NETWORKS_API")
NETWORK_ID = os.getenv("NETWORK_ID")
SHOPIFY_X_ACCESS_TOKEN = os.getenv("SHOPIFY_X_ACCESS_TOKEN")
SHOPIFY_STORE_NAME = os.getenv("SHOPIFY_STORE_NAME")
ZAPIER_INVITE_WEBHOOK_URL = os.getenv("ZAPIER_INVITE_WEBHOOK_URL")

# Email Configuration
MAIL_MAILER = os.getenv("MAIL_MAILER")
MAIL_HOST = os.getenv("MAIL_HOST")
MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
MAIL_ENCRYPTION = os.getenv("MAIL_ENCRYPTION")
MAIL_FROM_ADDRESS = os.getenv("MAIL_FROM_ADDRESS")
MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME", "")
QUEUE_CONNECTION = os.getenv("QUEUE_CONNECTION")
SECRET = os.getenv("SECRET", "")

# JWT and Security Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "TEST")
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Encryption setup
def get_encryption_key():
    """Generate a Fernet key from the SECRET environment variable."""
    if not SECRET:
        raise ValueError("SECRET environment variable not set")
    # Use SHA256 to create a 32-byte key from the secret
    key = hashlib.sha256(SECRET.encode()).digest()
    return base64.urlsafe_b64encode(key)

cipher = Fernet(get_encryption_key()) if SECRET else None

def encrypt_password(password: str) -> str:
    """Encrypt a password using Fernet encryption."""
    if not cipher:
        return password  # Fallback to plain text if no SECRET
    encrypted = cipher.encrypt(password.encode())
    return encrypted.decode()

def decrypt_password(encrypted_password: str) -> str:
    """Decrypt a password using Fernet encryption."""
    if not cipher:
        return encrypted_password  # Fallback if no SECRET
    try:
        decrypted = cipher.decrypt(encrypted_password.encode())
        return decrypted.decode()
    except Exception:
        return encrypted_password  # Return as-is if decryption fails

async def send_email(to_email: str, name: str, password: str):
    """Send welcome email with account credentials."""
    html_template = """<!DOCTYPE html>
<html>
<head>
<style>
body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
.container {{ max-width: 600px; margin: 0 auto; background-color: rgb(251, 195, 95); padding: 20px; border-radius: 8px; }}
.logo-section {{ text-align: center; margin-bottom: 20px; }}
.logo-section img {{ max-width: 50%; height: auto; border-radius: 8px; }}
.header {{ background-color: rgb(251, 195, 95); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
.content {{ background-color: white; padding: 30px; border-radius: 0 0 8px 8px; }}
.section {{ margin-bottom: 20px; }}
.section h2 {{ color: rgb(251, 195, 95); font-size: 18px; margin-bottom: 10px; }}
.credentials {{ background-color: #f0f0f0; padding: 15px; border-left: 4px solid rgb(251, 195, 95); border-radius: 4px; margin: 15px 0; }}
.credentials p {{ margin: 8px 0; font-size: 14px; }}
.cta-button {{ background-color: rgb(251, 195, 95); color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; display: inline-block; margin-top: 15px; font-weight: bold; }}
.footer {{ color: #666; font-size: 12px; margin-top: 20px; padding-top: 15px; border-top: 1px solid #ddd; text-align: center; }}
</style>
</head>
<body>
<div class="container">
<div class="logo-section">
<img src="https://shopus.parelli.com/cdn/shop/files/Untitled_design-6_6667ea54-ba7e-43a6-8246-0a59ae10c111.png?v=1618580221&width=360" alt="Parelli Logo">
</div>
<div class="header">
<h1>Welcome to Parelli!</h1>
</div>
<div class="content">
<p>Hi {name},</p>

<div class="section">
<h2>Your Account is Ready</h2>
<p>Your account has been successfully created! You can now access the Parelli workflow platform with your credentials.
<br>
This is a one time email, so we recommend that you save your login details.
<br>
When you click on "Sign Into your Account" we also recommend bookmarking your dashboard URL for future ease of access</p>
</div>

<div class="section">
<h2>Sign In Information</h2>
<div class="credentials">
<p><strong>Email:</strong> {email}</p>
<p><strong>Password:</strong> {password}</p>
</div>
<p>Please keep these credentials secure and do not share them with anyone.</p>
</div>

<div class="section">
<a href="https://workflow.parelli.com" class="cta-button" style="color:white;">Sign In to Your Account</a>
</div>

<div class="section">
<h2>Need Help?</h2>
<p>If you have any questions or need assistance getting started, please don't hesitate to reach out to our support team. We're here to help! 
<br>
Please contact Jeri on support@parelli.com</p>
</div>

<div class="footer">
<p>Best regards,<br><strong>Parelli Management</strong></p>
<p>© 2024 Parelli. All rights reserved.</p>
</div>
</div>
</body>
</html>"""
    
    html_content = html_template.format(name=name, email=to_email, password=password)
    
    def send_smtp():
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = 'Welcome to Parelli - Your Account Credentials'
            msg['From'] = f"{MAIL_FROM_NAME} <{MAIL_FROM_ADDRESS}>" if MAIL_FROM_NAME else MAIL_FROM_ADDRESS
            msg['To'] = to_email
            
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            if MAIL_ENCRYPTION == "tls":
                with smtplib.SMTP(MAIL_HOST, MAIL_PORT) as server:
                    server.starttls()
                    if MAIL_USERNAME and MAIL_PASSWORD:
                        server.login(MAIL_USERNAME, MAIL_PASSWORD)
                    server.send_message(msg)
            elif MAIL_ENCRYPTION == "ssl":
                with smtplib.SMTP_SSL(MAIL_HOST, MAIL_PORT) as server:
                    if MAIL_USERNAME and MAIL_PASSWORD:
                        server.login(MAIL_USERNAME, MAIL_PASSWORD)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(MAIL_HOST, MAIL_PORT) as server:
                    if MAIL_USERNAME and MAIL_PASSWORD:
                        server.login(MAIL_USERNAME, MAIL_PASSWORD)
                    server.send_message(msg)
            
            print(f"[EMAIL] Successfully sent email to {to_email}")
        except Exception as e:
            print(f"[EMAIL] Failed to send email to {to_email}: {e}")
    
    # Run in thread to avoid blocking (Python 3.7+ compatible)
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, send_smtp)

# Load SKU mapping
SKU_MAPPING_PATH = os.path.join(os.path.dirname(__file__), "sku_mapping.json")
with open(SKU_MAPPING_PATH, "r") as f:
    SKU_TO_PLAN_MAPPING = json.load(f)

# Plan ID to Plan Name mapping
PLAN_ID_TO_NAME = {
    243479: "Level 1 Program",
    242949: "Level 1 & 2 Program"
}

# Badge to Plan ID mapping for Parelli Programs
BADGE_TO_PLAN_ID = {
    "Level 1 Parelli Program": "243479",
    "Level 2 Parelli Program": "242949",
    "Level 3 Parelli Program": "TBD",  # Update when Level 3 plan ID is known
    "Level 4 Parelli Program": "TBD"   # Update when Level 4 plan ID is known
}

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
            plan_id = SKU_TO_PLAN_MAPPING[sku]
            # Get plan name from mapping, default to title if not found
            plan_name = PLAN_ID_TO_NAME.get(plan_id, item.get("title", ""))
            matched_items.append({
                "sku": sku,
                "plan_id": plan_id,
                "title": plan_name,
                "quantity": item.get("quantity", 1) * 5  # Multiply quantity by 5
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
        
        # Decrypt existing user's password and send email
        try:
            decrypted_password = decrypt_password(existing_user["password"])
            user_name = first_name or existing_user.get("first_name") or email.split("@")[0]
            await send_email(email, user_name, decrypted_password)
        except Exception as e:
            print(f"Failed to send email to existing user: {e}")
        
        return {
            "status": "success",
            "message": "Plans added to existing user",
            "user_id": user_id,
            "plans_added": len(matched_items)
        }
    
    # Create new user with random password
    password = generate_password(10)
    encrypted_password = encrypt_password(password)
    
    user_id = db.create_user(
        email=email,
        password=encrypted_password,
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
    
    # Send welcome email with credentials
    try:
        user_name = first_name or email.split("@")[0]
        await send_email(email, user_name, password)
    except Exception as e:
        print(f"Failed to send welcome email: {e}")
    
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
    
    event_type = payload.get("event_type")
    print(f"[MIGHTY WEBHOOK] Event type: {event_type}")
    
    # Only handle badge events
    if event_type not in ["MemberBadgeAddedHook", "MemberBadgeRemovedHook"]:
        print(f"[MIGHTY WEBHOOK] Skipping - event type not handled")
        return {"status": "skipped", "reason": f"Event type {event_type} not handled"}
    
    # Extract member and badge information
    data = payload.get("payload", {})
    member = data.get("member", {})
    badge = data.get("badge", {})
    
    print(f"[MIGHTY WEBHOOK] Member data: {json.dumps(member, indent=2)}")
    print(f"[MIGHTY WEBHOOK] Badge data: {json.dumps(badge, indent=2)}")
    
    member_email = member.get("email")
    badge_name = badge.get("title")
    
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
    
    # Get the corresponding plan ID for this badge
    plan_id = BADGE_TO_PLAN_ID.get(badge_name)
    if not plan_id or plan_id == "TBD":
        print(f"[MIGHTY WEBHOOK] Skipping - no plan ID mapped for badge '{badge_name}'")
        return {"status": "skipped", "reason": f"No plan ID configured for badge {badge_name}"}
    
    print(f"[MIGHTY WEBHOOK] Badge '{badge_name}' mapped to plan_id: {plan_id}")
    
    # Find the invite by recipient email and plan_id
    print(f"[MIGHTY WEBHOOK] Searching for invite with email: {member_email} and plan_id: {plan_id}")
    invite = db.get_invite_by_email_and_plan(member_email, plan_id)
    
    if not invite:
        print(f"[MIGHTY WEBHOOK] No invite found for email: {member_email}")
        return {"status": "skipped", "reason": f"No invite found for email {member_email}"}
    
    print(f"[MIGHTY WEBHOOK] Found invite: ID={invite['id']}, Status={invite['status']}")
    
    # Update invite status based on event type
    if event_type == "MemberBadgeAddedHook":
        print(f"[MIGHTY WEBHOOK] Updating invite {invite['id']} status to 'joined'")
        db.update_invite_status(invite["id"], "joined")
        print(f"[MIGHTY WEBHOOK] Successfully updated invite status to 'joined'")
        return {
            "status": "success",
            "message": f"Invite status updated to 'joined' for {member_email}",
            "invite_id": invite["id"],
            "badge_name": badge_name
        }
    elif event_type == "MemberBadgeRemovedHook":
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
    
    # Verify password (support encrypted, hashed, and plain text for backwards compatibility)
    password_valid = False
    stored_password = user["password"]
    
    if stored_password.startswith("$2b$"):  # bcrypt hash
        password_valid = verify_password(password, stored_password)
    else:
        # Try to decrypt first (encrypted password)
        try:
            decrypted = decrypt_password(stored_password)
            password_valid = (decrypted == password)
        except Exception:
            # Fall back to plain text comparison
            password_valid = (stored_password == password)
        
        # If valid, update to encrypted password
        if password_valid and stored_password != encrypt_password(password):
            db.update_user_password(user["id"], encrypt_password(password))
    
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
    
    # Get the user_plan to retrieve the Mighty Networks plan_id
    user_plan = db.get_user_plan_by_id(invite["user_plan_id"])
    if not user_plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    
    mighty_plan_id = user_plan["plan_id"]
    recipient_email = invite["recipient_email"]
    
    print(f"[REVOKE] Fetching invites for plan_id: {mighty_plan_id}, email: {recipient_email}")
    
    # Fetch invites from Mighty Networks for this plan
    try:
        async with httpx.AsyncClient() as client:
            headers = {
                "Authorization": f"Bearer {MIGHTY_NETWORKS_API}",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0"
            }
            
            # Get all invites for this plan
            url = f"https://api.mn.co/admin/v1/networks/{NETWORK_ID}/plans/{mighty_plan_id}/invites"
            print(f"[REVOKE] Request URL: {url}")
            print(f"[REVOKE] NETWORK_ID: {NETWORK_ID}")
            print(f"[REVOKE] API Token present: {bool(MIGHTY_NETWORKS_API)}")
            
            response = await client.get(url, headers=headers)
            
            print(f"[REVOKE] Response status: {response.status_code}")
            print(f"[REVOKE] Response body: {response.text}")
            
            if response.status_code != 200:
                print(f"[REVOKE] Failed to fetch invites from Mighty Networks: {response.status_code}")
                raise HTTPException(status_code=500, detail="Failed to fetch invites from Mighty Networks")
            
            invites_data = response.json()
            mighty_invites = invites_data.get("items", [])
            
            print(f"[REVOKE] Found {len(mighty_invites)} total invites for this plan")
            print(f"[REVOKE] Searching for exact match: '{recipient_email}'")
            
            # Log all emails found
            for idx, mn_invite in enumerate(mighty_invites):
                print(f"[REVOKE] Invite {idx+1}: email='{mn_invite.get('recipient_email')}', id={mn_invite.get('id')}")
            
            # Find the invite matching this email
            mighty_invite_id = None
            for mn_invite in mighty_invites:
                if mn_invite.get("recipient_email") == recipient_email:
                    mighty_invite_id = mn_invite.get("id")
                    print(f"[REVOKE] Found Mighty Networks invite_id: {mighty_invite_id} for email: {recipient_email}")
                    break
            
            if not mighty_invite_id:
                print(f"[REVOKE] No Mighty Networks invite found for email: {recipient_email}")
                raise HTTPException(status_code=404, detail="Invite not found in Mighty Networks")
            
            # Revoke the invite via Mighty Networks API
            revoke_url = f"https://api.mn.co/admin/v1/networks/{NETWORK_ID}/invites/{mighty_invite_id}"
            revoke_response = await client.delete(revoke_url, headers=headers)
            
            if revoke_response.status_code not in [200, 204]:
                print(f"[REVOKE] Failed to revoke invite in Mighty Networks: {revoke_response.status_code}")
                raise HTTPException(status_code=500, detail="Failed to revoke invite in Mighty Networks")
            
            print(f"[REVOKE] Successfully revoked invite in Mighty Networks")
    
    except httpx.RequestError as e:
        print(f"[REVOKE] Network error: {e}")
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
