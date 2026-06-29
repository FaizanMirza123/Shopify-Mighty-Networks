"""
God-mode admin layer for the Shopify <-> Mighty Networks integration.

This module is intentionally self-contained and additive: it does NOT modify or
depend on the runtime behaviour of the existing customer-facing endpoints. It
exposes a separate admin login (backed by the `admins` table), read-only views
over users / plans / logs, an invite action that fires the connected Zapier
webhook, and a self-hosted HTML dashboard served straight from the backend.

It is wired in from main.py via `app.include_router(router)`.
"""

import os
import json
from datetime import datetime, timedelta
from typing import Optional

import httpx
import jwt
from passlib.context import CryptContext
from fastapi import APIRouter, HTTPException, Request, Header, Depends, Query
from fastapi.responses import HTMLResponse

import database as db

# Reuse the same JWT secret so configuration stays in one place. Admin tokens are
# distinguished from customer tokens by an explicit `role: "admin"` claim, so the
# two auth surfaces never overlap.
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "TEST")
JWT_ALGORITHM = "HS256"
ADMIN_TOKEN_EXPIRE_HOURS = 12

ZAPIER_INVITE_WEBHOOK_URL = os.getenv("ZAPIER_INVITE_WEBHOOK_URL")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter(prefix="/admin", tags=["admin"])


# ---------------------------------------------------------------- auth helpers
def hash_admin_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_admin_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False


def create_admin_token(admin: dict) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": str(admin["id"]),
        "email": admin["email"],
        "role": "admin",
        "iat": now,
        "exp": now + timedelta(hours=ADMIN_TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


async def get_current_admin(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Admin authorization required")

    token = authorization[len("Bearer "):]
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not an admin token")

    admin = db.get_admin_by_id(int(payload.get("sub", 0)))
    if not admin:
        raise HTTPException(status_code=401, detail="Admin not found")
    return admin


# ---------------------------------------------------------------- API endpoints
@router.post("/login")
async def admin_login(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")

    admin = db.get_admin_by_email(email)
    if not admin or not verify_admin_password(password, admin["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_admin_token(admin)
    return {
        "status": "success",
        "access_token": token,
        "token_type": "bearer",
        "admin": {"id": admin["id"], "email": admin["email"]},
    }


@router.get("/me")
async def admin_me(admin: dict = Depends(get_current_admin)):
    return {"id": admin["id"], "email": admin["email"]}


@router.get("/users")
async def admin_list_users(admin: dict = Depends(get_current_admin)):
    """All customers, each with their plans and invite summary."""
    users = db.get_all_users()
    result = []
    for u in users:
        plans = db.get_user_plans(u["id"])
        invites = db.get_invites_by_user(u["id"])
        result.append({
            "id": u["id"],
            "email": u["email"],
            "first_name": u["first_name"],
            "last_name": u["last_name"],
            "phone": u["phone"],
            "created_at": u["created_at"],
            "plans": [
                {
                    "id": p["id"],
                    "sku": p["sku"],
                    "plan_id": p["plan_id"],
                    "plan_title": p["plan_title"],
                    "total_quantity": p["total_quantity"],
                    "used_quantity": p["used_quantity"],
                    "available_quantity": p["total_quantity"] - p["used_quantity"],
                }
                for p in plans
            ],
            "invites": [
                {
                    "id": inv["id"],
                    "recipient_email": inv["recipient_email"],
                    "recipient_first_name": inv["recipient_first_name"],
                    "recipient_last_name": inv["recipient_last_name"],
                    "plan_title": inv["plan_title"],
                    "status": inv["status"],
                    "created_at": inv["created_at"],
                }
                for inv in invites
            ],
        })
    return {"status": "success", "count": len(result), "users": result}


@router.get("/webhook-logs")
async def admin_webhook_logs(
    admin: dict = Depends(get_current_admin),
    status: Optional[str] = Query(None, description="e.g. 'skipped' or 'processed'"),
    source: Optional[str] = Query(None, description="e.g. 'shopify'"),
    limit: int = Query(200, ge=1, le=1000),
):
    """Every webhook that was filtered out or processed, newest first."""
    logs = db.get_webhook_logs(limit=limit, status=status, source=source)
    return {"status": "success", "count": len(logs), "logs": logs}


@router.get("/email-logs")
async def admin_email_logs(
    admin: dict = Depends(get_current_admin),
    email_type: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
):
    """Where credentials / invites / reset links were delivered, newest first."""
    logs = db.get_email_logs(limit=limit, email_type=email_type)
    return {"status": "success", "count": len(logs), "logs": logs}


@router.post("/invite")
async def admin_invite(request: Request, admin: dict = Depends(get_current_admin)):
    """
    Invite a new member. Fires the connected Zapier webhook (same payload shape the
    customer invite flow uses) so Zapier provisions the member and sends credentials.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    email = (body.get("email") or "").strip()
    first_name = body.get("first_name", "") or ""
    last_name = body.get("last_name", "") or ""
    plan_name = body.get("plan_name", "") or ""

    if not email:
        raise HTTPException(status_code=400, detail="Recipient email is required")

    if not ZAPIER_INVITE_WEBHOOK_URL:
        db.log_email_event(email, "admin_invite", "failed",
                           detail="ZAPIER_INVITE_WEBHOOK_URL not configured")
        raise HTTPException(status_code=500, detail="Zapier webhook URL is not configured")

    payload = {
        "email": email,
        "first_name": first_name,
        "last_name": last_name,
        "plan_name": plan_name,
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(ZAPIER_INVITE_WEBHOOK_URL, json=payload)
    except httpx.RequestError as e:
        db.log_email_event(email, "admin_invite", "failed",
                           detail=f"Zapier connection error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to connect to Zapier: {e}")

    if resp.status_code not in (200, 201):
        db.log_email_event(email, "admin_invite", "failed",
                           detail=f"Zapier returned {resp.status_code}")
        raise HTTPException(status_code=502, detail=f"Zapier returned {resp.status_code}")

    db.log_email_event(
        email, "admin_invite", "sent",
        detail=f"plan='{plan_name}' by admin {admin['email']}",
    )
    return {
        "status": "success",
        "message": f"Invite fired to Zapier for {email}",
        "sent": payload,
    }


# ---------------------------------------------------------------- dashboard UI
@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard():
    """Self-contained god-mode dashboard. Auth happens client-side against /admin/login."""
    return HTMLResponse(content=DASHBOARD_HTML)


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Parelli Admin · God Mode</title>
<style>
  :root { --accent: rgb(251,195,95); --bg:#0f1115; --panel:#171a21; --panel2:#1f242d;
          --text:#e7eaf0; --muted:#9aa3b2; --ok:#36d399; --bad:#f87272; --warn:#fbbd23; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
         background: var(--bg); color: var(--text); }
  header { display:flex; align-items:center; justify-content:space-between;
           padding:14px 22px; background: var(--panel); border-bottom:1px solid #262b34; }
  header h1 { font-size:17px; margin:0; letter-spacing:.3px; }
  header h1 span { color: var(--accent); }
  .who { color: var(--muted); font-size:13px; }
  button { cursor:pointer; border:none; border-radius:7px; padding:9px 14px;
           font-weight:600; font-size:13px; background: var(--accent); color:#1a1a1a; }
  button.ghost { background: var(--panel2); color: var(--text); border:1px solid #2c333d; }
  button:disabled { opacity:.5; cursor:default; }
  nav { display:flex; gap:8px; padding:14px 22px 0; flex-wrap:wrap; }
  nav button { background: var(--panel2); color: var(--muted); }
  nav button.active { background: var(--accent); color:#1a1a1a; }
  main { padding:18px 22px 60px; }
  .card { background: var(--panel); border:1px solid #262b34; border-radius:12px;
          padding:18px; margin-bottom:18px; }
  .login-wrap { max-width:380px; margin:9vh auto; }
  label { display:block; font-size:12px; color: var(--muted); margin:12px 0 6px; }
  input { width:100%; padding:10px 12px; border-radius:8px; border:1px solid #2c333d;
          background: var(--panel2); color: var(--text); font-size:14px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:9px 10px; border-bottom:1px solid #242a33; vertical-align:top; }
  th { color: var(--muted); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.5px; }
  tr:hover td { background:#12151b; }
  .pill { display:inline-block; padding:2px 9px; border-radius:999px; font-size:11px; font-weight:700; }
  .pill.skipped { background: rgba(248,114,114,.15); color: var(--bad); }
  .pill.processed, .pill.sent, .pill.joined { background: rgba(54,211,153,.15); color: var(--ok); }
  .pill.failed, .pill.revoked, .pill.removed { background: rgba(251,189,35,.15); color: var(--warn); }
  .muted { color: var(--muted); }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end; }
  .row > div { flex:1; min-width:150px; }
  .err { color: var(--bad); font-size:13px; margin-top:10px; min-height:16px; }
  .ok { color: var(--ok); font-size:13px; margin-top:10px; min-height:16px; }
  .toolbar { display:flex; gap:10px; align-items:center; margin-bottom:12px; flex-wrap:wrap; }
  details summary { cursor:pointer; color: var(--accent); font-size:12px; }
  pre { white-space:pre-wrap; word-break:break-word; background:#0c0e12; padding:10px;
        border-radius:8px; font-size:11px; color:#cbd3e1; max-height:320px; overflow:auto; }
  .count { color: var(--muted); font-size:12px; }
  .empty { color: var(--muted); padding:20px; text-align:center; }
  code { color: var(--accent); }
</style>
</head>
<body>
<div id="app"></div>
<script>
const API = "/admin";
let token = localStorage.getItem("admin_token") || null;
let adminEmail = localStorage.getItem("admin_email") || null;
let tab = "users";

async function api(path, opts={}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  if (token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(API + path, Object.assign({}, opts, { headers }));
  if (res.status === 401 || res.status === 403) { logout(); throw new Error("Session expired. Please log in again."); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || ("Request failed ("+res.status+")"));
  return data;
}

function logout() { token=null; adminEmail=null; localStorage.removeItem("admin_token"); localStorage.removeItem("admin_email"); render(); }
function esc(s){ return (s===null||s===undefined)?"":String(s).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function fmt(ts){ if(!ts) return "—"; const t=String(ts).replace(" ","T"); const d=new Date(/Z|\+/.test(t)?t:t+"Z"); return isNaN(d)?esc(ts):d.toLocaleString(); }
function pill(s){ return '<span class="pill '+esc(s)+'">'+esc(s)+'</span>'; }

// ---------- login ----------
function loginView() {
  document.getElementById("app").innerHTML = `
    <header><h1>Parelli <span>Admin</span> · God Mode</h1></header>
    <div class="login-wrap card">
      <h2 style="margin-top:0">Sign in</h2>
      <label>Email</label><input id="email" type="email" autocomplete="username">
      <label>Password</label><input id="password" type="password" autocomplete="current-password">
      <div style="margin-top:16px"><button id="loginBtn" style="width:100%">Sign in</button></div>
      <div class="err" id="loginErr"></div>
    </div>`;
  const go = async () => {
    const btn=document.getElementById("loginBtn"); btn.disabled=true;
    document.getElementById("loginErr").textContent="";
    try {
      const data = await api("/login", { method:"POST", body: JSON.stringify({
        email: document.getElementById("email").value.trim(),
        password: document.getElementById("password").value }) });
      token=data.access_token; adminEmail=data.admin.email;
      localStorage.setItem("admin_token", token); localStorage.setItem("admin_email", adminEmail);
      render();
    } catch(e){ document.getElementById("loginErr").textContent=e.message; btn.disabled=false; }
  };
  document.getElementById("loginBtn").onclick=go;
  document.getElementById("password").addEventListener("keydown", e=>{ if(e.key==="Enter") go(); });
}

// ---------- shell ----------
function shell(inner) {
  return `
    <header>
      <h1>Parelli <span>Admin</span> · God Mode</h1>
      <div><span class="who">${esc(adminEmail||"")}</span>
        <button class="ghost" onclick="logout()" style="margin-left:12px">Sign out</button></div>
    </header>
    <nav>
      ${["users","Users","filtered","Filtered Orders","emails","Credential Logs","invite","Send Invite"]
        .reduce((a,_,i,arr)=> i%2===0 ? a+`<button class="${tab===arr[i]?'active':''}" onclick="setTab('${arr[i]}')">${arr[i+1]}</button>`:a,"")}
      <button class="ghost" onclick="render()" style="margin-left:auto">↻ Refresh</button>
    </nav>
    <main id="main">${inner}</main>`;
}
function setTab(t){ tab=t; render(); }

// ---------- views ----------
async function usersView() {
  const d = await api("/users");
  if (!d.users.length) return `<div class="card empty">No customers yet.</div>`;
  return `<div class="card"><div class="count">${d.count} customer(s)</div><table>
    <thead><tr><th>ID</th><th>Customer</th><th>Email</th><th>Plans (used / total)</th><th>Invites</th><th>Joined</th></tr></thead>
    <tbody>${d.users.map(u=>`<tr>
      <td>${u.id}</td>
      <td>${esc((u.first_name||"")+" "+(u.last_name||""))||"—"}</td>
      <td>${esc(u.email)}</td>
      <td>${u.plans.length? u.plans.map(p=>`<div>${esc(p.plan_title||p.plan_id)} <span class="muted">(${p.used_quantity}/${p.total_quantity}, ${p.available_quantity} left)</span></div>`).join(""):'<span class="muted">—</span>'}</td>
      <td>${u.invites.length? u.invites.map(i=>`<div>${esc(i.recipient_email)} ${pill(i.status)}</div>`).join(""):'<span class="muted">0</span>'}</td>
      <td class="muted">${fmt(u.created_at)}</td>
    </tr>`).join("")}</tbody></table></div>`;
}

let filterStatus = "skipped";
async function filteredView() {
  const d = await api("/webhook-logs?limit=300" + (filterStatus?("&status="+filterStatus):""));
  const bar = `<div class="toolbar">
    <span class="muted">Show:</span>
    ${["skipped","Filtered only","processed","Processed only","","All"].reduce((a,_,i,arr)=> i%2===0?
        a+`<button class="${filterStatus===arr[i]?'':'ghost'}" onclick="setFilter('${arr[i]}')">${arr[i+1]}</button>`:a,"")}
    <span class="count" style="margin-left:auto">${d.count} record(s)</span></div>`;
  if (!d.logs.length) return `<div class="card">${bar}<div class="empty">No matching webhook records.</div></div>`;
  return `<div class="card">${bar}<table>
    <thead><tr><th>When</th><th>Source</th><th>Status</th><th>Reason</th><th>Order</th><th>Email</th><th>Payload</th></tr></thead>
    <tbody>${d.logs.map(l=>`<tr>
      <td class="muted">${fmt(l.created_at)}</td>
      <td>${esc(l.source)}</td>
      <td>${pill(l.status)}</td>
      <td>${esc(l.reason)}</td>
      <td>${esc(l.order_id)||"—"}</td>
      <td>${esc(l.email)||"—"}</td>
      <td>${l.payload?`<details><summary>view</summary><pre>${esc(pretty(l.payload))}</pre></details>`:'<span class="muted">—</span>'}</td>
    </tr>`).join("")}</tbody></table></div>`;
}
function setFilter(s){ filterStatus=s; render(); }
function pretty(p){ try { return JSON.stringify(JSON.parse(p), null, 2); } catch(e){ return p; } }

async function emailsView() {
  const d = await api("/email-logs?limit=300");
  if (!d.logs.length) return `<div class="card empty">No credential / invite emails recorded yet.</div>`;
  return `<div class="card"><div class="count">${d.count} delivery record(s)</div><table>
    <thead><tr><th>When</th><th>Type</th><th>Sent To</th><th>Status</th><th>Detail</th></tr></thead>
    <tbody>${d.logs.map(l=>`<tr>
      <td class="muted">${fmt(l.created_at)}</td>
      <td>${esc(l.email_type)}</td>
      <td><code>${esc(l.recipient)}</code></td>
      <td>${pill(l.status)}</td>
      <td class="muted">${esc(l.detail)||"—"}</td>
    </tr>`).join("")}</tbody></table></div>`;
}

function inviteView() {
  return `<div class="card" style="max-width:520px">
    <h2 style="margin-top:0">Invite a new member</h2>
    <p class="muted" style="font-size:13px">Fires the connected Zapier webhook (which provisions the member and sends credentials), then records the delivery under <b>Credential Logs</b>.</p>
    <div class="row">
      <div><label>Email *</label><input id="i_email" type="email"></div>
    </div>
    <div class="row">
      <div><label>First name</label><input id="i_first"></div>
      <div><label>Last name</label><input id="i_last"></div>
    </div>
    <label>Plan name</label><input id="i_plan" placeholder="e.g. Level 1 Program">
    <div style="margin-top:16px"><button id="i_btn">Send invite via Zapier</button></div>
    <div class="ok" id="i_ok"></div><div class="err" id="i_err"></div>
  </div>`;
}
function bindInvite() {
  const btn=document.getElementById("i_btn"); if(!btn) return;
  btn.onclick = async () => {
    btn.disabled=true;
    document.getElementById("i_ok").textContent=""; document.getElementById("i_err").textContent="";
    try {
      const d = await api("/invite", { method:"POST", body: JSON.stringify({
        email: document.getElementById("i_email").value.trim(),
        first_name: document.getElementById("i_first").value.trim(),
        last_name: document.getElementById("i_last").value.trim(),
        plan_name: document.getElementById("i_plan").value.trim() }) });
      document.getElementById("i_ok").textContent = d.message;
      ["i_email","i_first","i_last","i_plan"].forEach(id=>document.getElementById(id).value="");
    } catch(e){ document.getElementById("i_err").textContent=e.message; }
    finally { btn.disabled=false; }
  };
}

// ---------- render ----------
async function render() {
  if (!token) { loginView(); return; }
  document.getElementById("app").innerHTML = shell(`<div class="empty">Loading…</div>`);
  try {
    let inner="";
    if (tab==="users") inner = await usersView();
    else if (tab==="filtered") inner = await filteredView();
    else if (tab==="emails") inner = await emailsView();
    else if (tab==="invite") inner = inviteView();
    document.getElementById("main").innerHTML = inner;
    if (tab==="invite") bindInvite();
  } catch(e) {
    document.getElementById("main").innerHTML = `<div class="card err">${esc(e.message)}</div>`;
  }
}
render();
</script>
</body>
</html>"""
