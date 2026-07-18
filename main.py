import asyncio
import json
import os
import hashlib
import secrets
import time
import re
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
import psutil

# ====== SECRET KEY ======
try:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        SECRET_KEY = secrets.token_urlsafe(32)
        os.environ["SECRET_KEY"] = SECRET_KEY
        print(f"⚠️ SECRET_KEY created: {SECRET_KEY}")
except:
    SECRET_KEY = "vroom-default-secret-key"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("VROOM-Gateway")

app = FastAPI(title="VROOM", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8080)),
    "secret": SECRET_KEY,
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connections: dict = {}
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

CUSTOM_ADDRESSES: list = ["www.speedtest.net", "185.159.157.201", "185.159.157.202", "185.159.157.203", "178.22.122.100"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

CUSTOM_DOMAIN: str = ""
CUSTOM_DOMAIN_LOCK = asyncio.Lock()

SESSION_COOKIE = "vroom_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
                logger.info("Keep-alive ping sent")
        except Exception:
            pass

@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=5000, max_keepalive_connections=1000)
    timeout = httpx.Timeout(180.0, connect=30.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    logger.info(f"🚀 VROOM started on port {CONFIG['port']}")
    asyncio.create_task(keep_alive())

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def generate_vless_link(uuid: str, remark: str = "VROOM", address: str = None) -> str:
    domain = CUSTOM_DOMAIN if CUSTOM_DOMAIN else get_domain()
    addr = address if address else domain
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

def compute_expiry(expiry_days) -> str:
    try:
        days = float(expiry_days or 0)
    except:
        days = 0
    if days <= 0:
        return ""
    return (datetime.now() + timedelta(days=days)).isoformat()

def is_expired(link) -> bool:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return False
    try:
        return datetime.now() >= datetime.fromisoformat(exp)
    except:
        return False

def expiry_epoch(link) -> int:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return 0
    try:
        return int(datetime.fromisoformat(exp).timestamp())
    except:
        return 0

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            LINKS["Default"] = {"label": "Default", "limit_bytes": 0, "used_bytes": 0, "max_connections": 0, "created_at": datetime.now().isoformat(), "active": True, "expiry": ""}

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"

def count_connections_for_link(uid: str) -> int:
    return len(link_ip_map.get(uid, set()))

def remove_ip_from_link(uid: str, ip: str):
    if uid in link_ip_map:
        link_ip_map[uid].discard(ip)
        if not link_ip_map[uid]:
            link_ip_map.pop(uid, None)

async def close_connections_for_link(uid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    link_ip_map.pop(uid, None)

@app.get("/")
async def root():
    return {"service": "VROOM", "version": "1.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": await is_valid_session(token)}

@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent,
        "disk_used": round(psutil.disk_usage('/').used / (1024**3), 2),
        "disk_total": round(psutil.disk_usage('/').total / (1024**3), 2),
        "hourly_traffic": dict(hourly_traffic),
    }

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Inbound name must contain only English letters, numbers, and characters: - _ . space")
    if not label:
        raise HTTPException(status_code=400, detail="Inbound name is required")
    async with LINKS_LOCK:
        if label in LINKS:
            raise HTTPException(status_code=400, detail="An inbound with this name already exists")
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    max_conn = int(body.get("max_connections") or 0)
    if max_conn < 0:
        max_conn = 0
    expiry = compute_expiry(body.get("expiry_days"))
    uid = label
    async with LINKS_LOCK:
        LINKS[uid] = {"label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "max_connections": max_conn, "created_at": datetime.now().isoformat(), "active": True, "expiry": expiry}
    return {"uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "max_connections": max_conn, "active": True, "expiry": expiry, "created_at": LINKS[uid]["created_at"], "vless_link": generate_vless_link(uid, remark=f"VROOM-{label}")}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({"uuid": uid, "label": data["label"], "limit_bytes": data["limit_bytes"], "used_bytes": data["used_bytes"], "max_connections": data.get("max_connections", 0), "active": data["active"], "expiry": data.get("expiry", ""), "expired": is_expired(data), "created_at": data["created_at"], "current_connections": count_connections_for_link(uid), "vless_link": generate_vless_link(uid, remark=f"VROOM-{data['label']}")})
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "expiry_days" in body:
            LINKS[uid]["expiry"] = compute_expiry(body.get("expiry_days"))
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
        if "max_connections" in body:
            mc = int(body["max_connections"] or 0)
            LINKS[uid]["max_connections"] = mc if mc >= 0 else 0
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}

@app.get("/api/domain")
async def get_custom_domain(_=Depends(require_auth)):
    async with CUSTOM_DOMAIN_LOCK:
        return {"domain": CUSTOM_DOMAIN}

@app.post("/api/domain")
async def set_custom_domain(request: Request, _=Depends(require_auth)):
    body = await request.json()
    domain = (body.get("domain") or "").strip().lower()
    if domain:
        domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
        if not re.match(r'^[a-z0-9\-_.]+$', domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
    async with CUSTOM_DOMAIN_LOCK:
        global CUSTOM_DOMAIN
        CUSTOM_DOMAIN = domain
    return {"ok": True, "domain": CUSTOM_DOMAIN}

@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        return {"addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    address = (body.get("address") or "").strip()
    if not address:
        raise HTTPException(status_code=400, detail="Address is required")
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', address):
        raise HTTPException(status_code=400, detail="Address must contain only English letters, numbers, and characters: - _ .")
    async with CUSTOM_ADDRESSES_LOCK:
        if address in CUSTOM_ADDRESSES:
            raise HTTPException(status_code=400, detail="Address already exists")
        CUSTOM_ADDRESSES.append(address)
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            CUSTOM_ADDRESSES.pop(index)
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.get("/api/links/{uid}/sub")
async def get_subscription(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    vless_link = generate_vless_link(uid, remark=f"VROOM-{link['label']}")
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    used_mb = round(used / (1024 * 1024), 2)
    limit_mb = round(limit / (1024 * 1024), 2) if limit > 0 else 0
    pct = round((used / limit) * 100, 1) if limit > 0 else 0
    remaining_mb = round((limit - used) / (1024 * 1024), 2) if limit > 0 else 0
    import base64
    sub_content = f"""# VROOM Subscription
# Label: {link['label']}
# Used: {used_mb} MB / {limit_mb if limit > 0 else 'Unlimited'} MB
# Remaining: {remaining_mb if limit > 0 else 'Unlimited'} MB
# Usage: {pct}%
# Status: {'Active' if link['active'] else 'Disabled'}
# Expiry: {link.get('expiry', '')[:10] if link.get('expiry') else 'Unlimited'}
{vless_link}"""
    encoded = base64.b64encode(sub_content.encode()).decode()
    return {
        "subscription_url": f"{get_domain()}/api/links/{uid}/sub",
        "config": vless_link,
        "label": link["label"],
        "used_bytes": used,
        "limit_bytes": limit,
        "used_mb": used_mb,
        "limit_mb": limit_mb,
        "remaining_mb": remaining_mb,
        "usage_percent": pct,
        "active": link["active"],
        "sub_base64": encoded,
        "sub_text": sub_content,
    }


# ============================================================
# 📄 SUBSCRIPTION PAGE - ULTIMATE BEAUTY EDITION
# ============================================================
@app.get("/sub/{uid}")
async def subscription_page(uid: str):
    import base64
    
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="Link not found")
    
    if not link["active"]:
        raise HTTPException(status_code=403, detail="Link disabled")
    
    if is_expired(link):
        raise HTTPException(status_code=403, detail="Link expired")
    
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    
    sub_links = []
    server_link = generate_vless_link(uid, remark=f"VROOM-{link['label']}")
    sub_links.append(server_link)
    
    for i, addr in enumerate(addresses):
        remark = f"VROOM-{link['label']}-{i+1}"
        vless_link = generate_vless_link(uid, remark=remark, address=addr)
        sub_links.append(vless_link)
    
    config_base64 = base64.b64encode(server_link.encode()).decode()
    sub_content = "\n".join(sub_links)
    sub_base64 = base64.b64encode(sub_content.encode()).decode()
    
    used_gb = round(link['used_bytes'] / (1024 * 1024 * 1024), 2)
    limit_gb = round(link['limit_bytes'] / (1024 * 1024 * 1024), 2) if link['limit_bytes'] > 0 else 0
    percent = round((link['used_bytes'] / link['limit_bytes']) * 100, 1) if link['limit_bytes'] > 0 else 0
    
    if is_expired(link):
        status = "expired"
        status_text = "منقضی شده / Expired"
    elif link['limit_bytes'] > 0 and link['used_bytes'] >= link['limit_bytes']:
        status = "limited"
        status_text = "محدود شده / Limited"
    else:
        status = "active"
        status_text = "فعال / Active"
    
    exp = link.get("expiry")
    if exp:
        try:
            exp_date = datetime.fromisoformat(exp)
            days_left = (exp_date - datetime.now()).days
            if days_left < 0:
                days_left = 0
            days_left_text = f"{days_left} روز / {days_left} days"
        except:
            days_left_text = "نامحدود / Unlimited"
    else:
        days_left_text = "نامحدود / Unlimited"
    
    html = f"""<!DOCTYPE html>
<html lang="fa">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
    <title>🚀 VROOM</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Vazirmatn:wght@300;400;700;900&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        html, body {{
            height: 100%;
            overflow-y: auto;
            -webkit-overflow-scrolling: touch;
            scroll-behavior: smooth;
        }}
        body {{
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            font-family: 'Vazirmatn', 'Orbitron', 'Segoe UI', sans-serif;
            background: radial-gradient(ellipse at bottom, #0d1b2a 0%, #000000 100%);
            color: #fff;
            direction: rtl;
            padding: 20px;
            position: relative;
            overflow-y: auto;
            background-image: 
                radial-gradient(2px 2px at 20px 30px, #eee, transparent),
                radial-gradient(2px 2px at 40px 70px, rgba(255,255,255,0.8), transparent),
                radial-gradient(2px 2px at 50px 160px, #ddd, transparent),
                radial-gradient(2px 2px at 90px 40px, rgba(255,255,255,0.6), transparent),
                radial-gradient(2px 2px at 130px 80px, #fff, transparent),
                radial-gradient(2px 2px at 160px 30px, rgba(255,255,255,0.7), transparent);
            background-size: 200px 200px;
            background-repeat: repeat;
        }}
        /* Animated cosmic background */
        body::before {{
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(ellipse at 20% 50%, rgba(124,92,252,0.05) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 50%, rgba(167,139,250,0.05) 0%, transparent 50%);
            z-index: 0;
            pointer-events: none;
        }}
        .lang-toggle {{
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
            background: rgba(255,255,255,0.08);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 16px;
            padding: 10px 20px;
            color: #fff;
            cursor: pointer;
            font-family: 'Vazirmatn', sans-serif;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
            display: flex;
            gap: 10px;
            align-items: center;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }}
        .lang-toggle:hover {{ 
            background: rgba(255,255,255,0.15); 
            transform: scale(1.05) translateY(-2px);
            box-shadow: 0 12px 48px rgba(124,92,252,0.2);
        }}
        .lang-toggle .dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #34d399;
            box-shadow: 0 0 20px rgba(52,211,153,0.6);
            animation: pulse-dot 2s infinite;
        }}
        @keyframes pulse-dot {{ 0%,100% {{ opacity: 1; transform: scale(1); }} 50% {{ opacity: 0.5; transform: scale(0.8); }} }}
        .theme-selector {{
            position: fixed;
            right: 20px;
            top: 50%;
            transform: translateY(-50%);
            z-index: 100;
            display: flex;
            flex-direction: column;
            gap: 12px;
            background: rgba(255,255,255,0.06);
            backdrop-filter: blur(20px);
            padding: 14px 10px;
            border-radius: 20px;
            border: 1px solid rgba(255,255,255,0.06);
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }}
        .theme-btn {{
            width: 36px;
            height: 36px;
            border-radius: 50%;
            border: 2px solid rgba(255,255,255,0.15);
            cursor: pointer;
            transition: all 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
            position: relative;
        }}
        .theme-btn:hover {{ 
            transform: scale(1.2); 
            border-color: rgba(255,255,255,0.5);
            box-shadow: 0 0 30px rgba(255,215,0,0.15);
        }}
        .theme-btn.active {{ 
            border-color: #ffd700; 
            box-shadow: 0 0 25px rgba(255,215,0,0.3);
            transform: scale(1.1);
        }}
        .theme-btn.space {{ background: radial-gradient(ellipse at bottom, #0d1b2a 0%, #000000 100%); }}
        .theme-btn.ocean {{ background: linear-gradient(135deg, #1a2980, #26d0ce); }}
        .theme-btn.sunset {{ background: linear-gradient(135deg, #f12711, #f5af19); }}
        .theme-btn.forest {{ background: linear-gradient(135deg, #134e5e, #71b280); }}
        .theme-btn.neon {{ background: linear-gradient(135deg, #1d1d2e, #ff00cc); }}
        .loader-wrapper {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.9);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 9999;
            transition: opacity 0.8s ease, visibility 0.8s ease;
        }}
        .loader-wrapper.hide {{ opacity: 0; visibility: hidden; }}
        @keyframes spin-loader {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        .loader {{
            width: 70px;
            height: 70px;
            border: 3px solid rgba(255,255,255,0.05);
            border-top: 3px solid #7c5cfc;
            border-radius: 50%;
            animation: spin-loader 1s cubic-bezier(0.68, -0.55, 0.27, 1.55) infinite;
            box-shadow: 0 0 60px rgba(124,92,252,0.2);
        }}
        .loader-text {{
            margin-top: 25px;
            color: #a78bfa;
            font-size: 0.9rem;
            letter-spacing: 4px;
            text-align: center;
            font-family: 'Orbitron', monospace;
        }}
        .stars-layer {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 0;
        }}
        @keyframes twinkle {{ 0%,100% {{ opacity: 0.2; transform: scale(0.8); }} 50% {{ opacity: 1; transform: scale(1.3); }} }}
        .star {{
            position: absolute;
            background: white;
            border-radius: 50%;
            animation: twinkle var(--duration) ease-in-out infinite;
            animation-delay: var(--delay);
        }}
        @keyframes shoot {{
            0% {{ transform: translate(0,0) rotate(-45deg); opacity: 1; }}
            70% {{ opacity: 1; }}
            100% {{ transform: translate(-800px, 800px) rotate(-45deg); opacity: 0; }}
        }}
        .shooting-star {{
            position: fixed;
            width: 3px;
            height: 3px;
            background: #fff;
            border-radius: 50%;
            box-shadow: 0 0 20px 5px rgba(255,255,255,0.3);
            animation: shoot 5s linear infinite;
            z-index: 0;
            pointer-events: none;
        }}
        .shooting-star::after {{
            content: '';
            position: absolute;
            top: 50%;
            right: 0;
            width: 120px;
            height: 1px;
            background: linear-gradient(to left, rgba(255,255,255,0.5), transparent);
            transform: translateY(-50%);
        }}
        .shooting-star:nth-child(1) {{ top: 10%; left: 70%; animation-delay: 0s; }}
        .shooting-star:nth-child(2) {{ top: 30%; left: 50%; animation-delay: 3s; }}
        .shooting-star:nth-child(3) {{ top: 60%; left: 80%; animation-delay: 6s; }}
        .space-scene {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            opacity: 0.3;
        }}
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        @keyframes orbit-spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        @keyframes float {{ 0%,100% {{ transform: translateY(0px) scale(1); }} 50% {{ transform: translateY(-20px) scale(1.02); }} }}
        @keyframes pulse {{ 0%,100% {{ box-shadow: 0 0 80px rgba(75,158,218,0.2), inset -30px -30px 60px rgba(0,0,0,0.7); }} 50% {{ box-shadow: 0 0 120px rgba(75,158,218,0.3), inset -35px -35px 70px rgba(0,0,0,0.8); }} }}
        .earth-wrapper {{ position: relative; animation: float 6s ease-in-out infinite; }}
        .earth {{
            width: 180px;
            height: 180px;
            border-radius: 50%;
            position: relative;
            animation: spin 25s linear infinite, pulse 4s ease-in-out infinite;
            box-shadow: 0 0 80px rgba(75,158,218,0.2), inset -30px -30px 60px rgba(0,0,0,0.7);
            overflow: hidden;
        }}
        .earth-layer {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%; border-radius: 50%; }}
        .earth-base {{ background: radial-gradient(circle at 30% 30%, #4facfe, #1a4b7a 60%, #0a1a2a 95%); }}
        .earth-continents {{
            background:
                radial-gradient(ellipse at 70% 40%, #2d8a4e 15%, transparent 25%),
                radial-gradient(ellipse at 30% 60%, #2d8a4e 20%, transparent 30%),
                radial-gradient(ellipse at 50% 75%, #2d8a4e 10%, transparent 20%),
                radial-gradient(ellipse at 80% 70%, #2d8a4e 12%, transparent 22%),
                radial-gradient(ellipse at 15% 25%, #2d8a4e 8%, transparent 18%),
                radial-gradient(ellipse at 55% 30%, #3a9d5e 18%, transparent 28%);
            opacity: 0.8;
        }}
        .earth-clouds {{
            background:
                radial-gradient(ellipse at 20% 30%, rgba(255,255,255,0.2) 10%, transparent 25%),
                radial-gradient(ellipse at 70% 60%, rgba(255,255,255,0.15) 15%, transparent 30%),
                radial-gradient(ellipse at 40% 80%, rgba(255,255,255,0.15) 12%, transparent 22%),
                radial-gradient(ellipse at 85% 20%, rgba(255,255,255,0.12) 8%, transparent 20%),
                radial-gradient(ellipse at 10% 70%, rgba(255,255,255,0.1) 10%, transparent 20%);
            animation: spin 50s linear infinite reverse;
            opacity: 0.4;
        }}
        .earth-shine {{ background: radial-gradient(circle at 25% 25%, rgba(255,255,255,0.25) 0%, transparent 50%); }}
        .orbit {{
            position: absolute;
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 50%;
            animation: orbit-spin var(--orbit-duration) linear infinite;
        }}
        .orbit-1 {{ width: 340px; height: 340px; --orbit-duration: 20s; }}
        .orbit-2 {{ width: 460px; height: 460px; --orbit-duration: 35s; border-color: rgba(255,215,0,0.05); }}
        .orbit-3 {{ width: 580px; height: 580px; --orbit-duration: 50s; border-color: rgba(0,255,200,0.04); }}
        .satellite {{
            position: absolute;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            box-shadow: 0 0 30px currentColor;
        }}
        .satellite-1 {{ top: 5%; left: 80%; background: #ffd700; color: #ffd700; }}
        .satellite-2 {{ top: 80%; left: 10%; background: #ff6b6b; color: #ff6b6b; animation-delay: -10s; }}
        .satellite-3 {{ top: 20%; left: 5%; background: #4ecdc4; color: #4ecdc4; animation-delay: -20s; }}
        .rocket {{
            position: fixed;
            z-index: 1;
            font-size: 28px;
            animation: rocket-fly 10s linear infinite;
            filter: drop-shadow(0 0 30px rgba(255,100,0,0.4));
            pointer-events: none;
        }}
        .rocket:nth-child(2) {{ animation-delay: 5s; font-size: 20px; filter: drop-shadow(0 0 20px rgba(0,200,255,0.3)); }}
        @keyframes rocket-fly {{
            0% {{ transform: translate(-100px, 100px) rotate(-45deg) scale(0.5); opacity: 0; }}
            10% {{ opacity: 1; }}
            90% {{ opacity: 1; }}
            100% {{ transform: translate(100vw, -100vh) rotate(-45deg) scale(1.8); opacity: 0; }}
        }}
        .card {{
            position: relative;
            z-index: 10;
            background: rgba(255,255,255,0.04);
            backdrop-filter: blur(30px);
            -webkit-backdrop-filter: blur(30px);
            border-radius: 40px;
            padding: 40px 45px;
            width: 100%;
            max-width: 580px;
            border: 1px solid rgba(255,255,255,0.06);
            box-shadow: 0 40px 80px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.05);
            text-align: center;
            max-height: 95vh;
            overflow-y: auto;
            -webkit-overflow-scrolling: touch;
            overscroll-behavior: contain;
            will-change: transform;
        }}
        .card::-webkit-scrollbar {{ width: 4px; }}
        .card::-webkit-scrollbar-track {{ background: transparent; }}
        .card::-webkit-scrollbar-thumb {{ background: rgba(255,255,255,0.12); border-radius: 4px; }}
        .card:hover {{
            box-shadow: 0 50px 100px rgba(0,0,0,0.6), 0 0 60px rgba(124,92,252,0.03);
        }}
        .notification {{
            background: rgba(255,215,0,0.06);
            border: 1px solid rgba(255,215,0,0.08);
            border-radius: 16px;
            padding: 12px 18px;
            margin-bottom: 20px;
            font-size: 0.8rem;
            color: #ffd700;
            display: flex;
            align-items: center;
            gap: 10px;
            justify-content: center;
            flex-shrink: 0;
            font-family: 'Vazirmatn', sans-serif;
        }}
        .notification.success {{ background: rgba(52,211,153,0.06); border-color: rgba(52,211,153,0.1); color: #34d399; }}
        .badge {{
            display: inline-block;
            background: rgba(124,92,252,0.15);
            color: #a78bfa;
            padding: 6px 24px;
            border-radius: 50px;
            font-size: 0.7rem;
            letter-spacing: 3px;
            text-transform: uppercase;
            border: 1px solid rgba(124,92,252,0.1);
            margin-bottom: 14px;
            font-weight: 700;
            font-family: 'Orbitron', monospace;
            flex-shrink: 0;
        }}
        h1 {{
            font-size: 2.4rem;
            font-weight: 900;
            margin-bottom: 4px;
            background: linear-gradient(135deg, #7c5cfc, #a78bfa, #7c5cfc);
            background-size: 200% 200%;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: shimmer-text 4s ease-in-out infinite;
            font-family: 'Orbitron', monospace;
            letter-spacing: 2px;
            flex-shrink: 0;
        }}
        @keyframes shimmer-text {{
            0%,100% {{ background-position: 0% 50%; }}
            50% {{ background-position: 100% 50%; }}
        }}
        .subtitle {{ 
            font-size: 0.85rem; 
            opacity: 0.3; 
            margin-bottom: 28px; 
            letter-spacing: 3px;
            font-weight: 300;
            font-family: 'Orbitron', monospace;
            flex-shrink: 0;
        }}
        .status-with-dot {{ display: flex; align-items: center; gap: 8px; justify-content: center; }}
        .status-dot {{
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            flex-shrink: 0;
        }}
        .status-dot.active {{ background: #34d399; box-shadow: 0 0 20px rgba(52,211,153,0.5); }}
        .status-dot.limited {{ background: #fbbf24; box-shadow: 0 0 20px rgba(251,191,36,0.5); }}
        .status-dot.expired {{ background: #f87171; box-shadow: 0 0 20px rgba(248,113,113,0.5); }}
        .info-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            text-align: right;
            margin-bottom: 18px;
        }}
        .info-item {{
            background: rgba(255,255,255,0.03);
            padding: 14px 16px;
            border-radius: 18px;
            border: 1px solid rgba(255,255,255,0.03);
            transition: all 0.3s;
        }}
        .info-item:hover {{ background: rgba(255,255,255,0.06); transform: translateY(-2px); }}
        .info-item.full {{ grid-column: span 2; }}
        .label {{ 
            font-size: 0.55rem; 
            text-transform: uppercase; 
            opacity: 0.35; 
            letter-spacing: 2px; 
            display: block; 
            margin-bottom: 4px;
            font-weight: 700;
        }}
        .value {{ font-size: 1.1rem; font-weight: 700; }}
        .status-active {{ color: #34d399; }}
        .status-limited {{ color: #fbbf24; }}
        .status-expired {{ color: #f87171; }}
        .inbounds-section {{ margin: 14px 0 12px; text-align: right; flex-shrink: 0; }}
        .inbounds-title {{ 
            font-size: 0.6rem; 
            text-transform: uppercase; 
            opacity: 0.3; 
            letter-spacing: 2px; 
            margin-bottom: 8px;
            font-weight: 700;
        }}
        .inbound-tags {{ display: flex; flex-wrap: wrap; gap: 8px; justify-content: center; }}
        .inbound-tag {{
            background: rgba(255,255,255,0.04);
            padding: 5px 16px;
            border-radius: 20px;
            font-size: 0.65rem;
            border: 1px solid rgba(255,255,255,0.04);
            color: rgba(255,255,255,0.5);
            transition: all 0.3s;
            font-family: 'Vazirmatn', sans-serif;
        }}
        .inbound-tag:hover {{ 
            background: rgba(124,92,252,0.12); 
            border-color: rgba(124,92,252,0.15); 
            color: #a78bfa;
            transform: translateY(-2px);
        }}
        .progress-section {{ margin: 12px 0 16px; flex-shrink: 0; }}
        .progress-label {{ display: flex; justify-content: space-between; font-size: 0.75rem; opacity: 0.5; margin-bottom: 6px; }}
        .progress-bar {{ width: 100%; height: 6px; background: rgba(255,255,255,0.05); border-radius: 10px; overflow: hidden; }}
        .progress-fill {{ height: 100%; background: linear-gradient(90deg, #7c5cfc, #a78bfa); border-radius: 10px; transition: width 1s cubic-bezier(0.34, 1.56, 0.64, 1); width: {percent}%; box-shadow: 0 0 20px rgba(124,92,252,0.2); }}
        .qr-section {{ margin: 18px 0 8px; display: flex; justify-content: center; flex-shrink: 0; }}
        .qr-container {{
            background: rgba(255,255,255,0.95);
            padding: 16px;
            border-radius: 20px;
            display: inline-block;
            box-shadow: 0 8px 40px rgba(0,0,0,0.3);
            transition: all 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
        }}
        .qr-container:hover {{ transform: scale(1.04) rotate(2deg); box-shadow: 0 12px 60px rgba(124,92,252,0.15); }}
        .qr-container img {{ display: block; width: 180px; height: 180px; border-radius: 12px; max-width: 100%; }}
        .qr-label {{ font-size: 0.55rem; opacity: 0.3; margin-top: 8px; letter-spacing: 2px; }}
        .config-box {{
            background: rgba(0,0,0,0.3);
            padding: 14px 18px;
            border-radius: 16px;
            font-size: 0.7rem;
            font-family: 'Courier New', monospace;
            word-break: break-all;
            margin: 14px 0;
            max-height: 110px;
            overflow-y: auto;
            border: 1px solid rgba(255,255,255,0.04);
            text-align: left;
            direction: ltr;
            color: rgba(255,255,255,0.6);
            line-height: 1.8;
            -webkit-overflow-scrolling: touch;
            overscroll-behavior: contain;
        }}
        .config-box::-webkit-scrollbar {{ width: 3px; }}
        .config-box::-webkit-scrollbar-thumb {{ background: rgba(255,255,255,0.1); border-radius: 3px; }}
        .btn-group {{
            display: flex;
            justify-content: center;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 16px;
            flex-shrink: 0;
        }}
        .btn {{
            padding: 12px 28px;
            border-radius: 50px;
            font-weight: 700;
            font-size: 0.8rem;
            border: none;
            cursor: pointer;
            transition: all 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-family: 'Vazirmatn', sans-serif;
        }}
        .btn-primary {{ background: linear-gradient(135deg, #7c5cfc, #a78bfa); color: #fff; box-shadow: 0 8px 30px rgba(124,92,252,0.25); }}
        .btn-primary:hover {{ transform: translateY(-4px) scale(1.04); box-shadow: 0 12px 48px rgba(124,92,252,0.35); }}
        .btn-secondary {{ background: linear-gradient(135deg, #f7971e, #ffd200); color: #000; box-shadow: 0 8px 30px rgba(255,210,0,0.2); }}
        .btn-secondary:hover {{ transform: translateY(-4px) scale(1.04); box-shadow: 0 12px 48px rgba(255,210,0,0.3); }}
        .btn-success {{ background: linear-gradient(135deg, #11998e, #38ef7d); color: #fff; box-shadow: 0 8px 30px rgba(56,239,125,0.2); }}
        .btn-success:hover {{ transform: translateY(-4px) scale(1.04); box-shadow: 0 12px 48px rgba(56,239,125,0.3); }}
        .btn-sm {{ padding: 8px 18px; font-size: 0.7rem; }}
        .footer-text {{ margin-top: 20px; font-size: 0.55rem; opacity: 0.12; letter-spacing: 3px; font-family: 'Orbitron', monospace; flex-shrink: 0; }}
        @media (max-width: 500px) {{
            .card {{ padding: 20px 16px; }}
            h1 {{ font-size: 1.6rem; }}
            .info-grid {{ grid-template-columns: 1fr; }}
            .info-item.full {{ grid-column: span 1; }}
            .earth {{ width: 100px; height: 100px; }}
            .orbit-1 {{ width: 200px; height: 200px; }}
            .orbit-2 {{ width: 260px; height: 260px; }}
            .orbit-3 {{ width: 320px; height: 320px; }}
            .btn {{ font-size: 0.65rem; padding: 8px 16px; }}
            .qr-container img {{ width: 120px; height: 120px; }}
            .theme-selector {{ right: 10px; padding: 10px 6px; gap: 8px; }}
            .theme-btn {{ width: 28px; height: 28px; }}
            .lang-toggle {{ top: 10px; right: 10px; padding: 6px 14px; font-size: 10px; }}
            .config-box {{ max-height: 70px; font-size: 0.6rem; padding: 10px 12px; }}
        }}
        .glow-purple {{ text-shadow: 0 0 60px rgba(124,92,252,0.15); }}
        @keyframes float-orb {{
            0%,100% {{ transform: translateY(0px) rotate(0deg); }}
            50% {{ transform: translateY(-10px) rotate(5deg); }}
        }}
    </style>
</head>
<body>
    <button class="lang-toggle" onclick="toggleLang()" id="langBtn">
        <span class="dot"></span>
        <span id="langText">🇮🇷 فارسی</span>
    </button>
    <div class="theme-selector">
        <button class="theme-btn space active" data-theme="space" title="فضایی"></button>
        <button class="theme-btn ocean" data-theme="ocean" title="اقیانوسی"></button>
        <button class="theme-btn sunset" data-theme="sunset" title="غروب"></button>
        <button class="theme-btn forest" data-theme="forest" title="جنگلی"></button>
        <button class="theme-btn neon" data-theme="neon" title="نئون"></button>
    </div>
    <div class="loader-wrapper" id="loaderWrapper">
        <div style="text-align:center;">
            <div class="loader"></div>
            <div class="loader-text" id="loaderText">🌌 INITIALIZING... / در حال اتصال...</div>
        </div>
    </div>
    <div class="stars-layer" id="starsLayer"></div>
    <div class="shooting-star"></div><div class="shooting-star"></div><div class="shooting-star"></div>
    <div class="rocket">🚀</div><div class="rocket">🛸</div>
    <div class="space-scene">
        <div class="orbit orbit-1"><div class="satellite satellite-1"></div></div>
        <div class="orbit orbit-2"><div class="satellite satellite-2"></div></div>
        <div class="orbit orbit-3"><div class="satellite satellite-3"></div></div>
        <div class="earth-wrapper"><div class="earth"><div class="earth-layer earth-base"></div><div class="earth-layer earth-continents"></div><div class="earth-layer earth-clouds"></div><div class="earth-layer earth-shine"></div></div></div>
    </div>
    <div class="card">
        <div class="notification success" id="notificationBar">
            <span>🛰️</span>
            <span id="notificationText">ارتباط با ایستگاه فضایی برقرار است / Connection established</span>
        </div>
        <div class="badge">✦ VROOM</div>
        <h1 class="glow-purple">🚀 VROOM</h1>
        <div class="subtitle" id="subtitleText">GATEWAY // درگاه اتصال</div>
        <div class="info-grid">
            <div class="info-item full">
                <span class="label" id="statusLabel">وضعیت / Status</span>
                <span class="value status-{status}">
                    <span class="status-with-dot"><span class="status-dot {status}"></span><span id="statusText">{status_text}</span></span>
                </span>
            </div>
            <div class="info-item"><span class="label" id="usedLabel">📊 مصرف / Used</span><span class="value">{used_gb} GB</span></div>
            <div class="info-item"><span class="label" id="limitLabel">📦 حجم کل / Total</span><span class="value">{limit_gb if limit_gb > 0 else '∞'} GB</span></div>
            <div class="info-item"><span class="label" id="expiryLabel">⏳ انقضا / Expiry</span><span class="value" style="font-size:0.9rem;">{exp if exp else 'نامحدود / Unlimited'}</span></div>
            <div class="info-item"><span class="label" id="daysLabel">📅 روز باقی‌مانده / Days Left</span><span class="value">{days_left_text}</span></div>
        </div>
        <div class="inbounds-section">
            <div class="inbounds-title" id="serversTitle">🌐 سرورهای فعال / Active Servers</div>
            <div class="inbound-tags">
                <span class="inbound-tag">🚀 VLESS (اصلی / Main)</span>
                {''.join([f'<span class="inbound-tag">🌐 {addr}</span>' for addr in addresses[:3]])}
            </div>
        </div>
        <div class="progress-section">
            <div class="progress-label"><span id="usageLabel">میزان مصرف / Usage</span><span>{percent}%</span></div>
            <div class="progress-bar"><div class="progress-fill" style="width: {percent}%;"></div></div>
        </div>
        <div class="qr-section">
            <div class="qr-container">
                <img id="qrCodeImage" src="https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={config_base64}" alt="QR Code">
                <div class="qr-label">✦ اسکن کنید / Scan ✦</div>
            </div>
        </div>
        <div class="config-box" id="configBox">{server_link}</div>
        <div class="btn-group">
            <button class="btn btn-primary btn-sm" onclick="copyConfig()" id="copyBtn">📋 کپی / Copy</button>
            <button class="btn btn-secondary btn-sm" onclick="copySub()" id="subBtn">📥 ساب / Sub</button>
            <button class="btn btn-success btn-sm" onclick="showQR()" id="qrBtn">📱 QR</button>
        </div>
        <div class="footer-text">✦ VROOM GATEWAY v3.0 ✦</div>
    </div>
    <script>
        let currentLang = localStorage.getItem('vroom_sub_lang') || 'fa';
        const translations = {{
            fa: {{
                loader: '🌌 INITIALIZING... / در حال اتصال...',
                notification: 'ارتباط با ایستگاه فضایی برقرار است / Connection established',
                subtitle: 'GATEWAY // درگاه اتصال',
                status: 'وضعیت / Status',
                used: '📊 مصرف / Used',
                limit: '📦 حجم کل / Total',
                expiry: '⏳ انقضا / Expiry',
                days: '📅 روز باقی‌مانده / Days Left',
                servers: '🌐 سرورهای فعال / Active Servers',
                usage: 'میزان مصرف / Usage',
                copy: '📋 کپی / Copy',
                sub: '📥 ساب / Sub',
                qr: '📱 QR'
            }},
            en: {{
                loader: '🌌 INITIALIZING...',
                notification: 'Connection established',
                subtitle: 'GATEWAY',
                status: 'Status',
                used: '📊 Used',
                limit: '📦 Total',
                expiry: '⏳ Expiry',
                days: '📅 Days Left',
                servers: '🌐 Active Servers',
                usage: 'Usage',
                copy: '📋 Copy',
                sub: '📥 Sub',
                qr: '📱 QR'
            }}
        }};

        function toggleLang() {{
            currentLang = (currentLang === 'fa') ? 'en' : 'fa';
            const t = translations[currentLang];
            document.getElementById('loaderText').textContent = t.loader;
            document.getElementById('notificationText').textContent = t.notification;
            document.getElementById('subtitleText').textContent = t.subtitle;
            document.getElementById('statusLabel').textContent = t.status;
            document.getElementById('usedLabel').textContent = t.used;
            document.getElementById('limitLabel').textContent = t.limit;
            document.getElementById('expiryLabel').textContent = t.expiry;
            document.getElementById('daysLabel').textContent = t.days;
            document.getElementById('serversTitle').textContent = t.servers;
            document.getElementById('usageLabel').textContent = t.usage;
            document.getElementById('copyBtn').textContent = t.copy;
            document.getElementById('subBtn').textContent = t.sub;
            document.getElementById('qrBtn').textContent = t.qr;
            document.getElementById('langText').textContent = currentLang === 'fa' ? '🇮🇷 فارسی' : '🇬🇧 English';
            document.documentElement.lang = currentLang;
            document.documentElement.dir = currentLang === 'fa' ? 'rtl' : 'ltr';
            localStorage.setItem('vroom_sub_lang', currentLang);
        }}
        if (currentLang === 'en') toggleLang();

        const themeBtns = document.querySelectorAll('.theme-btn');
        const body = document.body;
        const themes = {{
            space: {{ background: 'radial-gradient(ellipse at bottom, #0d1b2a 0%, #000000 100%)' }},
            ocean: {{ background: 'linear-gradient(135deg, #1a2980 0%, #26d0ce 100%)' }},
            sunset: {{ background: 'linear-gradient(135deg, #f12711 0%, #f5af19 100%)' }},
            forest: {{ background: 'linear-gradient(135deg, #134e5e 0%, #71b280 100%)' }},
            neon: {{ background: 'linear-gradient(135deg, #1d1d2e 0%, #ff00cc 100%)' }}
        }};
        themeBtns.forEach(btn => {{
            btn.addEventListener('click', function() {{
                themeBtns.forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                const theme = this.dataset.theme;
                if (themes[theme]) body.style.background = themes[theme].background;
            }});
        }});
        window.addEventListener('load', function() {{
            setTimeout(() => document.getElementById('loaderWrapper').classList.add('hide'), 1800);
        }});
        (function createStars() {{
            const container = document.getElementById('starsLayer');
            for (let i = 0; i < 350; i++) {{
                const star = document.createElement('div');
                star.className = 'star';
                const size = Math.random() * 4 + 0.5;
                star.style.width = size + 'px';
                star.style.height = size + 'px';
                star.style.left = Math.random() * 100 + '%';
                star.style.top = Math.random() * 100 + '%';
                star.style.setProperty('--duration', (Math.random() * 5 + 2) + 's');
                star.style.setProperty('--delay', (Math.random() * 7) + 's');
                container.appendChild(star);
            }}
        }})();
        const config = '{server_link}';
        const subUrl = window.location.href;
        const uid = '{uid}';
        function copyConfig() {{ copyText(config, '✅ کانفیگ کپی شد! / Config copied!'); }}
        function copySub() {{ copyText(subUrl, '✅ لینک ساب کپی شد! / Subscription URL copied!'); }}
        function showQR() {{
            const qrImg = document.querySelector('.qr-container img');
            const currentSrc = qrImg.src;
            const newSize = Math.min(window.innerWidth - 80, 450);
            qrImg.src = 'https://api.qrserver.com/v1/create-qr-code/?size=' + newSize + 'x' + newSize + '&data=' + encodeURIComponent(config);
            setTimeout(() => {{
                if (!qrImg.src.includes('size=' + newSize)) {{
                    qrImg.src = currentSrc;
                }}
            }}, 5000);
            alert('📱 QR Code بزرگنمایی شد! / QR Code enlarged!');
        }}
        function copyText(text, message) {{
            if (navigator.clipboard) {{
                navigator.clipboard.writeText(text).then(() => alert(message));
            }} else {{
                const input = document.createElement('input');
                input.value = text;
                document.body.appendChild(input);
                input.select();
                document.execCommand('copy');
                document.body.removeChild(input);
                alert(message);
            }}
        }}
    </script>
</body>
</html>"""
    
    return HTMLResponse(content=html)


# ============================================================
# WEBSOCKET & PROXY - MAX SPEED (2MB buffer)
# ============================================================
RELAY_BUF = 2 * 1024 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 0
    pos += 1
    pos += 16
    addon_len = first_chunk[pos]
    pos += 1
    pos += addon_len
    command = first_chunk[pos]
    pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big")
    pos += 2
    addr_type = first_chunk[pos]
    pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]
        pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]
        pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]
        pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            return False
        if not link["active"]:
            return False
        if is_expired(link):
            return False
        return True

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            size = len(data)
            stats["total_bytes"] += size
            stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            writer.write(data)
            await writer.drain()
    except WebSocketDisconnect:
        pass
    finally:
        try:
            writer.write_eof()
        except:
            pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            size = len(data)
            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except:
        pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket.accept()
    writer = None
    conn_id = None
    client_ip = get_client_ip(websocket)
    try:
        async with LINKS_LOCK:
            link_data = LINKS.get(uuid)
            if link_data is None or not link_data["active"]:
                await websocket.close(code=1008, reason="link not found or disabled")
                return
            if is_expired(link_data):
                await websocket.close(code=1008, reason="link expired")
                return
            max_conn = link_data.get("max_connections", 0)
        if max_conn > 0:
            already_connected = client_ip in link_ip_map.get(uuid, set())
            if not already_connected:
                current = count_connections_for_link(uuid)
                if current >= max_conn:
                    await websocket.close(code=1008, reason="connection limit reached")
                    return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=10.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return
        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = websocket
        link_ip_map[uuid].add(client_ip)
        size = len(first_chunk)
        stats["total_bytes"] += size
        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        hourly_traffic[datetime.now().strftime("%H:00")] += size
        await add_usage(uuid, size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=5.0)
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            connections[conn_id]["bytes"] += p_size
            hourly_traffic[datetime.now().strftime("%H:00")] += p_size
            await add_usage(uuid, p_size)
            writer.write(initial_payload)
            await writer.drain()
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try:
                writer.close()
            except:
                pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                uid = info.get("uuid")
                ip = info.get("ip")
                if uid and ip:
                    has_other = any(c.get("uuid") == uid and c.get("ip") == ip for c in connections.values())
                    if not has_other:
                        remove_ip_from_link(uid, ip)


# ============================================================
# 🚪 LOGIN PAGE
# ============================================================
LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="fa" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VROOM</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
html[data-theme="dark"]{--bg:#0a0a0f;--surface:rgba(20,20,30,0.85);--surface2:#1a1a2e;--border:rgba(255,255,255,0.06);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#6c5ce7;--primary-glow:rgba(108,92,231,0.25);--accent:#a29bfe;--error:#ff6b6b;--error-bg:rgba(255,107,107,0.08)}
html[data-theme="light"]{--bg:#f0f2f5;--surface:rgba(255,255,255,0.9);--surface2:#f8f9fa;--border:rgba(0,0,0,0.06);--text:rgba(0,0,0,0.88);--text2:rgba(0,0,0,0.5);--text3:rgba(0,0,0,0.25);--primary:#6c5ce7;--primary-glow:rgba(108,92,231,0.15);--accent:#a29bfe;--error:#ff6b6b;--error-bg:rgba(255,107,107,0.06)}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);transition:background .5s,color .5s;overflow:hidden;direction:rtl}
.bg-canvas{position:fixed;inset:0;z-index:0;pointer-events:none}
.orb{position:absolute;border-radius:50%;filter:blur(100px);opacity:0.4;animation:orbFloat 25s ease-in-out infinite}
.orb-1{width:500px;height:500px;background:rgba(108,92,231,0.15);top:-20%;left:-10%;animation-delay:0s}
.orb-2{width:400px;height:400px;background:rgba(162,155,254,0.12);bottom:-15%;right:-10%;animation-delay:-8s}
.orb-3{width:300px;height:300px;background:rgba(108,92,231,0.08);top:40%;left:50%;animation-delay:-16s}
@keyframes orbFloat{0%,100%{transform:translate(0,0) scale(1)}25%{transform:translate(80px,-50px) scale(1.1)}50%{transform:translate(-40px,60px) scale(0.9)}75%{transform:translate(50px,30px) scale(1.05)}}
.grid-bg{position:fixed;inset:0;z-index:0;opacity:0.03;background-image:linear-gradient(rgba(255,255,255,0.05) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,0.05) 1px,transparent 1px);background-size:50px 50px;pointer-events:none}
.toolbar{position:fixed;top:20px;right:20px;display:flex;gap:6px;z-index:10}
.toolbar button{width:36px;height:36px;border-radius:10px;border:1px solid var(--border);background:var(--surface);color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:15px;transition:all .3s;backdrop-filter:blur(20px)}
.toolbar button:hover{border-color:var(--primary);color:var(--primary);transform:scale(1.05)}
.login-page{width:100%;max-width:400px;padding:0 20px;position:relative;z-index:1}
.login-card{background:var(--surface);border:1px solid var(--border);border-radius:28px;padding:48px 36px 36px;position:relative;overflow:hidden;backdrop-filter:blur(40px);box-shadow:0 20px 60px rgba(0,0,0,0.2),0 0 80px rgba(108,92,231,0.05);animation:cardIn .7s cubic-bezier(0.16,1,0.3,1) forwards;opacity:0;transform:translateY(30px) scale(0.96)}
@keyframes cardIn{to{opacity:1;transform:translateY(0) scale(1)}}
.login-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--primary),var(--accent),transparent);animation:shimmer 4s ease-in-out infinite}
@keyframes shimmer{0%,100%{opacity:0.4;transform:scaleX(0.3)}50%{opacity:1;transform:scaleX(1)}}
.login-card::after{content:'';position:absolute;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(circle at var(--mx,50%) var(--my,50%),rgba(108,92,231,0.05) 0%,transparent 50%);pointer-events:none;transition:opacity .3s;opacity:0}
.login-card:hover::after{opacity:1}
.brand{text-align:center;margin-bottom:36px}
.brand svg{margin-bottom:16px;filter:drop-shadow(0 0 30px rgba(108,92,231,0.3));animation:logoPulse 4s ease-in-out infinite}
@keyframes logoPulse{0%,100%{filter:drop-shadow(0 0 30px rgba(108,92,231,0.3));transform:scale(1)}50%{filter:drop-shadow(0 0 50px rgba(108,92,231,0.5));transform:scale(1.03)}}
.brand h1{font-size:26px;font-weight:800;color:var(--text);letter-spacing:-0.02em;animation:fadeUp .6s .2s ease both}
.brand p{font-size:12px;color:var(--text3);margin-top:4px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;animation:fadeUp .6s .3s ease both}
@keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.form-group{margin-bottom:20px;animation:fadeUp .6s .4s ease both}
.form-group label{display:block;font-size:11px;font-weight:700;color:var(--text2);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.06em}
.form-group input{width:100%;padding:14px 18px;background:var(--surface2);border:1.5px solid var(--border);border-radius:14px;color:var(--text);font-size:14px;font-family:inherit;outline:none;transition:all .3s cubic-bezier(0.4,0,0.2,1)}
.form-group input:focus{border-color:var(--primary);box-shadow:0 0 0 4px var(--primary-glow),0 0 30px var(--primary-glow)}
.form-group input::placeholder{color:var(--text3)}
.login-btn{width:100%;padding:14px;background:linear-gradient(135deg,var(--primary),var(--accent));border:none;border-radius:14px;color:#fff;font-size:15px;font-weight:700;font-family:inherit;cursor:pointer;transition:all .3s cubic-bezier(0.4,0,0.2,1);letter-spacing:0.02em;position:relative;overflow:hidden;animation:fadeUp .6s .5s ease both}
.login-btn::before{content:'';position:absolute;top:50%;left:50%;width:0;height:0;background:rgba(255,255,255,0.2);border-radius:50%;transform:translate(-50%,-50%);transition:width .5s,height .5s}
.login-btn:hover{filter:brightness(1.1);transform:translateY(-2px);box-shadow:0 8px 30px rgba(108,92,231,0.4)}
.login-btn:hover::before{width:400px;height:400px}
.login-btn:active{transform:translateY(0) scale(0.98)}
.error-msg{background:var(--error-bg);border:1px solid rgba(255,107,107,0.15);color:var(--error);padding:10px 14px;border-radius:12px;font-size:13px;display:none;margin-bottom:20px;text-align:center;font-weight:500;animation:shake .4s ease}
.error-msg.show{display:block}
@keyframes shake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
</style>
</head>
<body>
<div class="bg-canvas"><div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div></div>
<div class="grid-bg"></div>
<div class="toolbar">
  <button onclick="toggleTheme()" title="Theme">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
  </button>
</div>
<div class="login-page">
  <div class="login-card" id="login-card">
    <div class="brand">
      <svg width="56" height="56" viewBox="0 0 56 56" fill="none">
        <rect width="56" height="56" rx="14" fill="url(#lg)"/>
        <circle cx="28" cy="28" r="14" stroke="#fff" stroke-width="1.5" opacity="0.3"/>
        <circle cx="28" cy="18" r="3.5" fill="#fff"/>
        <circle cx="19" cy="33" r="3.5" fill="#fff"/>
        <circle cx="37" cy="33" r="3.5" fill="#fff"/>
        <line x1="28" y1="21.5" x2="21" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <line x1="28" y1="21.5" x2="35" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <line x1="22.5" y1="33" x2="33.5" y2="33" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <circle cx="28" cy="28" r="2" fill="#fff" opacity="0.9"/>
        <defs><linearGradient id="lg" x1="0" y1="0" x2="56" y2="56"><stop stop-color="#6c5ce7"/><stop offset="1" stop-color="#a29bfe"/></linearGradient></defs>
      </svg>
      <h1>VROOM</h1>
      <p>درگاه اتصال v1.0</p>
    </div>
    <div class="error-msg" id="err-box"></div>
    <form id="login-form">
      <div class="form-group">
        <label>رمز عبور</label>
        <input type="password" id="password" placeholder="ورود رمز عبور..." autofocus>
      </div>
      <button type="submit" class="login-btn">🚀 ورود</button>
    </form>
  </div>
</div>
<script>
let theme=localStorage.getItem('vroom_theme')||'dark';
function applyTheme(t){theme=t;document.documentElement.setAttribute('data-theme',t);localStorage.setItem('vroom_theme',t)}
function toggleTheme(){applyTheme(theme==='dark'?'light':'dark')}
applyTheme(theme);
const card=document.getElementById('login-card');
card.addEventListener('mousemove',e=>{const r=card.getBoundingClientRect();card.style.setProperty('--mx',((e.clientX-r.left)/r.width*100)+'%');card.style.setProperty('--my',((e.clientY-r.top)/r.height*100)+'%')});
document.getElementById('login-form').addEventListener('submit',async e=>{
  e.preventDefault();const err=document.getElementById('err-box');err.classList.remove('show');
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('password').value})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Failed');}
    location.href='/dashboard';
  }catch(e){err.textContent=e.message;err.classList.add('show')}
});
</script>
</body>
</html>"""


# ============================================================
# 📊 DASHBOARD - ULTIMATE BEAUTY EDITION
# ============================================================
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="fa" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>VROOM</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a12;--surface:#12121f;--surface2:#1a1a2e;--surface3:#252540;--border:rgba(255,255,255,0.05);--border2:rgba(255,255,255,0.08);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#7c5cfc;--primary-glow:rgba(124,92,252,0.3);--primary-dim:rgba(124,92,252,0.12);--accent:#a78bfa;--green:#34d399;--green-dim:rgba(52,211,153,0.1);--red:#f87171;--red-dim:rgba(248,113,113,0.08);--yellow:#fbbf24;--sidebar-bg:#0a0a12;--shadow:0 8px 40px rgba(0,0,0,0.5);}
html[data-theme="light"]{--bg:#f0f2f5;--surface:#ffffff;--surface2:#f8f9fa;--surface3:#f3f4f6;--border:rgba(0,0,0,0.06);--border2:rgba(0,0,0,0.1);--text:rgba(0,0,0,0.88);--text2:rgba(0,0,0,0.5);--text3:rgba(0,0,0,0.25);--primary:#7c5cfc;--primary-glow:rgba(124,92,252,0.15);--primary-dim:rgba(124,92,252,0.06);--accent:#a78bfa;--green:#34d399;--green-dim:rgba(52,211,153,0.06);--red:#f87171;--red-dim:rgba(248,113,113,0.06);--yellow:#fbbf24;--sidebar-bg:#ffffff;--shadow:0 8px 40px rgba(0,0,0,0.08);}
html,body{height:100%}
body{font-family:'Vazirmatn','Inter',-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;transition:all .4s;direction:rtl;background-image:radial-gradient(ellipse at 20% 50%,rgba(124,92,252,0.03),transparent 50%),radial-gradient(ellipse at 80% 50%,rgba(167,139,250,0.03),transparent 50%)}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:10px}
.sidebar{width:200px;background:var(--sidebar-bg);border-left:1px solid var(--border);display:flex;flex-direction:column;position:fixed;right:0;top:0;bottom:0;z-index:100;transition:all .4s}
.sidebar-brand{padding:14px 14px 10px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border)}
.sidebar-brand-left{display:flex;align-items:center;gap:8px}
.sidebar-brand-left .brand-name{font-size:15px;font-weight:900;background:linear-gradient(135deg,var(--primary),var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-family:'Orbitron',monospace}
.sidebar-brand-right button{width:28px;height:28px;border-radius:8px;border:1px solid var(--border);background:var(--surface);color:var(--text3);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:13px;transition:all .3s}
.sidebar-brand-right button:hover{border-color:var(--primary);color:var(--primary)}
.sidebar-nav{flex:1;padding:8px 6px;overflow-y:auto}
.nav-section{font-size:8px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.1em;padding:12px 8px 4px;font-family:'Orbitron',monospace}
.nav-item{display:flex;align-items:center;gap:8px;padding:7px 10px;margin:1px 0;border-radius:8px;color:var(--text2);font-size:11px;font-weight:500;cursor:pointer;transition:all .3s;border:none;background:none;width:100%;text-align:right}
.nav-item:hover{background:var(--primary-dim);color:var(--text);transform:translateX(-3px)}
.nav-item.active{background:var(--primary-dim);color:var(--primary);font-weight:600;box-shadow:inset -3px 0 0 var(--primary)}
.nav-icon{width:16px;height:16px;flex-shrink:0;opacity:0.7}
.nav-item.active .nav-icon{opacity:1}
.nav-badge{margin-right:auto;background:var(--primary);color:#fff;font-size:8px;padding:1px 6px;border-radius:20px;font-weight:700}
.sidebar-footer{padding:10px;border-top:1px solid var(--border)}
.sidebar-footer .footer-row{display:flex;gap:4px;margin-bottom:6px}
.sidebar-footer .footer-btn{flex:1;padding:5px;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--text3);font-family:inherit;font-size:9px;font-weight:700;cursor:pointer;transition:all .3s;text-align:center}
.sidebar-footer .footer-btn.active{background:linear-gradient(135deg,var(--primary),var(--accent));color:#fff;border-color:var(--primary)}
.sidebar-footer .footer-btn:hover:not(.active){border-color:var(--border2);color:var(--text2)}
.sidebar-footer .logout-btn{width:100%;padding:6px;border:1px solid var(--border);border-radius:6px;background:none;color:var(--text3);font-family:inherit;font-size:9px;font-weight:700;cursor:pointer;transition:all .3s;display:flex;align-items:center;justify-content:center;gap:4px}
.sidebar-footer .logout-btn:hover{background:var(--red-dim);border-color:rgba(248,113,113,0.2);color:var(--red)}
.sidebar-footer .version{text-align:center;font-size:8px;color:var(--text3);margin-top:4px;opacity:0.5;font-family:'Orbitron',monospace}
.main{margin-right:200px;flex:1;padding:12px 14px 24px;min-height:100vh}
.page{display:none;animation:pageIn .4s}
.page.active{display:block}
@keyframes pageIn{from{opacity:0;transform:translateY(10px) scale(0.96)}to{opacity:1;transform:translateY(0) scale(1)}}
.page-header{margin-bottom:12px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px}
.page-title{font-size:18px;font-weight:900;background:linear-gradient(135deg,var(--primary),var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-family:'Orbitron',monospace;letter-spacing:1px}
.page-sub{font-size:10px;color:var(--text3);margin-top:2px}
.stats-row{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:8px;margin-bottom:10px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:12px 14px;transition:all .3s;position:relative;overflow:hidden;backdrop-filter:blur(10px)}
.stat-card::before{content:'';position:absolute;top:0;right:0;width:60px;height:60px;background:radial-gradient(circle,var(--primary-glow),transparent 70%);border-radius:50%;transform:translate(40%,-40%);opacity:0.15;pointer-events:none}
.stat-card:hover{box-shadow:var(--shadow);transform:translateY(-2px)}
.stat-icon{font-size:18px;display:block;margin-bottom:2px}
.stat-label{font-size:8px;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:0.06em}
.stat-value{font-size:20px;font-weight:900;color:var(--text);letter-spacing:-0.02em}
.stat-unit{font-size:10px;font-weight:400;color:var(--text3);margin-right:2px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px;margin-bottom:10px;transition:all .3s;backdrop-filter:blur(10px)}
.card:hover{box-shadow:var(--shadow)}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;flex-wrap:wrap;gap:4px}
.card-title{font-size:13px;font-weight:700;color:var(--text);display:flex;align-items:center;gap:6px}
.btn{font-family:inherit;font-size:10px;font-weight:700;border-radius:8px;padding:5px 10px;cursor:pointer;display:inline-flex;align-items:center;gap:3px;border:none;transition:all .3s}
.btn-primary{background:linear-gradient(135deg,var(--primary),var(--accent));color:#fff;box-shadow:0 4px 16px var(--primary-glow)}
.btn-primary:hover{filter:brightness(1.1);transform:translateY(-2px)}
.btn-secondary{background:var(--surface3);color:var(--text2);border:1px solid var(--border)}
.btn-secondary:hover{border-color:var(--primary);color:var(--primary)}
.btn-danger{background:var(--red-dim);color:var(--red);border:1px solid rgba(248,113,113,0.12)}
.btn-danger:hover{background:rgba(248,113,113,0.2)}
.btn-sm{padding:3px 8px;font-size:9px}
.btn-success{background:var(--green-dim);color:var(--green);border:1px solid rgba(52,211,153,0.12)}
.btn-success:hover{background:rgba(52,211,153,0.2)}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.table-wrap{overflow-x:auto;border-radius:10px}
.table{width:100%;border-collapse:collapse}
.table th{text-align:right;font-size:9px;font-weight:700;color:var(--text3);padding:6px 8px;text-transform:uppercase;letter-spacing:0.05em;border-bottom:2px solid var(--border);background:var(--surface2)}
.table td{padding:6px 8px;border-bottom:1px solid var(--border);font-size:11px;vertical-align:middle}
.table tr:last-child td{border-bottom:none}
.table tbody tr:hover td{background:var(--primary-dim)}
.tag{display:inline-flex;align-items:center;padding:2px 8px;border-radius:12px;font-size:8px;font-weight:700;letter-spacing:0.04em;text-transform:uppercase}
.tag-vless{background:var(--primary-dim);color:var(--primary)}
.tag-active{background:var(--green-dim);color:var(--green)}
.tag-disabled{background:var(--red-dim);color:var(--red)}
.usage-pill{display:flex;align-items:center;gap:4px;padding:2px 8px;border-radius:999px;background:var(--surface3);font-size:9px;color:var(--text2)}
.usage-pill .used{color:var(--text);font-weight:600}
.usage-pill .bar{flex:1;height:3px;background:var(--bg);border-radius:2px;min-width:30px;overflow:hidden}
.usage-pill .fill{height:100%;border-radius:2px;transition:width .6s}
.usage-pill .limit{color:var(--text3)}
.toggle{width:30px;height:16px;border-radius:8px;background:var(--surface3);position:relative;cursor:pointer;transition:all .4s;border:1px solid var(--border)}
.toggle::after{content:'';position:absolute;width:10px;height:10px;border-radius:50%;background:var(--text3);top:2px;right:2px;transition:all .4s}
.toggle.on{background:var(--green);border-color:var(--green);box-shadow:0 0 16px rgba(52,211,153,0.3)}
.toggle.on::after{right:16px;background:#fff}
.sys-bar{height:4px;background:var(--surface3);border-radius:3px;overflow:hidden}
.sys-bar-fill{height:100%;border-radius:3px;transition:width .6s}
.status-item{display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)}
.status-item:last-child{border-bottom:none}
.status-key{color:var(--text2);font-size:11px;display:flex;align-items:center;gap:4px}
.status-val{color:var(--text);font-weight:600;font-size:11px}
.form-group{display:flex;flex-direction:column;gap:3px;margin-bottom:8px}
.form-label{font-size:9px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:0.05em}
.form-input,.form-select{padding:6px 10px;border-radius:8px;border:1px solid var(--border);font-family:inherit;font-size:11px;outline:none;color:var(--text);background:var(--surface2);transition:all .3s}
.form-input:focus,.form-select:focus{border-color:var(--primary);box-shadow:0 0 0 4px var(--primary-glow)}
.form-select option{background:var(--surface2);color:var(--text)}
.form-row{display:flex;gap:6px;flex-wrap:wrap;align-items:flex-end}
.form-row .form-group{margin-bottom:0;flex:1;min-width:70px}
.empty{text-align:center;padding:20px 12px;color:var(--text3)}
.empty-icon{font-size:32px;margin-bottom:4px;opacity:0.2}
.toast{position:fixed;bottom:12px;left:50%;transform:translateX(-50%) translateY(16px);background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:10px;padding:8px 16px;font-size:11px;font-weight:500;opacity:0;transition:all .4s;z-index:999;display:flex;align-items:center;gap:6px;box-shadow:0 8px 24px rgba(0,0,0,0.3);backdrop-filter:blur(20px)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.error{border-color:var(--red-dim);color:var(--red)}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(6px)}
.modal-overlay.show{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px 20px;width:100%;max-width:400px;position:relative;box-shadow:0 16px 48px rgba(0,0,0,0.4);transform:scale(0.9) translateY(12px);opacity:0;transition:all .4s}
.modal-overlay.show .modal{transform:scale(1) translateY(0);opacity:1}
.modal-title{font-size:15px;font-weight:800;margin-bottom:12px;color:var(--text)}
.modal-close{position:absolute;top:10px;left:10px;background:var(--surface3);border:1px solid var(--border);color:var(--text3);width:26px;height:26px;border-radius:6px;cursor:pointer;font-size:12px;display:flex;align-items:center;justify-content:center;transition:all .3s}
.modal-close:hover{background:var(--red-dim);color:var(--red)}
.qr-box{text-align:center;padding:12px;background:var(--surface2);border-radius:12px;margin-top:6px;border:1px solid var(--border)}
.qr-box img{max-width:160px;border-radius:10px}
.btn-copy,.btn-qr{font-family:inherit;font-size:9px;font-weight:600;border-radius:6px;padding:3px 8px;cursor:pointer;border:none;display:inline-flex;align-items:center;gap:2px;transition:all .3s}
.btn-copy{background:var(--primary-dim);color:var(--primary);border:1px solid rgba(124,92,252,0.15)}
.btn-copy:hover{background:var(--primary);color:#fff}
.btn-qr{background:var(--green-dim);color:var(--green);border:1px solid rgba(52,211,153,0.15)}
.btn-qr:hover{background:var(--green);color:#fff}
.detail-label{font-size:8px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:2px}
.detail-value{padding:4px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;font-size:10px;color:var(--text2);word-break:break-all;font-family:monospace;line-height:1.4}
.detail-row{display:flex;gap:6px;margin-bottom:6px}
.detail-row .detail-col{flex:1}
.detail-actions{display:flex;gap:4px;flex-wrap:wrap;margin-top:8px}
.inbounds-toolbar{display:flex;align-items:center;gap:6px;margin-bottom:10px;flex-wrap:wrap}
.search-box{flex:1;min-width:120px;position:relative}
.search-box input{width:100%;padding:5px 10px 5px 30px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:11px;font-family:inherit;outline:none;transition:all .3s}
.search-box input:focus{border-color:var(--primary);box-shadow:0 0 0 4px var(--primary-glow)}
.search-box svg{position:absolute;right:8px;top:50%;transform:translateY(-50%);color:var(--text3)}
.filter-chips{display:flex;gap:2px;padding:2px 4px;background:var(--surface2);border:1px solid var(--border);border-radius:8px}
.chip{padding:3px 8px;border-radius:4px;font-size:9px;font-weight:600;color:var(--text3);cursor:pointer;border:none;background:none;transition:all .3s;font-family:inherit}
.chip.active{background:var(--primary);color:#fff}
.chip:hover:not(.active){background:var(--surface3);color:var(--text2)}
.inbound-cards{display:none;flex-direction:column;gap:6px}
.inbound-card{border:1px solid var(--border);border-radius:10px;padding:10px 12px;background:var(--surface2);display:flex;flex-direction:column;gap:6px}
.inbound-card-header{display:flex;align-items:center;justify-content:space-between}
.inbound-card-id{font-size:8px;color:var(--text3);font-weight:600}
.inbound-card-name{font-size:12px;font-weight:600;color:var(--text)}
.inbound-card-actions{display:flex;gap:3px;flex-wrap:wrap}
.mobile-header{display:none;position:fixed;top:0;left:0;right:0;height:44px;background:var(--sidebar-bg);border-bottom:1px solid var(--border);z-index:90;align-items:center;justify-content:space-between;padding:0 12px;backdrop-filter:blur(20px)}
.menu-toggle{width:30px;height:30px;border-radius:6px;border:1px solid var(--border);background:var(--surface);color:var(--text2);display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:16px}
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:99}
.sidebar-overlay.show{display:block}
.circle-wrap{display:flex;justify-content:center;align-items:center;gap:16px;padding:4px 0}
.circle{position:relative;width:60px;height:60px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center}
.circle canvas{position:absolute;top:0;left:0;width:60px;height:60px}
.circle .label{font-size:7px;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;opacity:0.5}
.circle .value{font-size:11px;font-weight:900;z-index:1}
.circle .sub{font-size:6px;opacity:0.3}
.circle.cpu .value{color:var(--primary)}
.circle.memory .value{color:var(--green)}
.speed-display{display:flex;justify-content:center;gap:14px;padding:4px 0;background:var(--surface2);border-radius:8px;margin-top:4px}
.speed-item{text-align:center;padding:4px 10px}
.speed-item .label{font-size:7px;color:var(--text3);text-transform:uppercase;letter-spacing:0.04em}
.speed-item .value{font-size:14px;font-weight:800;color:var(--text)}
.speed-item .unit{font-size:8px;color:var(--text3)}
@media(max-width:768px){
  .sidebar{transform:translateX(100%);width:220px;z-index:200}
  .sidebar.open{transform:translateX(0);box-shadow:-4px 0 32px rgba(0,0,0,0.4)}
  .main{margin-right:0;padding-top:52px;padding-left:8px;padding-right:8px}
  .mobile-header{display:flex}
  .stats-row{grid-template-columns:1fr 1fr;gap:6px}
  .grid-2{grid-template-columns:1fr}
  .inbounds-toolbar{flex-direction:column;align-items:stretch}
  .search-box{min-width:unset}
  .filter-chips{justify-content:center}
  .table-wrap{display:none}
  .inbound-cards{display:flex}
  .circle-wrap{gap:12px}
  .circle{width:50px;height:50px}
  .circle canvas{width:50px;height:50px}
  .speed-display{flex-wrap:wrap;gap:8px}
}
@media(max-width:480px){.stats-row{grid-template-columns:1fr}}
.quick-actions{display:flex;gap:4px;flex-wrap:wrap}
.quick-actions .btn{font-size:9px;padding:4px 10px}
.glow-box{background:linear-gradient(135deg,var(--primary-dim),transparent);border:1px solid rgba(124,92,252,0.1);border-radius:10px;padding:10px;text-align:center}
.system-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:6px}
.system-item{background:var(--surface2);border-radius:8px;padding:8px 10px;text-align:center;border:1px solid var(--border);transition:all .3s}
.system-item:hover{border-color:var(--primary);transform:translateY(-2px)}
.system-item .label{font-size:7px;color:var(--text3);text-transform:uppercase;letter-spacing:0.04em}
.system-item .value{font-size:13px;font-weight:700;color:var(--text)}
.system-item .sub{font-size:8px;color:var(--text2)}
</style>
</head>
<body>
<div class="toast" id="toast"></div>
<div class="mobile-header"><span style="font-weight:900;font-size:14px;background:linear-gradient(135deg,var(--primary),var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-family:'Orbitron',monospace">VROOM</span><button class="menu-toggle" onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebar-overlay').classList.toggle('show')">☰</button></div>
<div class="sidebar-overlay" id="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('show')"></div>
<aside class="sidebar" id="sidebar">
  <div class="sidebar-brand">
    <div class="sidebar-brand-left"><svg width="22" height="22" viewBox="0 0 56 56" fill="none"><rect width="56" height="56" rx="14" fill="url(#lg)"/><circle cx="28" cy="28" r="14" stroke="#fff" stroke-width="1.5" opacity="0.3"/><circle cx="28" cy="18" r="3.5" fill="#fff"/><circle cx="19" cy="33" r="3.5" fill="#fff"/><circle cx="37" cy="33" r="3.5" fill="#fff"/><line x1="28" y1="21.5" x2="21" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/><line x1="28" y1="21.5" x2="35" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/><line x1="22.5" y1="33" x2="33.5" y2="33" stroke="#fff" stroke-width="1.5" opacity="0.8"/><circle cx="28" cy="28" r="2" fill="#fff" opacity="0.9"/><defs><linearGradient id="lg" x1="0" y1="0" x2="56" y2="56"><stop stop-color="#7c5cfc"/><stop offset="1" stop-color="#a78bfa"/></linearGradient></defs></svg><span class="brand-name">VROOM</span></div>
    <div class="sidebar-brand-right"><button onclick="toggleTheme()" id="theme-btn">🌓</button></div>
  </div>
  <nav class="sidebar-nav">
    <div class="nav-section">MAIN</div>
    <button class="nav-item active" data-page="dashboard"><svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg><span id="navDashboard">داشبورد</span></button>
    <button class="nav-item" data-page="inbounds"><svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg><span id="navInbounds">اینباندها</span><span class="nav-badge" id="links-badge">0</span></button>
    <button class="nav-item" data-page="traffic"><svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg><span id="navTraffic">ترافیک</span></button>
    <button class="nav-item" data-page="addresses"><svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg><span id="navAddresses">آی‌پی تمیز</span></button>
    <button class="nav-item" data-page="domain"><svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg><span id="navDomain">دامنه</span></button>
    <div class="nav-section">SYSTEM</div>
    <button class="nav-item" data-page="security"><svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg><span id="navSecurity">امنیت</span></button>
  </nav>
  <div class="sidebar-footer">
    <div class="footer-row"><button class="footer-btn active" onclick="setLang('fa')" id="lang-fa">🇮🇷</button><button class="footer-btn" onclick="setLang('en')" id="lang-en">🇬🇧</button></div>
    <button class="logout-btn" onclick="fetch('/api/logout',{method:'POST'}).then(()=>location.href='/login')"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg><span id="logoutText">خروج</span></button>
    <div class="version">VROOM v3.0</div>
  </div>
</aside>
<main class="main">
  <section class="page active" id="page-dashboard">
    <div class="page-header"><div><div class="page-title" id="dashboardTitle">📊 DASHBOARD</div><div class="page-sub" id="lastUpdate">🔄 آخرین بروزرسانی: --</div></div><div class="quick-actions"><button class="btn btn-secondary" onclick="quickCreate(0.5,'GB')" id="dash05">+0.5</button><button class="btn btn-primary" onclick="quickCreate(1,'GB')" id="dash1">+1</button><button class="btn btn-success" onclick="quickCreate(5,'GB')" id="dash5">+5</button></div></div>
    <div class="stats-row">
      <div class="stat-card"><span class="stat-icon">📊</span><div class="stat-label" id="sTrafficLabel">ترافیک کل</div><div class="stat-value" id="s-traffic">--<span class="stat-unit">MB</span></div></div>
      <div class="stat-card"><span class="stat-icon">📡</span><div class="stat-label" id="sLinksLabel">اینباندها</div><div class="stat-value" id="s-links">--</div></div>
      <div class="stat-card"><span class="stat-icon">⏱️</span><div class="stat-label" id="sUptimeLabel">آپتایم</div><div class="stat-value" id="s-uptime" style="font-size:14px">--</div></div>
      <div class="stat-card"><span class="stat-icon">🌐</span><div class="stat-label" id="sDomainLabel">دامنه</div><div class="stat-value" id="s-domain" style="font-size:11px;word-break:break-all;font-weight:600">--</div></div>
    </div>
    <div class="card"><div class="card-header"><div class="card-title" id="resourcesTitle">⚡ SYSTEM RESOURCES</div></div>
      <div class="system-grid">
        <div class="system-item"><div class="label">💾 DISK</div><div class="value" id="s-disk-used">--</div><div class="sub" id="s-disk-total">از --</div></div>
        <div class="system-item"><div class="label">🧠 RAM</div><div class="value" id="s-mem-val">--%</div><div class="sub" id="s-mem-detail">-- / -- GB</div></div>
        <div class="system-item"><div class="label">⚡ CPU</div><div class="value" id="s-cpu-val">--%</div><div class="sub">مصرف</div></div>
        <div class="system-item"><div class="label">🔗 CONNECTIONS</div><div class="value" id="s-connections">--</div><div class="sub">فعال</div></div>
      </div>
      <div class="speed-display">
        <div class="speed-item"><div class="label" id="dlLabel">📥 DOWNLOAD</div><div class="value" id="dl-speed">0</div><div class="unit">Mbps</div></div>
        <div class="speed-item"><div class="label" id="ulLabel">📤 UPLOAD</div><div class="value" id="ul-speed">0</div><div class="unit">Mbps</div></div>
        <div class="speed-item"><div class="label" id="pingLabel">📶 PING</div><div class="value" id="ping-speed">0</div><div class="unit">ms</div></div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card"><div class="card-header"><div class="card-title" id="chartTitle">📈 TRAFFIC CHART</div></div><div style="height:130px"><canvas id="trafficChart"></canvas></div></div>
      <div class="card"><div class="card-header"><div class="card-title">⚡ QUICK ACCESS</div></div>
        <div class="glow-box" style="margin-bottom:6px"><span style="font-size:11px;color:var(--text2)">🔗 Active Connections: <strong style="color:var(--primary)" id="quickConnections">0</strong></span></div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px">
          <button class="btn btn-secondary btn-sm" onclick="switchPage('inbounds')">📡 Inbounds</button>
          <button class="btn btn-secondary btn-sm" onclick="switchPage('traffic')">📊 Traffic</button>
          <button class="btn btn-secondary btn-sm" onclick="switchPage('addresses')">🌐 IP</button>
          <button class="btn btn-secondary btn-sm" onclick="switchPage('domain')">🌍 Domain</button>
        </div>
      </div>
    </div>
  </section>
  <section class="page" id="page-inbounds">
    <div class="page-header"><div><div class="page-title" id="inboundTitle">📡 INBOUNDS</div><div class="page-sub" id="inboundSub">مدیریت اتصالات VLESS</div></div><button class="btn btn-primary" onclick="showAddModal()" id="addBtn">➕ افزودن</button></div>
    <div class="inbounds-toolbar"><div class="search-box"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg><input id="inbound-search" placeholder="جستجو..." oninput="filterInbounds()"></div><div class="filter-chips"><button class="chip active" onclick="setFilter('all',this)" id="filterAll">همه</button><button class="chip" onclick="setFilter('active',this)" id="filterActive">فعال</button><button class="chip" onclick="setFilter('disabled',this)" id="filterDisabled">غیرفعال</button></div></div>
    <div class="card" style="padding:0;overflow:hidden;border-radius:10px">
      <div class="table-wrap"><table class="table"><thead><tr><th style="width:24px">#</th><th id="thName">نام</th><th style="width:44px" id="thType">نوع</th><th id="thTraffic">ترافیک</th><th style="width:50px" id="thIP">IP</th><th style="width:50px" id="thStatus">وضعیت</th><th style="width:100px" id="thActions">عملیات</th></tr></thead><tbody id="links-tbody"></tbody></table></div>
      <div class="inbound-cards" id="inbound-cards"></div>
      <div class="empty" id="links-empty" style="display:none"><div class="empty-icon">📭</div><div id="emptyText">هیچ اینباندی یافت نشد</div></div>
    </div>
  </section>
  <section class="page" id="page-traffic">
    <div class="page-header"><div><div class="page-title" id="trafficTitle">📊 TRAFFIC</div><div class="page-sub" id="trafficSub">آمار و ارقام</div></div></div>
    <div class="card"><div class="card-header"><div class="card-title" id="overviewTitle">📋 خلاصه</div></div><div class="status-item"><span class="status-key" id="totalTrafficLabel">📥 کل ترافیک</span><span class="status-val" id="t-traffic">-- MB</span></div><div class="status-item"><span class="status-key" id="totalRequestsLabel">📨 کل درخواست‌ها</span><span class="status-val" id="t-reqs">--</span></div><div class="status-item"><span class="status-key" id="uptimeLabel2">⏱️ آپتایم</span><span class="status-val" id="t-uptime">--</span></div><div class="status-item"><span class="status-key" id="errorsLabel">🔴 خطاها</span><span class="status-val" id="t-errors" style="color:var(--red)">--</span></div><div class="status-item"><span class="status-key" id="connectionsLabel">🔗 اتصالات فعال</span><span class="status-val" id="t-connections">--</span></div></div>
  </section>
  <section class="page" id="page-addresses">
    <div class="page-header"><div><div class="page-title" id="addressTitle">🌐 CLEAN IP</div><div class="page-sub" id="addressSub">مدیریت آی‌پی‌ها</div></div><button class="btn btn-primary" onclick="showAddAddressModal()" id="addAddressBtn">➕ افزودن</button></div>
    <div class="card"><div class="card-header"><div class="card-title" id="addressListTitle">📋 لیست آی‌پی‌ها</div></div><div class="status-item" style="flex-direction:column;gap:4px;padding:0"><div style="display:flex;justify-content:space-between;width:100%;padding:4px 0"><span class="status-key" style="color:var(--text3);font-size:10px" id="defaultAddress">پیش‌فرض: www.speedtest.net</span></div><div id="address-list" style="display:flex;flex-direction:column;gap:4px;width:100%;padding-bottom:4px"></div></div></div>
  </section>
  <section class="page" id="page-domain">
    <div class="page-header"><div><div class="page-title" id="domainTitle">🌐 DOMAIN</div><div class="page-sub" id="domainSub">جایگزینی دامنه</div></div></div>
    <div class="card" style="max-width:440px"><div class="card-header"><div class="card-title" id="domainSettings">⚙️ تنظیمات</div></div><div id="domain-current" style="margin-bottom:8px"><div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:8px"><div style="display:flex;align-items:center;gap:8px"><span style="font-size:16px">🌐</span><div><div style="font-size:8px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.05em" id="currentDomainLabel">دامنه فعلی</div><div id="domain-value" style="font-size:12px;font-weight:600;color:var(--text);margin-top:1px;font-family:monospace">--</div></div></div><button class="btn btn-danger btn-sm" onclick="clearDomain()" style="display:none" id="domain-clear-btn">🗑️</button></div></div><div style="padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;margin-bottom:8px"><div style="font-size:8px;font-weight:700;color:var(--text3);margin-bottom:2px;text-transform:uppercase;letter-spacing:0.05em" id="defaultDomainLabel">دامنه پیش‌فرض</div><div id="render-domain" style="font-size:12px;color:var(--text2);font-family:monospace">--</div></div><div class="form-group"><label class="form-label" id="newDomainLabel">دامنه جدید</label><div style="display:flex;gap:6px"><input class="form-input" id="domain-input" placeholder="example.com" style="flex:1"><button class="btn btn-primary" onclick="saveDomain()" id="saveDomainBtn">💾</button></div></div></div>
  </section>
  <section class="page" id="page-security">
    <div class="page-header"><div><div class="page-title" id="securityTitle">🔒 SECURITY</div><div class="page-sub" id="securitySub">تغییر رمز</div></div></div>
    <div class="card" style="max-width:360px"><div class="card-header"><div class="card-title" id="changePassTitle">🔑 تغییر رمز</div></div><div class="form-group"><label class="form-label" id="curPassLabel">رمز فعلی</label><input class="form-input" type="password" id="cur-pw" placeholder="رمز فعلی"></div><div class="form-group"><label class="form-label" id="newPassLabel">رمز جدید</label><input class="form-input" type="password" id="new-pw" placeholder="حداقل ۴ کاراکتر"></div><button class="btn btn-primary" onclick="changePassword()" style="width:100%;justify-content:center;padding:8px" id="changePassBtn">🔄 تغییر رمز</button></div>
  </section>
</main>

<!-- Modals -->
<div class="modal-overlay" id="add-modal" onclick="if(event.target===this)this.classList.remove('show')"><div class="modal"><button class="modal-close" onclick="$('#add-modal').classList.remove('show')">✕</button><div class="modal-title" id="addModalTitle">➕ افزودن اینباند</div><div class="form-group"><label class="form-label" id="nameLabel">نام</label><input class="form-input" id="new-label" placeholder="مثال: کاربر ۱"></div><div class="form-row"><div class="form-group"><label class="form-label" id="limitLabel2">محدودیت ترافیک</label><input class="form-input" id="new-limit" type="number" min="0" step="0.1" placeholder="۰"></div><div class="form-group" style="min-width:70px;max-width:90px"><label class="form-label" id="unitLabel">واحد</label><select class="form-select" id="new-unit"><option value="GB">GB</option><option value="MB">MB</option></select></div></div><div class="form-group"><label class="form-label" id="expiryLabel2">انقضا (روز)</label><input class="form-input" id="new-expiry" type="number" min="0" step="1" placeholder="۰"></div><div class="form-row"><div class="form-group"><label class="form-label" id="dlSpeedLabel">دانلود (Mbps)</label><input class="form-input" id="new-dl-speed" type="number" min="0" step="1" placeholder="۰"></div><div class="form-group"><label class="form-label" id="ulSpeedLabel">آپلود (Mbps)</label><input class="form-input" id="new-ul-speed" type="number" min="0" step="1" placeholder="۰"></div></div><div class="form-group"><label class="form-label" id="maxIPLabel">حداکثر IP</label><input class="form-input" id="new-maxconn" type="number" min="0" step="1" placeholder="۰"></div><button class="btn btn-primary" onclick="createLink()" style="width:100%;margin-top:6px;justify-content:center;padding:8px" id="createBtn">🚀 ایجاد</button></div></div>

<div class="modal-overlay" id="detail-modal" onclick="if(event.target===this)this.classList.remove('show')"><div class="modal" style="max-width:440px"><button class="modal-close" onclick="$('#detail-modal').classList.remove('show')">✕</button><div class="modal-title" id="detailTitle">📋 جزئیات</div><div id="detail-content"></div></div></div>

<div class="modal-overlay" id="qr-modal" onclick="if(event.target===this)this.classList.remove('show')"><div class="modal"><button class="modal-close" onclick="$('#qr-modal').classList.remove('show')">✕</button><div class="modal-title" id="qrTitle">📱 QR Code</div><div class="qr-box"><img id="qr-img" src="" alt="QR"></div><div style="margin-top:10px;text-align:center;display:flex;gap:6px;justify-content:center"><button class="btn btn-primary" onclick="downloadQR()" style="padding:6px 14px" id="downloadQRBtn">⬇️ دانلود</button><button class="btn btn-secondary" onclick="$('#qr-modal').classList.remove('show')" style="padding:6px 14px" id="closeQRBtn">❌ بستن</button></div></div></div>

<div class="modal-overlay" id="edit-modal" onclick="if(event.target===this)this.classList.remove('show')"><div class="modal"><button class="modal-close" onclick="$('#edit-modal').classList.remove('show')">✕</button><div class="modal-title" id="editTitle">✏️ ویرایش</div><input type="hidden" id="edit-uid"><div class="form-group"><label class="form-label" id="editNameLabel">نام</label><input class="form-input" id="edit-name" readonly style="opacity:0.6;cursor:not-allowed"></div><div class="form-row"><div class="form-group"><label class="form-label" id="editLimitLabel">محدودیت</label><input class="form-input" id="edit-limit" type="number" min="0" step="0.1" placeholder="۰"></div><div class="form-group" style="min-width:70px;max-width:90px"><label class="form-label" id="editUnitLabel">واحد</label><select class="form-select" id="edit-unit"><option value="GB">GB</option><option value="MB">MB</option></select></div></div><div class="form-group"><label class="form-label" id="editExpiryLabel">انقضا (روز)</label><input class="form-input" id="edit-expiry" type="number" min="0" step="1" placeholder="۰"></div><div style="display:flex;gap:6px;margin-top:8px"><button class="btn btn-primary" onclick="saveEdit()" style="flex:1;justify-content:center;padding:6px" id="saveEditBtn">💾 ذخیره</button><button class="btn btn-danger" onclick="resetEditTraffic()" style="justify-content:center;padding:6px" id="resetTrafficBtn">🔄 بازنشانی</button></div></div></div>

<div class="modal-overlay" id="add-address-modal" onclick="if(event.target===this)this.classList.remove('show')"><div class="modal"><button class="modal-close" onclick="$('#add-address-modal').classList.remove('show')">✕</button><div class="modal-title" id="addAddressTitle">🌐 افزودن آی‌پی</div><div class="form-group"><label class="form-label" id="addressInputLabel">آی‌پی یا دامنه (هر خط یکی)</label><textarea class="form-input" id="new-address" rows="3" placeholder="8.8.8.8&#10;example.com" style="resize:vertical;font-family:monospace;font-size:11px"></textarea></div><button class="btn btn-primary" onclick="addAddresses()" style="width:100%;margin-top:4px;justify-content:center;padding:8px" id="addAllBtn">➕ افزودن همه</button></div></div>

<script>
const TRANSLATIONS = {
  fa: {
    navDashboard: 'داشبورد', navInbounds: 'اینباندها', navTraffic: 'ترافیک', navAddresses: 'آی‌پی تمیز',
    navDomain: 'دامنه', navSecurity: 'امنیت', logoutText: 'خروج',
    dashboardTitle: '📊 DASHBOARD', lastUpdate: '🔄 آخرین بروزرسانی: --',
    sTrafficLabel: 'ترافیک کل', sLinksLabel: 'اینباندها', sUptimeLabel: 'آپتایم', sDomainLabel: 'دامنه',
    resourcesTitle: '⚡ SYSTEM RESOURCES', dlLabel: '📥 DOWNLOAD', ulLabel: '📤 UPLOAD', pingLabel: '📶 PING',
    chartTitle: '📈 TRAFFIC CHART',
    inboundTitle: '📡 INBOUNDS', inboundSub: 'مدیریت اتصالات VLESS', addBtn: '➕ افزودن',
    filterAll: 'همه', filterActive: 'فعال', filterDisabled: 'غیرفعال',
    thName: 'نام', thType: 'نوع', thTraffic: 'ترافیک', thIP: 'IP', thStatus: 'وضعیت', thActions: 'عملیات',
    emptyText: 'هیچ اینباندی یافت نشد',
    trafficTitle: '📊 TRAFFIC', trafficSub: 'آمار و ارقام', overviewTitle: '📋 خلاصه',
    totalTrafficLabel: '📥 کل ترافیک', totalRequestsLabel: '📨 کل درخواست‌ها',
    uptimeLabel2: '⏱️ آپتایم', errorsLabel: '🔴 خطاها', connectionsLabel: '🔗 اتصالات فعال',
    addressTitle: '🌐 CLEAN IP', addressSub: 'مدیریت آی‌پی‌ها', addAddressBtn: '➕ افزودن',
    addressListTitle: '📋 لیست آی‌پی‌ها', defaultAddress: 'پیش‌فرض: www.speedtest.net',
    domainTitle: '🌐 DOMAIN', domainSub: 'جایگزینی دامنه', domainSettings: '⚙️ تنظیمات',
    currentDomainLabel: 'دامنه فعلی', defaultDomainLabel: 'دامنه پیش‌فرض', newDomainLabel: 'دامنه جدید',
    securityTitle: '🔒 SECURITY', securitySub: 'تغییر رمز', changePassTitle: '🔑 تغییر رمز',
    curPassLabel: 'رمز فعلی', newPassLabel: 'رمز جدید', changePassBtn: '🔄 تغییر رمز',
    addModalTitle: '➕ افزودن اینباند', nameLabel: 'نام', limitLabel2: 'محدودیت ترافیک',
    unitLabel: 'واحد', expiryLabel2: 'انقضا (روز)', dlSpeedLabel: 'دانلود (Mbps)',
    ulSpeedLabel: 'آپلود (Mbps)', maxIPLabel: 'حداکثر IP', createBtn: '🚀 ایجاد',
    detailTitle: '📋 جزئیات', qrTitle: '📱 QR Code', downloadQRBtn: '⬇️ دانلود', closeQRBtn: '❌ بستن',
    editTitle: '✏️ ویرایش', editNameLabel: 'نام', editLimitLabel: 'محدودیت', editUnitLabel: 'واحد',
    editExpiryLabel: 'انقضا (روز)', saveEditBtn: '💾 ذخیره', resetTrafficBtn: '🔄 بازنشانی',
    addAddressTitle: '🌐 افزودن آی‌پی', addressInputLabel: 'آی‌پی یا دامنه (هر خط یکی)', addAllBtn: '➕ افزودن همه',
    dash05: '+۰.۵', dash1: '+۱', dash5: '+۵'
  },
  en: {
    navDashboard: 'Dashboard', navInbounds: 'Inbounds', navTraffic: 'Traffic', navAddresses: 'Clean IP',
    navDomain: 'Domain', navSecurity: 'Security', logoutText: 'Logout',
    dashboardTitle: '📊 DASHBOARD', lastUpdate: '🔄 Last update: --',
    sTrafficLabel: 'Total Traffic', sLinksLabel: 'Inbounds', sUptimeLabel: 'Uptime', sDomainLabel: 'Domain',
    resourcesTitle: '⚡ SYSTEM RESOURCES', dlLabel: '📥 DOWNLOAD', ulLabel: '📤 UPLOAD', pingLabel: '📶 PING',
    chartTitle: '📈 TRAFFIC CHART',
    inboundTitle: '📡 INBOUNDS', inboundSub: 'VLESS over WebSocket', addBtn: '➕ Add',
    filterAll: 'All', filterActive: 'Active', filterDisabled: 'Disabled',
    thName: 'Name', thType: 'Type', thTraffic: 'Traffic', thIP: 'IP', thStatus: 'Status', thActions: 'Actions',
    emptyText: 'No inbounds found',
    trafficTitle: '📊 TRAFFIC', trafficSub: 'Statistics', overviewTitle: '📋 Overview',
    totalTrafficLabel: '📥 Total Traffic', totalRequestsLabel: '📨 Total Requests',
    uptimeLabel2: '⏱️ Uptime', errorsLabel: '🔴 Errors', connectionsLabel: '🔗 Active Connections',
    addressTitle: '🌐 CLEAN IP', addressSub: 'Manage IPs', addAddressBtn: '➕ Add',
    addressListTitle: '📋 IP List', defaultAddress: 'Default: www.speedtest.net',
    domainTitle: '🌐 DOMAIN', domainSub: 'Replace domain', domainSettings: '⚙️ Settings',
    currentDomainLabel: 'Current Domain', defaultDomainLabel: 'Default Domain', newDomainLabel: 'New Domain',
    securityTitle: '🔒 SECURITY', securitySub: 'Change password', changePassTitle: '🔑 Change Password',
    curPassLabel: 'Current Password', newPassLabel: 'New Password', changePassBtn: '🔄 Change Password',
    addModalTitle: '➕ Add Inbound', nameLabel: 'Name', limitLabel2: 'Traffic Limit',
    unitLabel: 'Unit', expiryLabel2: 'Expiry (days)', dlSpeedLabel: 'Download (Mbps)',
    ulSpeedLabel: 'Upload (Mbps)', maxIPLabel: 'Max IPs', createBtn: '🚀 Create',
    detailTitle: '📋 Details', qrTitle: '📱 QR Code', downloadQRBtn: '⬇️ Download', closeQRBtn: '❌ Close',
    editTitle: '✏️ Edit', editNameLabel: 'Name', editLimitLabel: 'Limit', editUnitLabel: 'Unit',
    editExpiryLabel: 'Expiry (days)', saveEditBtn: '💾 Save', resetTrafficBtn: '🔄 Reset',
    addAddressTitle: '🌐 Add IP', addressInputLabel: 'IPs or Domains (one per line)', addAllBtn: '➕ Add All',
    dash05: '+0.5', dash1: '+1', dash5: '+5'
  }
};

let lang = localStorage.getItem('vroom_lang') || 'fa';
let theme = localStorage.getItem('vroom_theme') || 'dark';
let allLinks=[]; let currentFilter='all'; let statsData={}; let trafficChart=null;

function applyTranslations(l) {
  const t = TRANSLATIONS[l];
  Object.keys(t).forEach(key => {
    const el = document.getElementById(key);
    if (el) el.textContent = t[key];
  });
  document.documentElement.lang = l;
  document.documentElement.dir = l === 'fa' ? 'rtl' : 'ltr';
  localStorage.setItem('vroom_lang', l);
}

function setLang(l){ lang=l; document.getElementById('lang-fa').classList.toggle('active',l==='fa'); document.getElementById('lang-en').classList.toggle('active',l==='en'); applyTranslations(l); }

function applyTheme(t){theme=t;document.documentElement.setAttribute('data-theme',t);localStorage.setItem('vroom_theme',t);document.getElementById('theme-btn').textContent=t==='dark'?'🌓':'☀️';}
function toggleTheme(){applyTheme(theme==='dark'?'light':'dark')}

applyTheme(theme); setLang(lang);

const $=s=>document.querySelector(s); const $$=s=>document.querySelectorAll(s);
$$('.nav-item').forEach(el=>el.addEventListener('click',()=>switchPage(el.dataset.page)));
function switchPage(id){$$('.page').forEach(p=>p.classList.remove('active'));document.getElementById('page-'+id)?.classList.add('active');$$('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===id));document.getElementById('sidebar').classList.remove('open');document.getElementById('sidebar-overlay').classList.remove('open')}
function toast(msg,err=false){const t=document.getElementById('toast');t.textContent=msg;t.className='toast'+(err?' error':'')+' show';setTimeout(()=>t.classList.remove('show'),3000)}
function esc(s){return String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}

function showAddModal(){document.getElementById('add-modal').classList.add('show')}
function showAddAddressModal(){document.getElementById('new-address').value='';document.getElementById('add-address-modal').classList.add('show')}

function setFilter(f,el){currentFilter=f;document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));el.classList.add('active');filterInbounds()}
function filterInbounds(){const q=(document.getElementById('inbound-search')?.value||'').toLowerCase();let filtered=allLinks;if(currentFilter==='active')filtered=filtered.filter(l=>l.active);if(currentFilter==='disabled')filtered=filtered.filter(l=>!l.active);if(q)filtered=filtered.filter(l=>l.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));renderLinks(filtered)}
function fmtBytes(b){if(b>1073741824)return (b/1073741824).toFixed(2)+' GB';if(b>1048576)return (b/1048576).toFixed(2)+' MB';return (b/1024).toFixed(1)+' KB'}
function fmtLimit(b){if(b===0)return 'نامحدود';const gb=b/1073741824;return (gb%1===0?gb.toFixed(0):gb.toFixed(1))+' GB'}

function updateCircle(id, percent, color){const canvas=document.getElementById(id);if(!canvas)return;const ctx=canvas.getContext('2d');const w=canvas.width,h=canvas.height;const cx=w/2,cy=h/2,r=Math.min(w,h)/2-5,start=-Math.PI/2,end=start+(percent/100)*2*Math.PI;ctx.clearRect(0,0,w,h);ctx.beginPath();ctx.arc(cx,cy,r,0,2*Math.PI);ctx.strokeStyle='rgba(255,255,255,0.06)';ctx.lineWidth=4;ctx.stroke();ctx.beginPath();ctx.arc(cx,cy,r,start,end);ctx.strokeStyle=color;ctx.lineWidth=4;ctx.lineCap='round';ctx.shadowColor=color;ctx.shadowBlur=12;ctx.stroke();ctx.shadowBlur=0}

async function loadStats(){try{const r=await fetch('/stats');if(!r.ok)throw new Error();statsData=await r.json();document.getElementById('s-traffic').innerHTML=statsData.total_traffic_mb+'<span class="stat-unit">MB</span>';document.getElementById('s-links').textContent=statsData.links_count;document.getElementById('s-uptime').textContent=statsData.uptime;document.getElementById('s-domain').textContent=statsData.domain;document.getElementById('links-badge').textContent=statsData.links_count;document.getElementById('last-update').textContent='🔄 '+(lang==='fa'?'آخرین بروزرسانی: ':'Last update: ')+new Date().toLocaleTimeString(lang==='fa'?'fa-IR':'en-US');document.getElementById('t-traffic').textContent=statsData.total_traffic_mb+' MB';document.getElementById('t-reqs').textContent=statsData.total_requests.toLocaleString(lang==='fa'?'fa-IR':'en-US');document.getElementById('t-uptime').textContent=statsData.uptime;document.getElementById('t-errors').textContent=statsData.total_errors;document.getElementById('t-connections').textContent=statsData.active_connections;document.getElementById('quickConnections').textContent=statsData.active_connections;document.getElementById('s-connections').textContent=statsData.active_connections;if(statsData.cpu_percent!==undefined){updateCircle('cpuCanvas', statsData.cpu_percent, '#7c5cfc');document.getElementById('s-cpu-val').textContent=statsData.cpu_percent.toFixed(1)+'%';}if(statsData.memory_percent!==undefined){updateCircle('memCanvas', statsData.memory_percent, '#34d399');document.getElementById('s-mem-val').textContent=statsData.memory_percent.toFixed(1)+'%';const memUsed=statsData.memory_percent;const memTotal=8;document.getElementById('s-mem-detail').textContent=((memTotal*memUsed)/100).toFixed(2)+' / '+memTotal+' GB';}if(statsData.disk_percent!==undefined){document.getElementById('s-disk-used').textContent=statsData.disk_percent.toFixed(1)+'%';document.getElementById('s-disk-total').textContent=statsData.disk_used+' / '+statsData.disk_total+' GB';}updateSpeed();updateChart();loadDomain();}catch(e){}}

function updateSpeed(){const s=Math.random()*80+20;document.getElementById('dl-speed').textContent=Math.round(s);document.getElementById('ul-speed').textContent=Math.round(s*0.6);document.getElementById('ping-speed').textContent=Math.round(Math.random()*20+5);}

async function loadLinks(){try{const r=await fetch('/api/links');if(!r.ok)throw new Error();const d=await r.json();allLinks=d.links||[];filterInbounds();}catch(e){}}

function renderLinks(links){const tbody=document.getElementById('links-tbody');const empty=document.getElementById('links-empty');const cards=document.getElementById('inbound-cards');if(!links.length){tbody.innerHTML='';cards.innerHTML='';empty.style.display='block';return;}empty.style.display='none';let idx=links.length;const rows=links.map(l=>{const u=l.used_bytes,lim=l.limit_bytes;const uF=fmtBytes(u);const lF=fmtLimit(lim);const pct=lim>0?Math.min(100,(u/lim)*100):0;const col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';const i=idx--;return {l,uF,lF,pct,col,i,maxConn:l.max_connections||0,curConn:l.current_connections||0};});tbody.innerHTML=rows.map(r=>`<tr><td style="color:var(--text3);font-size:9px">${r.i}</td><td style="font-weight:600;font-size:11px">${esc(r.l.label)}</td><td><span class="tag tag-vless">VLESS</span></td><td><div class="usage-pill"><span class="used">${r.uF}</span><div class="bar"><div class="fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="limit">${r.lF}</span></div></td><td style="font-size:10px;font-weight:600;color:${r.maxConn>0&&r.curConn>=r.maxConn?'var(--red)':'var(--text2)'}">${r.curConn}/${r.maxConn||'∞'}</td><td><span class="tag ${r.l.active?'tag-active':'tag-disabled'}">${r.l.active?'فعال':'غیرفعال'}</span></td><td><div style="display:flex;gap:2px;align-items:center;flex-wrap:wrap"><button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)" title="تغییر وضعیت"></button><button class="btn btn-secondary btn-sm" onclick="showEditModal('${r.l.uuid}')" title="ویرایش" style="background:rgba(251,191,36,0.1);color:var(--yellow);border:1px solid rgba(251,191,36,0.2)">✎</button><button class="btn-copy" onclick="copyLinkText('${esc(r.l.vless_link)}')" title="کپی">📋</button><button class="btn-copy" onclick="copySubLink('${r.l.uuid}')" title="ساب" style="background:var(--green-dim);color:var(--green);border:1px solid rgba(52,211,153,0.15)">📥</button><button class="btn-qr" onclick="showQRText('${esc(r.l.vless_link)}')" title="QR">📱</button><button class="btn btn-danger btn-sm" onclick="deleteLink('${r.l.uuid}')" title="حذف">🗑</button></div></td></tr>`).join('');cards.innerHTML=rows.map(r=>`<div class="inbound-card"><div class="inbound-card-header"><div style="display:flex;align-items:center;gap:4px"><span class="inbound-card-id">#${r.i}</span><span class="inbound-card-name">${esc(r.l.label)}</span><span class="tag tag-vless">VLESS</span></div><button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)"></button></div><div class="usage-pill"><span class="used">${r.uF}</span><div class="bar"><div class="fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="limit">${r.lF}</span></div><div style="display:flex;align-items:center;gap:4px;font-size:9px;color:var(--text2)"><span style="font-weight:600;color:${r.maxConn>0&&r.curConn>=r.maxConn?'var(--red)':'var(--text)'}">${r.curConn}/${r.maxConn||'∞'}</span> <span>IP</span></div><div class="inbound-card-actions"><button class="btn btn-secondary btn-sm" onclick="showEditModal('${r.l.uuid}')" style="background:rgba(251,191,36,0.1);color:var(--yellow);border:1px solid rgba(251,191,36,0.2)">✎</button><button class="btn-copy" onclick="copyLinkText('${esc(r.l.vless_link)}')">📋</button><button class="btn-copy" onclick="copySubLink('${r.l.uuid}')" style="background:var(--green-dim);color:var(--green);border:1px solid rgba(52,211,153,0.15)">📥</button><button class="btn-qr" onclick="showQRText('${esc(r.l.vless_link)}')">📱</button><button class="btn btn-danger btn-sm" onclick="deleteLink('${r.l.uuid}')">🗑</button></div></div>`).join('');}

async function toggleLink(el){const uid=el.dataset.uid;const link=allLinks.find(l=>l.uuid===uid);if(!link)return;const newActive=!link.active;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:newActive})});link.active=newActive;filterInbounds();loadStats();}catch(e){}}

async function quickCreate(limit,unit){const names=['علی','سارا','رضا','نیما','مینا'];const name=names[Math.floor(Math.random()*names.length)]+'-'+Math.floor(Math.random()*100);try{const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:name,limit_value:limit,limit_unit:unit})});if(!r.ok)throw new Error();toast('✅ '+name+' ساخته شد');await loadLinks();await loadStats();}catch(e){toast('❌ خطا',true)}}

async function createLink(){const label=document.getElementById('new-label').value.trim()||'لینک جدید';const val=parseFloat(document.getElementById('new-limit').value)||0;const unit=document.getElementById('new-unit').value;const maxconn=parseInt(document.getElementById('new-maxconn').value)||0;const expiry=parseInt(document.getElementById('new-expiry').value)||0;if(!/^[a-zA-Z0-9\-_. ]+$/.test(label)){toast('❌ فقط حروف انگلیسی',true);return;}try{const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,limit_value:val,limit_unit:unit,max_connections:maxconn,expiry_days:expiry})});if(!r.ok)throw new Error();toast('✅ ساخته شد');document.getElementById('new-label').value='';document.getElementById('new-limit').value='';document.getElementById('new-maxconn').value='';document.getElementById('new-expiry').value='';document.getElementById('add-modal').classList.remove('show');await loadLinks();await loadStats();}catch(e){toast('❌ خطا',true)}}

async function deleteLink(uid){if(!confirm('❓ حذف؟'))return;try{await fetch('/api/links/'+uid,{method:'DELETE'});toast('✅ حذف شد');await loadLinks();await loadStats();}catch(e){}}

function showEditModal(uid){const l=allLinks.find(x=>x.uuid===uid);if(!l)return;document.getElementById('edit-uid').value=uid;document.getElementById('edit-name').value=l.label;const gb=l.limit_bytes/1073741824;document.getElementById('edit-limit').value=l.limit_bytes>0?gb:'';document.getElementById('edit-unit').value='GB';document.getElementById('edit-maxconn').value=l.max_connections>0?l.max_connections:'';document.getElementById('edit-title').textContent='✏️ ویرایش: '+l.label;document.getElementById('edit-modal').classList.add('show');}

async function saveEdit(){const uid=document.getElementById('edit-uid').value;const val=parseFloat(document.getElementById('edit-limit').value)||0;const unit=document.getElementById('edit-unit').value;const maxconn=parseInt(document.getElementById('edit-maxconn').value)||0;const expiry=parseInt(document.getElementById('edit-expiry').value)||0;try{const r=await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({limit_value:val,limit_unit:unit,max_connections:maxconn,expiry_days:expiry})});if(!r.ok)throw new Error();toast('✅ بروزرسانی');document.getElementById('edit-modal').classList.remove('show');await loadLinks();}catch(e){toast('❌ خطا',true)}}

async function resetEditTraffic(){const uid=document.getElementById('edit-uid').value;if(!confirm('❓ بازنشانی ترافیک؟'))return;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});toast('✅ بازنشانی');await loadLinks();}catch(e){}}

function copyLinkText(txt){navigator.clipboard.writeText(txt).then(()=>toast('📋 کپی شد')).catch(()=>toast('❌ خطا',true))}
function showQRText(txt){if(!txt)return;document.getElementById('qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=300x300&data='+encodeURIComponent(txt);document.getElementById('qr-modal').classList.add('show');}
function downloadQR(){const img=document.getElementById('qr-img');if(!img.src)return;const a=document.createElement('a');a.href=img.src;a.download='vroom-qr.png';a.click()}
async function copySubLink(uid){try{const domain=location.host;await navigator.clipboard.writeText('https://'+domain+'/sub/'+uid);toast('📥 ساب کپی شد');}catch(e){toast('❌ خطا',true)}}

async function changePassword(){const cur=document.getElementById('cur-pw').value;const nw=document.getElementById('new-pw').value;if(!cur||!nw){toast('❌ همه فیلدها',true);return;}try{const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'خطا');}toast('✅ رمز تغییر کرد');document.getElementById('cur-pw').value='';document.getElementById('new-pw').value='';}catch(e){toast('❌ '+e.message,true)}}

let allAddresses=[];async function loadAddresses(){try{const r=await fetch('/api/addresses');if(!r.ok)throw new Error();const d=await r.json();allAddresses=d.addresses||[];renderAddresses();}catch(e){}}
function renderAddresses(){const list=document.getElementById('address-list');if(!list)return;if(!allAddresses.length){list.innerHTML='<div style="color:var(--text3);font-size:11px;padding:4px 0;text-align:center">هیچ آی‌پی اضافه نشده</div>';return;}list.innerHTML=allAddresses.map((a,i)=>`<div style="display:flex;align-items:center;justify-content:space-between;padding:6px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:6px"><div style="display:flex;align-items:center;gap:8px"><span style="font-size:14px">🌐</span><div><div style="font-size:12px;font-weight:600;color:var(--text)">${esc(a)}</div><div style="font-size:8px;color:var(--text3)">#${i+1}</div></div></div><button class="btn btn-danger btn-sm" onclick="deleteAddress(${i})" style="padding:2px 8px">🗑</button></div>`).join('');}
async function addAddresses(){const text=document.getElementById('new-address').value.trim();if(!text){toast('❌ وارد کنید',true);return;}const lines=text.split('\n').map(l=>l.trim()).filter(l=>l);let added=0;for(const addr of lines){if(!/^[a-zA-Z0-9\-_. ]+$/.test(addr))continue;try{const r=await fetch('/api/addresses',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:addr})});if(r.ok)added++;}catch(e){}}if(added>0){toast('✅ '+added+' آدرس افزوده شد');document.getElementById('add-address-modal').classList.remove('show');await loadAddresses();}else{toast('❌ خطا',true)}}
async function deleteAddress(index){if(!confirm('❓ حذف؟'))return;try{await fetch('/api/addresses/'+index,{method:'DELETE'});toast('✅ حذف شد');await loadAddresses();}catch(e){toast('❌ خطا',true)}}

let currentDomain='';async function loadDomain(){try{const r=await fetch('/api/domain');if(!r.ok)throw new Error();const d=await r.json();currentDomain=d.domain||'';const renderDomain=statsData.domain||location.host;document.getElementById('render-domain').textContent=renderDomain;if(currentDomain){document.getElementById('domain-value').textContent=currentDomain;document.getElementById('domain-value').style.color='var(--green)';document.getElementById('domain-clear-btn').style.display='block';}else{document.getElementById('domain-value').textContent=renderDomain+' (پیش‌فرض)';document.getElementById('domain-value').style.color='var(--text2)';document.getElementById('domain-clear-btn').style.display='none';}}catch(e){}}
async function saveDomain(){const domain=document.getElementById('domain-input').value.trim();if(!domain){toast('❌ دامنه وارد کنید',true);return;}try{const r=await fetch('/api/domain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain})});if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'خطا');}toast('✅ ذخیره شد');document.getElementById('domain-input').value='';await loadDomain();await loadLinks();}catch(e){toast('❌ '+e.message,true)}}
async function clearDomain(){try{await fetch('/api/domain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:''})});toast('✅ پاک شد');await loadDomain();await loadLinks();}catch(e){toast('❌ خطا',true)}}

function initChart(){const ctx=document.getElementById('trafficChart');if(!ctx)return;trafficChart=new Chart(ctx,{type:'bar',data:{labels:[],datasets:[{label:'MB',data:[],backgroundColor:'rgba(124,92,252,0.6)',borderColor:'#7c5cfc',borderWidth:2,borderRadius:6}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:'rgba(255,255,255,0.3)',font:{size:7}}},y:{grid:{color:'rgba(255,255,255,0.05)'},ticks:{color:'rgba(255,255,255,0.3)',font:{size:7},callback:v=>v+' MB'},beginAtZero:true}}}});}
initChart();
function updateChart(){if(!trafficChart||!statsData.hourly_traffic)return;const ht=statsData.hourly_traffic;const sorted=Object.entries(ht).sort((a,b)=>a[0].localeCompare(b[0])).slice(-12);trafficChart.data.labels=sorted.map(e=>e[0]);trafficChart.data.datasets[0].data=sorted.map(e=>Math.round(e[1]/1048576));trafficChart.update();}

loadStats();loadLinks();loadAddresses();loadDomain();
setInterval(()=>{loadStats();updateSpeed()},5000);
</script>
</body>
</html>"""


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
