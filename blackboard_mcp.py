"""
Blackboard MCP Server (FastMCP 3.x) - Session-scoped OAuth with Upstash Redis

Flow:
- Tool called -> uses ctx.session_id (sid)
- If no token for sid -> returns login URL: {SERVER_URL}/login?sid=<sid>
- /login starts OAuth -> stores pending state -> redirects to Blackboard authorize endpoint
- /oauth/callback exchanges code for token -> stores token under bb:session:<sid>
- Subsequent tool calls reuse token

Env:
  BLACKBOARD_URL=https://<bb-host>              (no trailing slash)
  BLACKBOARD_APP_KEY=<client_id>
  BLACKBOARD_APP_SECRET=<client_secret>
  SERVER_URL=https://<your-fastmcp-host>        (no trailing slash)
  UPSTASH_REDIS_REST_URL=...
  UPSTASH_REDIS_REST_TOKEN=...

Optional:
  OAUTH_REDIRECT_PATH=oauth/callback   (default). Set to "" if Blackboard only allows host-level redirect_uri.
"""

import os
import base64
import secrets
import time
import logging
import json
import httpx
from urllib.parse import quote

from fastmcp import FastMCP
from fastmcp.dependencies import CurrentContext
from fastmcp.server.context import Context
from starlette.responses import RedirectResponse, JSONResponse
from upstash_redis import Redis

# =============================================================================
# LOGGING
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("blackboard-mcp")

# =============================================================================
# CONFIG
# =============================================================================
BLACKBOARD_URL = (os.environ.get("BLACKBOARD_URL") or "").rstrip("/")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY") or ""
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET") or ""
SERVER_URL = (os.environ.get("SERVER_URL") or "").rstrip("/")

UPSTASH_REDIS_REST_URL = os.environ.get("UPSTASH_REDIS_REST_URL")
UPSTASH_REDIS_REST_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN")

# If Blackboard doesn't accept full-path redirect URIs, set this to "" (empty).
OAUTH_REDIRECT_PATH = (os.environ.get("OAUTH_REDIRECT_PATH") or "oauth/callback").strip("/")

TOKEN_EXPIRY = 3600
PENDING_EXPIRY = 600

# Redis keys
PREFIX_SESSION = "bb:session:"       # bb:session:<sid> -> token record
PREFIX_PENDING = "bb:pending:"       # bb:pending:<state> -> {sid, redirect_uri, ts}
PREFIX_COMPLETED = "bb:completed:"   # optional guard against double-callback

REDIRECT_URI = f"{SERVER_URL}/{OAUTH_REDIRECT_PATH}" if OAUTH_REDIRECT_PATH else SERVER_URL


def _require_env():
    missing = []
    if not BLACKBOARD_URL:
        missing.append("BLACKBOARD_URL")
    if not BLACKBOARD_APP_KEY:
        missing.append("BLACKBOARD_APP_KEY")
    if not BLACKBOARD_APP_SECRET:
        missing.append("BLACKBOARD_APP_SECRET")
    if not SERVER_URL:
        missing.append("SERVER_URL")
    if not UPSTASH_REDIS_REST_URL:
        missing.append("UPSTASH_REDIS_REST_URL")
    if not UPSTASH_REDIS_REST_TOKEN:
        missing.append("UPSTASH_REDIS_REST_TOKEN")
    if missing:
        raise RuntimeError("Missing required env vars: " + ", ".join(missing))


def _to_str(v):
    if v is None:
        return None
    if isinstance(v, bytes):
        return v.decode("utf-8")
    return v


def get_redis() -> Redis:
    _require_env()
    return Redis(url=UPSTASH_REDIS_REST_URL, token=UPSTASH_REDIS_REST_TOKEN)


# =============================================================================
# Redis helpers
# =============================================================================
def store_session_token(sid: str, token_data: dict) -> bool:
    try:
        r = get_redis()
        r.setex(f"{PREFIX_SESSION}{sid}", TOKEN_EXPIRY, json.dumps(token_data))
        logger.info(f"Redis: stored token for sid={sid[:8]}…")
        return True
    except Exception as e:
        logger.error(f"Redis: failed to store session token: {e}")
        return False


def get_session_token(sid: str) -> dict | None:
    try:
        r = get_redis()
        data = r.get(f"{PREFIX_SESSION}{sid}")
        data = _to_str(data)
        return json.loads(data) if data else None
    except Exception as e:
        logger.error(f"Redis: failed to get session token: {e}")
        return None


def delete_session_token(sid: str):
    try:
        r = get_redis()
        r.delete(f"{PREFIX_SESSION}{sid}")
    except Exception as e:
        logger.error(f"Redis: failed to delete session token: {e}")


def store_pending(state: str, auth_data: dict) -> bool:
    try:
        r = get_redis()
        r.setex(f"{PREFIX_PENDING}{state}", PENDING_EXPIRY, json.dumps(auth_data))
        return True
    except Exception as e:
        logger.error(f"Redis: failed to store pending: {e}")
        return False


def get_pending(state: str) -> dict | None:
    try:
        r = get_redis()
        data = r.get(f"{PREFIX_PENDING}{state}")
        data = _to_str(data)
        return json.loads(data) if data else None
    except Exception as e:
        logger.error(f"Redis: failed to get pending: {e}")
        return None


def delete_pending(state: str):
    try:
        r = get_redis()
        r.delete(f"{PREFIX_PENDING}{state}")
    except Exception as e:
        logger.error(f"Redis: failed to delete pending: {e}")


def store_completed(state: str, data: dict) -> bool:
    try:
        r = get_redis()
        r.setex(f"{PREFIX_COMPLETED}{state}", PENDING_EXPIRY, json.dumps(data))
        return True
    except Exception as e:
        logger.error(f"Redis: failed to store completed: {e}")
        return False


def get_completed(state: str) -> dict | None:
    try:
        r = get_redis()
        data = r.get(f"{PREFIX_COMPLETED}{state}")
        data = _to_str(data)
        return json.loads(data) if data else None
    except Exception as e:
        logger.error(f"Redis: failed to get completed: {e}")
        return None


# =============================================================================
# Auth helpers
# =============================================================================
def auth_link_for_sid(sid: str) -> str:
    url = f"{SERVER_URL}/login?sid={sid}"
    return (
        "🔐 Authentication Required\n\n"
        f"Open this link in your browser:\n{url}\n\n"
        "After you see the success message, come back to Claude and run the tool again."
    )


# =============================================================================
# MCP server
# =============================================================================
mcp = FastMCP("Blackboard")


# =============================================================================
# Routes
# =============================================================================

# If Blackboard only supports host-level redirect_uri, it may redirect to:
#   https://your-host/?code=...&state=...
# This route makes that work by delegating to the same callback handler.
@mcp.custom_route("/", methods=["GET"])
async def root(request):
    if request.query_params.get("code") and request.query_params.get("state"):
        return await oauth_callback(request)
    return JSONResponse({"status": "ok"})


@mcp.custom_route("/login", methods=["GET"])
async def login_page(request):
    sid = request.query_params.get("sid")
    if not sid:
        return JSONResponse(
            {"error": "missing_sid", "message": "Open /login from Claude so it includes ?sid=<mcp session id>."},
            status_code=400,
        )

    state = secrets.token_urlsafe(32)
    store_pending(state, {
        "sid": sid,
        "redirect_uri": REDIRECT_URI,
        "timestamp": time.time(),
    })

    bb_auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?redirect_uri={quote(REDIRECT_URI, safe='')}"
        f"&response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&scope=read%20write"
        f"&state={state}"
    )

    logger.info(f"Login: sid={sid[:8]}… redirect_uri={REDIRECT_URI}")
    return RedirectResponse(bb_auth_url)


@mcp.custom_route("/login/success", methods=["GET"])
async def login_success(request):
    return JSONResponse({
        "status": "success",
        "message": "✅ Login successful! Close this window and return to Claude."
    })


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request):
    logger.info(f"OAuth: callback request.url={request.url}")
    logger.info(f"OAuth: expected redirect_uri={REDIRECT_URI}")

    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")

    if error:
        return JSONResponse(
            {
                "error": error,
                "error_description": request.query_params.get("error_description"),
            },
            status_code=400,
        )

    if not code or not state:
        return JSONResponse({"error": "missing_parameters"}, status_code=400)

    # Guard duplicate callback
    if get_completed(state):
        return RedirectResponse(f"{SERVER_URL}/login/success")

    pending = get_pending(state)
    if not pending:
        return JSONResponse({"error": "invalid_state"}, status_code=400)

    sid = pending.get("sid")
    redirect_uri = pending.get("redirect_uri") or REDIRECT_URI
    if not sid:
        return JSONResponse({"error": "pending_missing_sid"}, status_code=400)

    try:
        creds = f"{BLACKBOARD_APP_KEY}:{BLACKBOARD_APP_SECRET}"
        auth_header = base64.b64encode(creds.encode()).decode()

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/token",
                headers={
                    "Authorization": f"Basic {auth_header}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,  # must match authorize step
                },
            )

        if resp.status_code != 200:
            logger.error(f"OAuth: token exchange failed ({resp.status_code}): {resp.text}")
            return JSONResponse(
                {"error": "token_exchange_failed", "status_code": resp.status_code, "details": resp.text},
                status_code=500,
            )

        bb_token = resp.json()

        token_record = {
            "access_token": bb_token["access_token"],
            "token_type": bb_token.get("token_type", "bearer"),
            "expires_in": bb_token.get("expires_in", 3600),
            "refresh_token": bb_token.get("refresh_token"),
            "user_id": bb_token.get("user_id", "unknown"),
            "timestamp": time.time(),
        }

        if not store_session_token(sid, token_record):
            return JSONResponse({"error": "redis_store_failed"}, status_code=500)

        store_completed(state, {"user_id": token_record["user_id"]})
        delete_pending(state)

        logger.info(f"OAuth: ✅ stored token for sid={sid[:8]}… user_id={token_record['user_id']}")
        return RedirectResponse(f"{SERVER_URL}/login/success")

    except Exception as e:
        logger.exception("OAuth: exception during callback")
        return JSONResponse({"error": str(e)}, status_code=500)


# =============================================================================
# Tools (session-scoped)
# =============================================================================
@mcp.tool()
async def check_auth_status(ctx: Context = CurrentContext()) -> str:
    sid = ctx.session_id
    token_data = get_session_token(sid)
    if not token_data:
        return "🔒 Not Authenticated\n\n" + auth_link_for_sid(sid)

    return (
        "✅ Authenticated\n\n"
        f"• User ID: `{token_data.get('user_id')}`\n"
        f"• Expires in: ~{token_data.get('expires_in', 3600)//60} minutes\n"
        f"• Session: `{sid}`"
    )


@mcp.tool()
async def get_current_user(ctx: Context = CurrentContext()) -> str:
    sid = ctx.session_id
    token_data = get_session_token(sid)
    if not token_data:
        return auth_link_for_sid(sid)

    token = token_data["access_token"]

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(
            f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
            headers={"Authorization": f"Bearer {token}"},
        )

    if resp.status_code == 401:
        delete_session_token(sid)
        return "⚠️ Session expired.\n\n" + auth_link_for_sid(sid)

    if resp.status_code != 200:
        return f"Error: {resp.status_code} - {resp.text}"

    user = resp.json()
    name = user.get("name", {}) or {}

    out = "👤 Current User\n\n"
    out += f"• User ID: `{user.get('id')}`\n"
    out += f"• Username: `{user.get('userName')}`\n"
    if name.get("given") or name.get("family"):
        out += f"• Name: {name.get('given','')} {name.get('family','')}\n"
    email = (user.get("contact", {}) or {}).get("email")
    if email:
        out += f"• Email: {email}\n"
    return out


@mcp.tool()
async def get_my_courses(ctx: Context = CurrentContext()) -> str:
    sid = ctx.session_id
    token_data = get_session_token(sid)
    if not token_data:
        return auth_link_for_sid(sid)

    token = token_data["access_token"]

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(
            f"{BLACKBOARD_URL}/learn/api/public/v1/courses?limit=100",
            headers={"Authorization": f"Bearer {token}"},
        )

    if resp.status_code == 401:
        delete_session_token(sid)
        return "⚠️ Session expired.\n\n" + auth_link_for_sid(sid)

    if resp.status_code != 200:
        return f"Error: {resp.status_code} - {resp.text}"

    courses = resp.json().get("results", []) or []
    if not courses:
        return "No courses found."

    out = f"📚 Found {len(courses)} courses:\n\n"
    for c in courses:
        out += f"• **{c.get('name','Unnamed')}** (ID: `{c.get('id')}`)\n"
    return out


@mcp.tool()
async def get_course_assignments(course_id: str, ctx: Context = CurrentContext()) -> str:
    sid = ctx.session_id
    token_data = get_session_token(sid)
    if not token_data:
        return auth_link_for_sid(sid)

    token = token_data["access_token"]

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(
            f"{BLACKBOARD_URL}/learn/api/public/v1/courses/{course_id}/gradebook/columns",
            headers={"Authorization": f"Bearer {token}"},
        )

    if resp.status_code == 401:
        delete_session_token(sid)
        return "⚠️ Session expired.\n\n" + auth_link_for_sid(sid)

    if resp.status_code != 200:
        return f"Error: {resp.status_code} - {resp.text}"

    cols = resp.json().get("results", []) or []
    assignments = [c for c in cols if c.get("grading", {}).get("due")]

    if not assignments:
        return f"No assignments with due dates in course `{course_id}`"

    out = f"📝 Found {len(assignments)} assignments:\n\n"
    for a in assignments:
        out += (
            f"• **{a.get('name')}** "
            f"({a.get('score', {}).get('possible', '?')} pts) - "
            f"Due: {a.get('grading', {}).get('due')}\n"
        )
    return out


@mcp.tool()
async def logout(ctx: Context = CurrentContext()) -> str:
    delete_session_token(ctx.session_id)
    return "✅ Logged out for this Claude session."
  
@mcp.custom_route("/debug/session", methods=["GET"])
async def debug_session_http(request):
    sid = request.query_params.get("sid")
    if not sid:
        return JSONResponse({"error": "missing_sid"}, status_code=400)

    token_data = get_session_token(sid)

    return JSONResponse({
        "sid": sid,
        "has_token": bool(token_data),
        "user_id": token_data.get("user_id") if token_data else None,
        "redirect_uri": REDIRECT_URI,
    })


@mcp.tool()
async def debug_session(ctx: Context = CurrentContext()) -> str:
    sid = ctx.session_id
    out = "🔧 Debug Info\n\n"
    out += f"• Transport: `{ctx.transport}`\n"
    out += f"• Session ID: `{sid}`\n"
    out += f"• Redirect URI: `{REDIRECT_URI}`\n\n"

    try:
        r = get_redis()
        r.ping()
        out += "• Redis: ✅ Connected\n"
        token_data = get_session_token(sid)
        out += f"• Has token for this session: {'✅' if token_data else '❌'}\n"
        if token_data:
            out += f"• User ID: `{token_data.get('user_id')}`\n"
    except Exception as e:
        out += f"• Redis: ❌ {e}\n"
    return out
