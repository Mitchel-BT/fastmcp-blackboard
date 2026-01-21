"""
Blackboard MCP Server - Single-user auth (Upstash Redis)
- OAuth auth code flow
- Stores one "current" token in Redis (no per-session identity)
- Works even when MCP session_id changes every request (streamable-http)

Env vars required:
  BLACKBOARD_URL               e.g. https://anthropic.bt-retool.shop
  BLACKBOARD_APP_KEY           client_id
  BLACKBOARD_APP_SECRET        client_secret
  SERVER_URL                   e.g. https://your-fastmcp-cloud-host
  UPSTASH_REDIS_REST_URL
  UPSTASH_REDIS_REST_TOKEN

Optional:
  OAUTH_REDIRECT_PATH          default: "oauth/callback"
                               set to "" if Blackboard only allows host-level redirect_uri
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

# If Blackboard only supports host-level redirect_uri, set this to "" (empty)
OAUTH_REDIRECT_PATH = (os.environ.get("OAUTH_REDIRECT_PATH") or "oauth/callback").strip("/")
REDIRECT_URI = f"{SERVER_URL}/{OAUTH_REDIRECT_PATH}" if OAUTH_REDIRECT_PATH else SERVER_URL

# Expiries
DEFAULT_TOKEN_EXPIRY = 3600  # fallback if expires_in missing
PENDING_EXPIRY = 600

# Redis keys
KEY_CURRENT_TOKEN = "bb:token:current"
PREFIX_PENDING = "bb:pending:"
PREFIX_COMPLETED = "bb:completed:"


def _require_env():
    missing = []
    for k, v in [
        ("BLACKBOARD_URL", BLACKBOARD_URL),
        ("BLACKBOARD_APP_KEY", BLACKBOARD_APP_KEY),
        ("BLACKBOARD_APP_SECRET", BLACKBOARD_APP_SECRET),
        ("SERVER_URL", SERVER_URL),
        ("UPSTASH_REDIS_REST_URL", UPSTASH_REDIS_REST_URL),
        ("UPSTASH_REDIS_REST_TOKEN", UPSTASH_REDIS_REST_TOKEN),
    ]:
        if not v:
            missing.append(k)
    if missing:
        raise RuntimeError("Missing env vars: " + ", ".join(missing))


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
# REDIS HELPERS (single-user)
# =============================================================================
def store_current_token(token_data: dict) -> bool:
    """Store the single current token record."""
    try:
        expires_in = int(token_data.get("expires_in") or DEFAULT_TOKEN_EXPIRY)
        ttl = max(60, min(expires_in, 24 * 3600))  # keep sane bounds
        r = get_redis()
        r.setex(KEY_CURRENT_TOKEN, ttl, json.dumps(token_data))
        logger.info("Redis: stored current token")
        return True
    except Exception as e:
        logger.error(f"Redis: failed to store current token: {e}")
        return False


def get_current_token() -> dict | None:
    """Get the single current token record."""
    try:
        r = get_redis()
        data = _to_str(r.get(KEY_CURRENT_TOKEN))
        return json.loads(data) if data else None
    except Exception as e:
        logger.error(f"Redis: failed to get current token: {e}")
        return None


def delete_current_token():
    """Delete the single current token record."""
    try:
        r = get_redis()
        r.delete(KEY_CURRENT_TOKEN)
    except Exception as e:
        logger.error(f"Redis: failed to delete current token: {e}")


def store_pending(state: str, auth_data: dict) -> bool:
    """Store pending OAuth flow info."""
    try:
        r = get_redis()
        r.setex(f"{PREFIX_PENDING}{state}", PENDING_EXPIRY, json.dumps(auth_data))
        return True
    except Exception as e:
        logger.error(f"Redis: failed to store pending: {e}")
        return False


def get_pending(state: str) -> dict | None:
    """Get pending OAuth flow info."""
    try:
        r = get_redis()
        data = _to_str(r.get(f"{PREFIX_PENDING}{state}"))
        return json.loads(data) if data else None
    except Exception as e:
        logger.error(f"Redis: failed to get pending: {e}")
        return None


def delete_pending(state: str):
    """Delete pending OAuth flow info."""
    try:
        r = get_redis()
        r.delete(f"{PREFIX_PENDING}{state}")
    except Exception as e:
        logger.error(f"Redis: failed to delete pending: {e}")


def store_completed(state: str, data: dict) -> bool:
    """Mark an OAuth state as completed (guards double-callback)."""
    try:
        r = get_redis()
        r.setex(f"{PREFIX_COMPLETED}{state}", PENDING_EXPIRY, json.dumps(data))
        return True
    except Exception as e:
        logger.error(f"Redis: failed to store completed: {e}")
        return False


def get_completed(state: str) -> dict | None:
    """Check if an OAuth state has already completed."""
    try:
        r = get_redis()
        data = _to_str(r.get(f"{PREFIX_COMPLETED}{state}"))
        return json.loads(data) if data else None
    except Exception as e:
        logger.error(f"Redis: failed to get completed: {e}")
        return None


# =============================================================================
# AUTH URL HELPER
# =============================================================================
def get_auth_url() -> str:
    return (
        f"🔐 **Authentication Required**\n\n"
        f"Please log in to Blackboard:\n\n"
        f"👉 [{SERVER_URL}/login]({SERVER_URL}/login)\n\n"
        f"After logging in, return here and try again."
    )


# =============================================================================
# MCP SERVER
# =============================================================================
mcp = FastMCP("Blackboard")


# =============================================================================
# ROUTES
# =============================================================================

# If Blackboard only allows host-level redirect_uri, it may redirect to:
#   https://YOUR_HOST/?code=...&state=...
# This route catches that and forwards to the same callback handler.
@mcp.custom_route("/", methods=["GET"])
async def root(request):
    if request.query_params.get("code") and request.query_params.get("state"):
        return await oauth_callback(request)
    return JSONResponse({"status": "ok"})


@mcp.custom_route("/login", methods=["GET"])
async def login_page(request):
    """Start OAuth flow."""
    logger.info("Login: starting OAuth flow")

    state = secrets.token_urlsafe(32)
    store_pending(state, {
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

    logger.info(f"Login: redirect_uri={REDIRECT_URI}")
    return RedirectResponse(bb_auth_url)


@mcp.custom_route("/login/success", methods=["GET"])
async def login_success(request):
    """Success page after login."""
    return JSONResponse({
        "status": "success",
        "message": "✅ Login successful! Close this window and return to Claude."
    })


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request):
    """OAuth callback from Blackboard."""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")

    logger.info(f"OAuth: callback received url={request.url}")

    if error:
        return JSONResponse({
            "error": error,
            "error_description": request.query_params.get("error_description"),
        }, status_code=400)

    if not code or not state:
        return JSONResponse({"error": "missing_parameters"}, status_code=400)

    # Duplicate callback guard
    if get_completed(state):
        return RedirectResponse(f"{SERVER_URL}/login/success")

    # Validate pending state
    pending = get_pending(state)
    if not pending:
        # If user refreshed and we already have a token, treat as success
        if get_current_token():
            return RedirectResponse(f"{SERVER_URL}/login/success")
        return JSONResponse({"error": "invalid_state"}, status_code=400)

    redirect_uri = pending.get("redirect_uri") or REDIRECT_URI

    # Exchange code for token
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
                    "redirect_uri": redirect_uri,
                }
            )

        if resp.status_code != 200:
            logger.error(f"OAuth: token exchange failed {resp.status_code}: {resp.text}")
            return JSONResponse({
                "error": "token_exchange_failed",
                "status_code": resp.status_code,
                "details": resp.text
            }, status_code=500)

        bb_token = resp.json()
        access_token = bb_token["access_token"]

        expires_in = int(bb_token.get("expires_in", DEFAULT_TOKEN_EXPIRY))
        token_record = {
            "access_token": access_token,
            "token_type": bb_token.get("token_type", "bearer"),
            "expires_in": expires_in,
            "expires_at": time.time() + expires_in,
            "refresh_token": bb_token.get("refresh_token"),
            "user_id": bb_token.get("user_id", "unknown"),
            "timestamp": time.time(),
        }

        if not store_current_token(token_record):
            return JSONResponse({"error": "redis_store_failed"}, status_code=500)

        store_completed(state, {"user_id": token_record.get("user_id")})
        delete_pending(state)

        logger.info(f"OAuth: ✅ stored current token for user_id={token_record.get('user_id')}")
        return RedirectResponse(f"{SERVER_URL}/login/success")

    except Exception as e:
        logger.exception("OAuth: exception during callback")
        return JSONResponse({"error": str(e)}, status_code=500)


# =============================================================================
# MCP TOOLS
# =============================================================================
@mcp.tool()
async def check_auth_status() -> str:
    """Check authentication status (single-user)."""
    token_data = get_current_token()
    if not token_data:
        return "🔒 **Not Authenticated**\n\n" + get_auth_url()

    remaining = int(max(0, token_data.get("expires_at", time.time()) - time.time()))
    return (
        f"✅ **Authenticated**\n\n"
        f"• **User ID:** `{token_data.get('user_id')}`\n"
        f"• **Expires in:** ~{remaining // 60} minutes"
    )


@mcp.tool()
async def get_current_user() -> str:
    """Get current authenticated Blackboard user info."""
    token_data = get_current_token()
    if not token_data:
        return get_auth_url()

    token = token_data["access_token"]

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
                headers={"Authorization": f"Bearer {token}"},
            )

        if resp.status_code == 401:
            delete_current_token()
            return "⚠️ Session expired.\n\n" + get_auth_url()

        if resp.status_code != 200:
            return f"Error: {resp.status_code} - {resp.text}"

        user = resp.json()
        name = user.get("name", {}) or {}

        result = "👤 **Current User**\n\n"
        result += f"• **User ID:** `{user.get('id')}`\n"
        result += f"• **Username:** `{user.get('userName')}`\n"
        if name.get("given") or name.get("family"):
            result += f"• **Name:** {name.get('given','')} {name.get('family','')}\n"
        email = (user.get("contact", {}) or {}).get("email")
        if email:
            result += f"• **Email:** {email}\n"
        return result

    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def get_my_courses() -> str:
    """Get all courses you have access to in Blackboard."""
    token_data = get_current_token()
    if not token_data:
        return get_auth_url()

    token = token_data["access_token"]

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses?limit=100",
                headers={"Authorization": f"Bearer {token}"},
            )

        if resp.status_code == 401:
            delete_current_token()
            return "⚠️ Session expired.\n\n" + get_auth_url()

        if resp.status_code != 200:
            return f"Error: {resp.status_code} - {resp.text}"

        courses = (resp.json() or {}).get("results", []) or []
        if not courses:
            return "No courses found."

        result = f"📚 Found {len(courses)} courses:\n\n"
        for c in courses:
            result += f"• **{c.get('name','Unnamed')}** (ID: `{c.get('id')}`)\n"
        return result

    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def get_course_assignments(course_id: str) -> str:
    """Get assignments for a specific course."""
    token_data = get_current_token()
    if not token_data:
        return get_auth_url()

    token = token_data["access_token"]

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses/{course_id}/gradebook/columns",
                headers={"Authorization": f"Bearer {token}"},
            )

        if resp.status_code == 401:
            delete_current_token()
            return "⚠️ Session expired.\n\n" + get_auth_url()

        if resp.status_code != 200:
            return f"Error: {resp.status_code} - {resp.text}"

        columns = (resp.json() or {}).get("results", []) or []
        assignments = [c for c in columns if (c.get("grading", {}) or {}).get("due")]

        if not assignments:
            return f"No assignments with due dates in course `{course_id}`"

        result = f"📝 Found {len(assignments)} assignments:\n\n"
        for a in assignments:
            result += (
                f"• **{a.get('name')}** "
                f"({(a.get('score', {}) or {}).get('possible', '?')} pts) - "
                f"Due: {(a.get('grading', {}) or {}).get('due')}\n"
            )
        return result

    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def logout() -> str:
    """Log out from Blackboard (single-user)."""
    if get_current_token():
        delete_current_token()
        return "✅ Logged out successfully."
    return "ℹ️ Not currently logged in."


@mcp.tool()
async def check_config() -> str:
    """Check server configuration."""
    redis_ok = "❌"
    try:
        get_redis().ping()
        redis_ok = "✅"
    except Exception:
        pass

    return (
        f"⚙️ **Configuration**\n\n"
        f"• **Blackboard:** `{BLACKBOARD_URL}`\n"
        f"• **App Key:** `{BLACKBOARD_APP_KEY[:8] if BLACKBOARD_APP_KEY else 'NOT SET'}...`\n"
        f"• **Server URL:** `{SERVER_URL}`\n"
        f"• **Redirect URI:** `{REDIRECT_URI}`\n"
        f"• **Redis:** {redis_ok}\n"
    )


@mcp.tool()
async def debug_storage() -> str:
    """Debug token presence in Redis (single-user)."""
    out = "🔧 **Storage Debug**\n\n"
    try:
        r = get_redis()
        r.ping()
        out += "• Redis: ✅ Connected\n"
        token_data = get_current_token()
        out += f"• Has current token: {'✅' if token_data else '❌'}\n"
        if token_data:
            out += f"• User ID: `{token_data._
