"""
Blackboard MCP Server - OAuth + Upstash Redis (FastMCP Cloud friendly)

Supports BOTH redirect styles:
1) Full-path redirect:   https://your-host/oauth/callback
2) Bare-domain redirect: https://your-host/?code=...&state=...

Set env:
- SERVER_URL = https://your-host   (NO trailing slash)
- BLACKBOARD_URL = https://your-blackboard-host (NO trailing slash)
- BLACKBOARD_APP_KEY / BLACKBOARD_APP_SECRET
- UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN

Optional env:
- OAUTH_REDIRECT_PATH:
    - "oauth/callback" (default)
    - ""  (bare-domain redirect)
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
    level=logging.INFO,  # INFO in prod; bump to DEBUG while diagnosing
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("blackboard-mcp")

# =============================================================================
# CONFIG (normalized)
# =============================================================================
BLACKBOARD_URL = (os.environ.get("BLACKBOARD_URL") or "").rstrip("/")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY") or ""
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET") or ""

SERVER_URL = (os.environ.get("SERVER_URL") or "").rstrip("/")

# If Blackboard only supports host-level redirect URIs, set this to "".
OAUTH_REDIRECT_PATH = (os.environ.get("OAUTH_REDIRECT_PATH") or "oauth/callback").strip("/")

UPSTASH_REDIS_REST_URL = os.environ.get("UPSTASH_REDIS_REST_URL")
UPSTASH_REDIS_REST_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN")

# Expiries
TOKEN_EXPIRY = 3600
PENDING_EXPIRY = 600

# Redis keys
PREFIX_TOKEN = "bb:token:"
PREFIX_PENDING = "bb:pending:"
PREFIX_COMPLETED = "bb:completed:"
CURRENT_SESSION_KEY = "bb:current_session"

# Derived redirect URI
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
        raise RuntimeError(f"Missing required env vars: {', '.join(missing)}")


def _to_str(v):
    if v is None:
        return None
    if isinstance(v, bytes):
        return v.decode("utf-8")
    return v


# =============================================================================
# REDIS (Upstash HTTP)
# =============================================================================
def get_redis() -> Redis:
    _require_env()
    return Redis(url=UPSTASH_REDIS_REST_URL, token=UPSTASH_REDIS_REST_TOKEN)


def store_token(access_token: str, token_data: dict) -> bool:
    try:
        r = get_redis()
        r.setex(f"{PREFIX_TOKEN}{access_token}", TOKEN_EXPIRY, json.dumps(token_data))
        r.setex(CURRENT_SESSION_KEY, TOKEN_EXPIRY, access_token)
        logger.info("Redis: stored token and set as current session")
        return True
    except Exception as e:
        logger.error(f"Redis: failed to store token: {e}")
        return False


def get_token(access_token: str) -> dict | None:
    try:
        r = get_redis()
        access_token = _to_str(access_token)
        data = r.get(f"{PREFIX_TOKEN}{access_token}")
        data = _to_str(data)
        return json.loads(data) if data else None
    except Exception as e:
        logger.error(f"Redis: failed to get token: {e}")
        return None


def get_current_session() -> tuple[str | None, dict | None]:
    try:
        r = get_redis()
        access_token = _to_str(r.get(CURRENT_SESSION_KEY))
        if access_token:
            token_data = get_token(access_token)
            if token_data:
                return access_token, token_data
        return None, None
    except Exception as e:
        logger.error(f"Redis: failed to get current session: {e}")
        return None, None


def delete_token(access_token: str):
    try:
        r = get_redis()
        r.delete(f"{PREFIX_TOKEN}{access_token}")
        current = _to_str(r.get(CURRENT_SESSION_KEY))
        if current == access_token:
            r.delete(CURRENT_SESSION_KEY)
    except Exception as e:
        logger.error(f"Redis: failed to delete token: {e}")


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


def count_tokens() -> int:
    try:
        r = get_redis()
        keys = r.keys(f"{PREFIX_TOKEN}*")
        return len(keys) if keys else 0
    except Exception as e:
        logger.error(f"Redis: failed to count tokens: {e}")
        return 0


# =============================================================================
# AUTH helper
# =============================================================================
def get_auth_url() -> str:
    url = f"{SERVER_URL}/login"
    return (
        "🔐 Authentication Required\n\n"
        f"Open this link in your browser:\n{url}\n\n"
        "After logging in, come back to Claude and run the tool again."
    )


# =============================================================================
# MCP
# =============================================================================
mcp = FastMCP("Blackboard")


# =============================================================================
# ROUTES
# =============================================================================

# If Blackboard only redirects to the bare domain, it will hit "/" with code/state.
# This route gracefully handles that by delegating to the callback handler.
@mcp.custom_route("/", methods=["GET"])
async def root(request):
    if request.query_params.get("code") and request.query_params.get("state"):
        return await oauth_callback(request)
    return JSONResponse({"status": "ok"})


@mcp.custom_route("/login", methods=["GET"])
async def login_page(request):
    logger.info("Login: starting OAuth flow")

    our_state = secrets.token_urlsafe(32)
    store_pending(our_state, {"redirect_uri": REDIRECT_URI, "timestamp": time.time()})

    bb_auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?redirect_uri={quote(REDIRECT_URI, safe='')}"
        f"&response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&scope=read%20write"
        f"&state={our_state}"
    )

    logger.info(f"Login: redirect_uri={REDIRECT_URI}")
    return RedirectResponse(bb_auth_url)


@mcp.custom_route("/login/success", methods=["GET"])
async def login_success(request):
    return JSONResponse(
        {"status": "success", "message": "✅ Login successful! Close this window and return to Claude."}
    )


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request):
    # Log what we got (super helpful for mismatch debugging)
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

    # Prevent duplicate processing
    completed = get_completed(state)
    if completed:
        return RedirectResponse(f"{SERVER_URL}/login/success")

    original = get_pending(state)
    if not original:
        # If there's already an active token, treat it as success (user might have refreshed)
        if count_tokens() > 0:
            return RedirectResponse(f"{SERVER_URL}/login/success")
        return JSONResponse({"error": "invalid_state"}, status_code=400)

    # Must use the same redirect_uri we used in authorize step
    redirect_uri = original.get("redirect_uri") or REDIRECT_URI

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
                },
            )

        if resp.status_code != 200:
            logger.error(f"OAuth: token exchange failed ({resp.status_code}): {resp.text}")
            return JSONResponse(
                {"error": "token_exchange_failed", "status_code": resp.status_code, "details": resp.text},
                status_code=500,
            )

        bb_token = resp.json()
        access_token = bb_token["access_token"]
        user_id = bb_token.get("user_id", "unknown")

        token_record = {
            "access_token": access_token,
            "token_type": bb_token.get("token_type", "bearer"),
            "expires_in": bb_token.get("expires_in", 3600),
            "refresh_token": bb_token.get("refresh_token"),
            "user_id": user_id,
            "timestamp": time.time(),
        }

        if not store_token(access_token, token_record):
            return JSONResponse({"error": "redis_store_failed"}, status_code=500)

        store_completed(state, {"user_id": user_id})
        delete_pending(state)

        logger.info(f"OAuth: ✅ stored token for user_id={user_id}")
        return RedirectResponse(f"{SERVER_URL}/login/success")

    except Exception as e:
        logger.exception("OAuth: exception during callback")
        return JSONResponse({"error": str(e)}, status_code=500)


# =============================================================================
# TOOLS
# =============================================================================
@mcp.tool()
async def check_auth_status() -> str:
    token, token_data = get_current_session()
    if not token_data:
        return "🔒 Not Authenticated\n\n" + get_auth_url()
    return (
        "✅ Authenticated\n\n"
        f"• User ID: `{token_data.get('user_id')}`\n"
        f"• Expires in: ~{token_data.get('expires_in', 3600)//60} minutes"
    )


@mcp.tool()
async def get_current_user() -> str:
    token, _ = get_current_session()
    if not token:
        return get_auth_url()

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(
            f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
            headers={"Authorization": f"Bearer {token}"},
        )

    if resp.status_code == 401:
        delete_token(token)
        return "⚠️ Session expired.\n\n" + get_auth_url()

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
async def get_my_courses() -> str:
    token, _ = get_current_session()
    if not token:
        return get_auth_url()

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(
            f"{BLACKBOARD_URL}/learn/api/public/v1/courses?limit=100",
            headers={"Authorization": f"Bearer {token}"},
        )

    if resp.status_code == 401:
        delete_token(token)
        return "⚠️ Session expired.\n\n" + get_auth_url()

    if resp.status_code != 200:
        return f"Error: {resp.status_code} - {resp.text}"

    courses = resp.json().get("results", []) or []
    if not courses:
        return "No courses found."

    result = f"📚 Found {len(courses)} courses:\n\n"
    for c in courses:
        result += f"• **{c.get('name','Unnamed')}** (ID: `{c.get('id')}`)\n"
    return result


@mcp.tool()
async def logout() -> str:
    token, _ = get_current_session()
    if token:
        delete_token(token)
        return "✅ Logged out successfully."
    return "ℹ️ Not currently logged in."


@mcp.tool()
async def debug_session() -> str:
    out = "🔧 Debug Info\n\n"
    try:
        r = get_redis()
        r.ping()
        out += "Redis: ✅ Connected\n"
        out += f"• Tokens: {count_tokens()}\n"
        token, token_data = get_current_session()
        out += f"• Current session: {token_data.get('user_id') if token_data else 'None'}\n"
        out += f"• Redirect URI: {REDIRECT_URI}\n"
    except Exception as e:
        out += f"Redis: ❌ {e}\n"
    return out
