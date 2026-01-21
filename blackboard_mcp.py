"""
Blackboard MCP Server - Simple version with Redis session storage
Uses Upstash Redis HTTP API for serverless-friendly storage
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

# Use Upstash's HTTP-based Redis client
from upstash_redis import Redis

# ============================================================================
# LOGGING SETUP
# ============================================================================
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("blackboard-mcp")

# ============================================================================
# CONFIGURATION
# ============================================================================
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET")
SERVER_URL = os.environ.get("SERVER_URL")

# Upstash credentials
UPSTASH_REDIS_REST_URL = os.environ.get("UPSTASH_REDIS_REST_URL")
UPSTASH_REDIS_REST_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN")

# Token expiry times (in seconds)
TOKEN_EXPIRY = 3600
PENDING_EXPIRY = 600

# Redis key prefixes
PREFIX_TOKEN = "bb:token:"
PREFIX_PENDING = "bb:pending:"
PREFIX_COMPLETED = "bb:completed:"
CURRENT_SESSION_KEY = "bb:current_session"

# ============================================================================
# UPSTASH REDIS CLIENT
# ============================================================================

def get_redis() -> Redis:
    """Get Upstash Redis client"""
    if not UPSTASH_REDIS_REST_URL or not UPSTASH_REDIS_REST_TOKEN:
        raise RuntimeError("UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN required")
    return Redis(url=UPSTASH_REDIS_REST_URL, token=UPSTASH_REDIS_REST_TOKEN)


# ============================================================================
# REDIS STORAGE HELPERS
# ============================================================================

def store_token(access_token: str, token_data: dict):
    """Store token and set as current session"""
    try:
        r = get_redis()
        r.setex(f"{PREFIX_TOKEN}{access_token}", TOKEN_EXPIRY, json.dumps(token_data))
        r.setex(CURRENT_SESSION_KEY, TOKEN_EXPIRY, access_token)
        logger.info(f"Redis: Stored token and set as current session")
        return True
    except Exception as e:
        logger.error(f"Redis: Failed to store token: {e}")
        return False


def get_token(access_token: str) -> dict | None:
    """Retrieve a token"""
    try:
        r = get_redis()
        data = r.get(f"{PREFIX_TOKEN}{access_token}")
        if data:
            return json.loads(data)
        return None
    except Exception as e:
        logger.error(f"Redis: Failed to get token: {e}")
        return None


def get_current_session() -> tuple[str | None, dict | None]:
    """Get the current active session"""
    try:
        r = get_redis()
        access_token = r.get(CURRENT_SESSION_KEY)
        if access_token:
            token_data = get_token(access_token)
            if token_data:
                return access_token, token_data
        return None, None
    except Exception as e:
        logger.error(f"Redis: Failed to get current session: {e}")
        return None, None


def delete_token(access_token: str):
    """Delete a token"""
    try:
        r = get_redis()
        r.delete(f"{PREFIX_TOKEN}{access_token}")
        current = r.get(CURRENT_SESSION_KEY)
        if current == access_token:
            r.delete(CURRENT_SESSION_KEY)
    except Exception as e:
        logger.error(f"Redis: Failed to delete token: {e}")


def store_pending(state: str, auth_data: dict):
    """Store pending OAuth flow"""
    try:
        r = get_redis()
        r.setex(f"{PREFIX_PENDING}{state}", PENDING_EXPIRY, json.dumps(auth_data))
        return True
    except Exception as e:
        logger.error(f"Redis: Failed to store pending: {e}")
        return False


def get_pending(state: str) -> dict | None:
    """Get pending OAuth flow"""
    try:
        r = get_redis()
        data = r.get(f"{PREFIX_PENDING}{state}")
        return json.loads(data) if data else None
    except Exception as e:
        logger.error(f"Redis: Failed to get pending: {e}")
        return None


def delete_pending(state: str):
    """Delete pending OAuth flow"""
    try:
        r = get_redis()
        r.delete(f"{PREFIX_PENDING}{state}")
    except Exception as e:
        logger.error(f"Redis: Failed to delete pending: {e}")


def store_completed(state: str, data: dict):
    """Store completed state"""
    try:
        r = get_redis()
        r.setex(f"{PREFIX_COMPLETED}{state}", PENDING_EXPIRY, json.dumps(data))
        return True
    except Exception as e:
        logger.error(f"Redis: Failed to store completed: {e}")
        return False


def get_completed(state: str) -> dict | None:
    """Get completed state"""
    try:
        r = get_redis()
        data = r.get(f"{PREFIX_COMPLETED}{state}")
        return json.loads(data) if data else None
    except Exception as e:
        logger.error(f"Redis: Failed to get completed: {e}")
        return None


def count_tokens() -> int:
    """Count active tokens"""
    try:
        r = get_redis()
        keys = r.keys(f"{PREFIX_TOKEN}*")
        return len(keys) if keys else 0
    except Exception as e:
        logger.error(f"Redis: Failed to count tokens: {e}")
        return 0


# ============================================================================
# AUTH URL HELPER
# ============================================================================

def get_auth_url() -> str:
    """Generate the authentication URL"""
    return (
        f"🔐 **Authentication Required**\n\n"
        f"Please log in to Blackboard:\n\n"
        f"👉 [{SERVER_URL}/login]({SERVER_URL}/login)\n\n"
        f"After logging in, return here and try again."
    )


# ============================================================================
# MCP SERVER
# ============================================================================

mcp = FastMCP("Blackboard")


# ============================================================================
# OAUTH ROUTES
# ============================================================================

@mcp.custom_route("/login", methods=["GET"])
async def login_page(request):
    """User login - start OAuth flow"""
    logger.info("Login: Starting OAuth flow")
    
    our_state = secrets.token_urlsafe(32)
    store_pending(our_state, {
        "redirect_uri": f"{SERVER_URL}/login/success",
        "timestamp": time.time()
    })
    
    encoded_redirect = quote(f"{SERVER_URL}/oauth/callback", safe='')
    bb_auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?redirect_uri={encoded_redirect}"
        f"&response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&scope=read%20write"
        f"&state={our_state}"
    )
    
    return RedirectResponse(bb_auth_url)


@mcp.custom_route("/login/success", methods=["GET"])
async def login_success(request):
    """Success page after login"""
    return JSONResponse({
        "status": "success",
        "message": "✅ Login successful! Close this window and return to Claude."
    })


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request):
    """OAuth callback from Blackboard"""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    logger.info(f"OAuth: Callback received")
    
    if error:
        return JSONResponse({"error": error}, status_code=400)
    
    if not code or not state:
        return JSONResponse({"error": "missing_parameters"}, status_code=400)
    
    # Check for duplicate
    completed = get_completed(state)
    if completed:
        return JSONResponse({
            "status": "success",
            "message": "✅ Already authenticated! Close this window."
        })
    
    # Get pending auth
    original = get_pending(state)
    if not original:
        if count_tokens() > 0:
            return JSONResponse({
                "status": "success",
                "message": "✅ Already authenticated! Close this window."
            })
        return JSONResponse({"error": "invalid_state"}, status_code=400)
    
    try:
        # Exchange code for token
        logger.info("OAuth: Exchanging code for token...")
        
        creds = f"{BLACKBOARD_APP_KEY}:{BLACKBOARD_APP_SECRET}"
        auth_header = base64.b64encode(creds.encode()).decode()
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/token",
                headers={
                    "Authorization": f"Basic {auth_header}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": f"{SERVER_URL}/oauth/callback"
                }
            )
            
            if resp.status_code != 200:
                logger.error(f"OAuth: Token exchange failed: {resp.text}")
                return JSONResponse({"error": "token_exchange_failed"}, status_code=500)
            
            bb_token = resp.json()
            access_token = bb_token["access_token"]
            user_id = bb_token.get("user_id", "unknown")
            logger.info(f"OAuth: ✅ Got token for {user_id}")
        
        # Store token in Redis
        token_record = {
            "access_token": access_token,
            "token_type": bb_token.get("token_type", "bearer"),
            "expires_in": bb_token.get("expires_in", 3600),
            "refresh_token": bb_token.get("refresh_token"),
            "user_id": user_id,
            "timestamp": time.time()
        }
        store_token(access_token, token_record)
        
        # Mark completed
        store_completed(state, {"user_id": user_id})
        delete_pending(state)
        
        # Redirect to success
        return RedirectResponse(f"{SERVER_URL}/login/success")
        
    except Exception as e:
        logger.exception(f"OAuth error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================================
# MCP TOOLS
# ============================================================================

@mcp.tool()
async def get_my_courses() -> str:
    """Get all courses you have access to in Blackboard."""
    token, token_data = get_current_session()
    if not token:
        return get_auth_url()
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses?limit=100",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            if resp.status_code == 401:
                delete_token(token)
                return "⚠️ Session expired.\n\n" + get_auth_url()
            
            if resp.status_code != 200:
                return f"Error: {resp.status_code} - {resp.text}"
            
            courses = resp.json().get("results", [])
            if not courses:
                return "No courses found."
            
            result = f"📚 Found {len(courses)} courses:\n\n"
            for c in courses:
                result += f"• **{c.get('name', 'Unnamed')}** (ID: `{c.get('id')}`)\n"
            return result
            
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def get_course_assignments(course_id: str) -> str:
    """Get assignments for a specific course."""
    token, _ = get_current_session()
    if not token:
        return get_auth_url()
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses/{course_id}/gradebook/columns",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            if resp.status_code == 401:
                delete_token(token)
                return "⚠️ Session expired.\n\n" + get_auth_url()
            
            if resp.status_code != 200:
                return f"Error: {resp.status_code} - {resp.text}"
            
            columns = resp.json().get("results", [])
            assignments = [c for c in columns if c.get("grading", {}).get("due")]
            
            if not assignments:
                return f"No assignments with due dates in course `{course_id}`"
            
            result = f"📝 Found {len(assignments)} assignments:\n\n"
            for a in assignments:
                result += f"• **{a.get('name')}** ({a.get('score', {}).get('possible', '?')} pts) - Due: {a.get('grading', {}).get('due')}\n"
            return result
            
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def get_current_user() -> str:
    """Get current authenticated Blackboard user info."""
    token, _ = get_current_session()
    if not token:
        return get_auth_url()
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            if resp.status_code == 401:
                delete_token(token)
                return "⚠️ Session expired.\n\n" + get_auth_url()
            
            if resp.status_code != 200:
                return f"Error: {resp.status_code} - {resp.text}"
            
            user = resp.json()
            name = user.get('name', {})
            
            result = "👤 **Current User**\n\n"
            result += f"• **User ID:** `{user.get('id')}`\n"
            result += f"• **Username:** `{user.get('userName')}`\n"
            if name.get('given') or name.get('family'):
                result += f"• **Name:** {name.get('given', '')} {name.get('family', '')}\n"
            if user.get('contact', {}).get('email'):
                result += f"• **Email:** {user['contact']['email']}\n"
            return result
            
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def logout() -> str:
    """Log out from Blackboard."""
    token, _ = get_current_session()
    if token:
        delete_token(token)
        return "✅ Logged out successfully."
    return "ℹ️ Not currently logged in."


@mcp.tool()
async def check_auth_status() -> str:
    """Check authentication status."""
    token, token_data = get_current_session()
    
    if not token_data:
        return "🔒 **Not Authenticated**\n\n" + get_auth_url()
    
    return (
        f"✅ **Authenticated**\n\n"
        f"• **User ID:** `{token_data.get('user_id')}`\n"
        f"• **Expires in:** ~{token_data.get('expires_in', 3600) // 60} minutes"
    )


@mcp.tool()
async def debug_session() -> str:
    """Debug session and Redis info."""
    result = "🔧 **Debug Info**\n\n"
    
    try:
        r = get_redis()
        r.ping()
        result += f"**Redis:** ✅ Connected\n"
        result += f"• Tokens: {count_tokens()}\n"
        
        token, token_data = get_current_session()
        if token_data:
            result += f"• Current session: {token_data.get('user_id')}\n"
        else:
            result += f"• Current session: None\n"
    except Exception as e:
        result += f"**Redis:** ❌ {e}\n"
    
    return result


@mcp.tool()
async def check_config() -> str:
    """Check server configuration."""
    redis_ok = "❌"
    try:
        get_redis().ping()
        redis_ok = "✅"
    except:
        pass
    
    return (
        f"⚙️ **Configuration**\n\n"
        f"• **Blackboard:** `{BLACKBOARD_URL}`\n"
        f"• **App Key:** `{BLACKBOARD_APP_KEY[:8] if BLACKBOARD_APP_KEY else 'NOT SET'}...`\n"
        f"• **Server URL:** `{SERVER_URL}`\n"
        f"• **Redis:** {redis_ok}\n"
    )
