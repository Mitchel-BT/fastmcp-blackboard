"""
Blackboard MCP Server - Cloud Version with Custom OAuth
Uses Redis (Upstash) for persistent token storage across stateless requests
"""
import os
import base64
import secrets
import time
import logging
import json
import httpx
from urllib.parse import quote
from fastmcp import FastMCP, Context
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_http_headers, get_context
from starlette.responses import RedirectResponse, JSONResponse
import redis

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
REDIS_URL = os.environ.get("REDIS_URL")  # From Upstash: rediss://default:xxx@xxx.upstash.io:6379

# Token expiry times (in seconds)
TOKEN_EXPIRY = 3600       # 1 hour for access tokens
PENDING_EXPIRY = 600      # 10 minutes for pending auth flows
AUTH_CODE_EXPIRY = 300    # 5 minutes for auth codes

# Redis key prefixes
PREFIX_TOKEN = "bb:token:"
PREFIX_PENDING = "bb:pending:"
PREFIX_AUTHCODE = "bb:authcode:"
PREFIX_COMPLETED = "bb:completed:"

# ============================================================================
# REDIS CLIENT
# ============================================================================
_redis = None

def get_redis() -> redis.Redis:
    """Get or create Redis client"""
    global _redis
    if _redis is None:
        if not REDIS_URL:
            raise RuntimeError("REDIS_URL environment variable is required")
        _redis = redis.from_url(REDIS_URL, decode_responses=True)
        logger.info(f"Redis: Connected")
    return _redis


# ============================================================================
# REDIS STORAGE HELPERS
# ============================================================================

def store_token(access_token: str, token_data: dict):
    """Store a token in Redis with TTL"""
    try:
        r = get_redis()
        key = f"{PREFIX_TOKEN}{access_token}"
        r.setex(key, TOKEN_EXPIRY, json.dumps(token_data))
        logger.info(f"Redis: Stored token {access_token[:20]}...")
        return True
    except Exception as e:
        logger.error(f"Redis: Failed to store token: {e}")
        return False


def get_token(access_token: str) -> dict | None:
    """Retrieve a token from Redis"""
    try:
        r = get_redis()
        key = f"{PREFIX_TOKEN}{access_token}"
        data = r.get(key)
        if data:
            logger.debug(f"Redis: Found token {access_token[:20]}...")
            return json.loads(data)
        return None
    except Exception as e:
        logger.error(f"Redis: Failed to get token: {e}")
        return None


def delete_token(access_token: str):
    """Delete a token from Redis"""
    try:
        r = get_redis()
        r.delete(f"{PREFIX_TOKEN}{access_token}")
        logger.info(f"Redis: Deleted token {access_token[:20]}...")
    except Exception as e:
        logger.error(f"Redis: Failed to delete token: {e}")


def count_tokens() -> int:
    """Count active tokens"""
    try:
        r = get_redis()
        return len(r.keys(f"{PREFIX_TOKEN}*"))
    except Exception as e:
        logger.error(f"Redis: Failed to count tokens: {e}")
        return 0


def store_pending(state: str, auth_data: dict):
    """Store pending OAuth flow"""
    try:
        r = get_redis()
        r.setex(f"{PREFIX_PENDING}{state}", PENDING_EXPIRY, json.dumps(auth_data))
        logger.info(f"Redis: Stored pending auth {state[:20]}...")
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


def store_authcode(code: str, token_data: dict):
    """Store one-time auth code"""
    try:
        r = get_redis()
        r.setex(f"{PREFIX_AUTHCODE}{code}", AUTH_CODE_EXPIRY, json.dumps(token_data))
        logger.info(f"Redis: Stored auth code {code[:20]}...")
        return True
    except Exception as e:
        logger.error(f"Redis: Failed to store authcode: {e}")
        return False


def get_and_delete_authcode(code: str) -> dict | None:
    """Get and delete auth code (one-time use)"""
    try:
        r = get_redis()
        key = f"{PREFIX_AUTHCODE}{code}"
        data = r.get(key)
        if data:
            r.delete(key)
            return json.loads(data)
        return None
    except Exception as e:
        logger.error(f"Redis: Failed to get authcode: {e}")
        return None


def store_completed(state: str, data: dict):
    """Store completed state for duplicate handling"""
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
# MIDDLEWARE
# ============================================================================

class BlackboardAuthMiddleware(Middleware):
    """Extract Bearer token and load session from Redis"""
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        logger.debug(f"Middleware: Processing {context.message.name}")
        
        try:
            headers = get_http_headers()
            auth_header = headers.get("authorization", "") or headers.get("Authorization", "")
            
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                logger.info(f"Middleware: Bearer token {token[:20]}...")
                
                token_data = get_token(token)
                if token_data:
                    context.fastmcp_context.set_state("access_token", token)
                    context.fastmcp_context.set_state("user_id", token_data.get("user_id"))
                    context.fastmcp_context.set_state("token_data", token_data)
                    context.fastmcp_context.set_state("authenticated", True)
                    logger.info(f"Middleware: ✅ Authenticated {token_data.get('user_id')}")
                else:
                    logger.warning(f"Middleware: ❌ Token not in Redis")
                    context.fastmcp_context.set_state("authenticated", False)
            else:
                logger.debug("Middleware: No Bearer token")
                context.fastmcp_context.set_state("authenticated", False)
                
        except Exception as e:
            logger.exception(f"Middleware error: {e}")
            context.fastmcp_context.set_state("authenticated", False)
        
        return await call_next(context)


# ============================================================================
# MCP SERVER
# ============================================================================
mcp = FastMCP("Blackboard")
mcp.add_middleware(BlackboardAuthMiddleware())


def get_user_session() -> tuple[str | None, dict | None, bool]:
    """Get current user session from context"""
    try:
        ctx = get_context()
        if ctx.get_state("authenticated"):
            return ctx.get_state("access_token"), ctx.get_state("token_data"), True
    except Exception as e:
        logger.error(f"Session error: {e}")
    return None, None, False


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
        "original_state": "login",
        "is_user_login": True,
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


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_metadata(request):
    return JSONResponse({
        "issuer": SERVER_URL,
        "authorization_endpoint": f"{SERVER_URL}/oauth/authorize",
        "token_endpoint": f"{SERVER_URL}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
    })


@mcp.custom_route("/oauth/authorize", methods=["GET"])
async def oauth_authorize(request):
    """OAuth authorize endpoint"""
    client_id = request.query_params.get("client_id")
    redirect_uri = request.query_params.get("redirect_uri")
    state = request.query_params.get("state")
    code_challenge = request.query_params.get("code_challenge")
    
    logger.info(f"OAuth: Authorize request client_id={client_id}")
    
    our_state = secrets.token_urlsafe(32)
    store_pending(our_state, {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "original_state": state,
        "code_challenge": code_challenge,
        "is_user_login": False,
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


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request):
    """OAuth callback from Blackboard"""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    logger.info(f"OAuth: Callback state={state[:20] if state else 'None'}...")
    
    if error:
        return JSONResponse({"error": error}, status_code=400)
    
    if not code or not state:
        return JSONResponse({"error": "missing_parameters"}, status_code=400)
    
    # Check for duplicate
    completed = get_completed(state)
    if completed:
        logger.info("OAuth: Duplicate callback - showing success")
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
    
    is_user_login = original.get("is_user_login", False)
    
    try:
        # Exchange code for token
        logger.info("OAuth: Exchanging code...")
        
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
        
        # Create auth code for Claude
        claude_code = secrets.token_urlsafe(32)
        store_authcode(claude_code, token_record)
        
        # Mark completed
        store_completed(state, {
            "claude_code": claude_code,
            "redirect_uri": original["redirect_uri"],
            "original_state": original["original_state"]
        })
        delete_pending(state)
        
        # Redirect
        if is_user_login:
            redirect_url = f"{original['redirect_uri']}?code={claude_code}"
        else:
            redirect_url = f"{original['redirect_uri']}?code={claude_code}&state={original['original_state']}"
        
        logger.info(f"OAuth: Redirecting to {redirect_url[:50]}...")
        return RedirectResponse(redirect_url)
        
    except Exception as e:
        logger.exception(f"OAuth error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request):
    """Token endpoint for Claude"""
    form = await request.form()
    code = form.get("code")
    
    logger.info("OAuth: Token request from Claude")
    
    if not code:
        return JSONResponse({"error": "missing_code"}, status_code=400)
    
    token_data = get_and_delete_authcode(code)
    if not token_data:
        return JSONResponse({"error": "invalid_code"}, status_code=400)
    
    access_token = token_data["access_token"]
    
    # Ensure stored
    if not get_token(access_token):
        store_token(access_token, token_data)
    
    logger.info(f"OAuth: ✅ Issued token for {token_data.get('user_id')}")
    
    return JSONResponse({
        "access_token": access_token,
        "token_type": token_data["token_type"],
        "expires_in": token_data["expires_in"],
        "scope": "read write"
    })


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def protected_resource(request):
    return JSONResponse({
        "resource": SERVER_URL,
        "authorization_servers": [SERVER_URL]
    })


# ============================================================================
# MCP TOOLS
# ============================================================================

@mcp.tool()
async def get_my_courses() -> str:
    """Get all courses you have access to in Blackboard."""
    token, token_data, auth = get_user_session()
    if not auth:
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
    token, _, auth = get_user_session()
    if not auth:
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
    token, _, auth = get_user_session()
    if not auth:
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
    token, _, auth = get_user_session()
    if auth and token:
        delete_token(token)
        return "✅ Logged out successfully."
    return "ℹ️ Not currently logged in."


@mcp.tool()
async def check_auth_status() -> str:
    """Check authentication status."""
    # Test Redis connection
    try:
        token_count = count_tokens()
        logger.info(f"check_auth_status: {token_count} tokens in Redis")
    except Exception as e:
        return f"❌ Redis error: {e}"
    
    token, token_data, auth = get_user_session()
    
    if not auth:
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
    
    # Redis
    try:
        r = get_redis()
        r.ping()
        result += f"**Redis:** ✅ Connected\n"
        result += f"• Tokens: {count_tokens()}\n\n"
    except Exception as e:
        result += f"**Redis:** ❌ {e}\n\n"
    
    # Session
    token, token_data, auth = get_user_session()
    result += f"**Session:**\n"
    result += f"• Authenticated: {auth}\n"
    result += f"• User: {token_data.get('user_id') if token_data else 'N/A'}\n\n"
    
    # Headers
    try:
        headers = get_http_headers()
        auth_h = headers.get("authorization", "")
        result += f"**Headers:**\n"
        result += f"• Bearer: {'Yes' if auth_h.startswith('Bearer ') else 'No'}\n"
    except Exception as e:
        result += f"**Headers:** Error\n"
    
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
