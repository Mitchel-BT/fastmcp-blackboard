"""
Blackboard MCP Server - Cloud Version with Custom OAuth
Uses FastMCP's DiskStore for persistent token storage
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

# Storage backend from py-key-value-aio (bundled with FastMCP)
from key_value.aio.stores.disk import DiskStore

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

# Storage directory - can be configured via env var
STORAGE_DIR = os.environ.get("STORAGE_DIR", "/tmp/blackboard-mcp")

# Token expiry times
TOKEN_EXPIRY_SECONDS = 3600
PENDING_AUTH_EXPIRY = 600
AUTH_CODE_EXPIRY = 300

# ============================================================================
# STORAGE SETUP
# ============================================================================
# Initialize disk-based stores for different data types
token_store = DiskStore(directory=f"{STORAGE_DIR}/tokens")
pending_store = DiskStore(directory=f"{STORAGE_DIR}/pending")
authcode_store = DiskStore(directory=f"{STORAGE_DIR}/authcodes")
completed_store = DiskStore(directory=f"{STORAGE_DIR}/completed")

logger.info(f"Storage: Using DiskStore at {STORAGE_DIR}")


# ============================================================================
# ASYNC STORAGE HELPERS
# ============================================================================

async def store_token(access_token: str, token_data: dict):
    """Store a token"""
    try:
        # Add expiry timestamp
        token_data["_expires_at"] = time.time() + TOKEN_EXPIRY_SECONDS
        await token_store.set(access_token, json.dumps(token_data))
        logger.info(f"Storage: Stored token {access_token[:20]}...")
        return True
    except Exception as e:
        logger.error(f"Storage: Failed to store token: {e}")
        return False


async def get_token(access_token: str) -> dict | None:
    """Retrieve a token"""
    try:
        data = await token_store.get(access_token)
        if data:
            token_data = json.loads(data)
            # Check expiry
            if token_data.get("_expires_at", 0) < time.time():
                await token_store.delete(access_token)
                logger.debug(f"Storage: Token expired {access_token[:20]}...")
                return None
            logger.debug(f"Storage: Found token {access_token[:20]}...")
            return token_data
        return None
    except Exception as e:
        logger.error(f"Storage: Failed to get token: {e}")
        return None


async def delete_token(access_token: str):
    """Delete a token"""
    try:
        await token_store.delete(access_token)
        logger.info(f"Storage: Deleted token {access_token[:20]}...")
    except Exception as e:
        logger.error(f"Storage: Failed to delete token: {e}")


async def count_tokens() -> int:
    """Count active tokens"""
    try:
        keys = await token_store.keys()
        return len(list(keys))
    except Exception as e:
        logger.error(f"Storage: Failed to count tokens: {e}")
        return 0


async def store_pending_auth(state: str, auth_data: dict):
    """Store pending OAuth flow data"""
    try:
        auth_data["_expires_at"] = time.time() + PENDING_AUTH_EXPIRY
        await pending_store.set(state, json.dumps(auth_data))
        logger.info(f"Storage: Stored pending auth {state[:20]}...")
        return True
    except Exception as e:
        logger.error(f"Storage: Failed to store pending auth: {e}")
        return False


async def get_pending_auth(state: str) -> dict | None:
    """Retrieve pending OAuth flow data"""
    try:
        data = await pending_store.get(state)
        if data:
            auth_data = json.loads(data)
            if auth_data.get("_expires_at", 0) < time.time():
                await pending_store.delete(state)
                return None
            return auth_data
        return None
    except Exception as e:
        logger.error(f"Storage: Failed to get pending auth: {e}")
        return None


async def delete_pending_auth(state: str):
    """Delete pending OAuth flow data"""
    try:
        await pending_store.delete(state)
    except Exception as e:
        logger.error(f"Storage: Failed to delete pending auth: {e}")


async def store_auth_code(code: str, token_data: dict):
    """Store one-time auth code"""
    try:
        token_data["_expires_at"] = time.time() + AUTH_CODE_EXPIRY
        await authcode_store.set(code, json.dumps(token_data))
        logger.info(f"Storage: Stored auth code {code[:20]}...")
        return True
    except Exception as e:
        logger.error(f"Storage: Failed to store auth code: {e}")
        return False


async def get_and_delete_auth_code(code: str) -> dict | None:
    """Retrieve and delete auth code (one-time use)"""
    try:
        data = await authcode_store.get(code)
        if data:
            await authcode_store.delete(code)
            token_data = json.loads(data)
            if token_data.get("_expires_at", 0) < time.time():
                return None
            return token_data
        return None
    except Exception as e:
        logger.error(f"Storage: Failed to get auth code: {e}")
        return None


async def store_completed_state(state: str, completed_data: dict):
    """Store completed state for duplicate handling"""
    try:
        completed_data["_expires_at"] = time.time() + PENDING_AUTH_EXPIRY
        await completed_store.set(state, json.dumps(completed_data))
        return True
    except Exception as e:
        logger.error(f"Storage: Failed to store completed state: {e}")
        return False


async def get_completed_state(state: str) -> dict | None:
    """Retrieve completed state data"""
    try:
        data = await completed_store.get(state)
        if data:
            completed_data = json.loads(data)
            if completed_data.get("_expires_at", 0) < time.time():
                await completed_store.delete(state)
                return None
            return completed_data
        return None
    except Exception as e:
        logger.error(f"Storage: Failed to get completed state: {e}")
        return None


# ============================================================================
# AUTH URL HELPER
# ============================================================================

def get_auth_url() -> str:
    """Generate the authentication URL for users to log in"""
    auth_state = secrets.token_urlsafe(16)
    return (
        f"🔐 **Authentication Required**\n\n"
        f"Please log in to Blackboard by clicking the link below:\n\n"
        f"👉 [{SERVER_URL}/login]({SERVER_URL}/login?state={auth_state})\n\n"
        f"After logging in, return here and try your request again."
    )


# ============================================================================
# AUTHENTICATION MIDDLEWARE
# ============================================================================

class BlackboardAuthMiddleware(Middleware):
    """
    Middleware that extracts Bearer token from Authorization header
    and loads user session data from storage into context state.
    """
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Intercept tool calls to inject user session data"""
        logger.debug(f"Middleware: Processing tool call: {context.message.name}")
        
        try:
            headers = get_http_headers()
            auth_header = headers.get("authorization", "") or headers.get("Authorization", "")
            
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                logger.info(f"Middleware: Found Bearer token: {token[:20]}...")
                
                # Look up the token in storage
                token_data = await get_token(token)
                
                if token_data:
                    context.fastmcp_context.set_state("access_token", token)
                    context.fastmcp_context.set_state("user_id", token_data.get("user_id"))
                    context.fastmcp_context.set_state("token_data", token_data)
                    context.fastmcp_context.set_state("authenticated", True)
                    logger.info(f"Middleware: ✅ Authenticated user {token_data.get('user_id')}")
                else:
                    logger.warning(f"Middleware: ❌ Token not found in storage")
                    context.fastmcp_context.set_state("authenticated", False)
            else:
                logger.debug("Middleware: No Bearer token in Authorization header")
                context.fastmcp_context.set_state("authenticated", False)
                
        except Exception as e:
            logger.exception(f"Middleware: Error: {e}")
            context.fastmcp_context.set_state("authenticated", False)
        
        return await call_next(context)


# ============================================================================
# MCP SERVER SETUP
# ============================================================================
mcp = FastMCP("Blackboard")
mcp.add_middleware(BlackboardAuthMiddleware())


# ============================================================================
# HELPER FUNCTIONS FOR TOOLS
# ============================================================================

def get_user_session() -> tuple[str | None, dict | None, bool]:
    """Get the current user's session from context state."""
    try:
        ctx = get_context()
        authenticated = ctx.get_state("authenticated")
        
        if authenticated:
            token = ctx.get_state("access_token")
            token_data = ctx.get_state("token_data")
            return token, token_data, True
                
    except Exception as e:
        logger.error(f"Error getting user session: {e}")
    
    return None, None, False


# ============================================================================
# OAUTH ROUTES
# ============================================================================

@mcp.custom_route("/login", methods=["GET"])
async def login_page(request):
    """User-facing login page - start OAuth flow"""
    state = request.query_params.get("state", "manual")
    logger.info(f"Login: User initiated login")
    
    our_state = secrets.token_urlsafe(32)
    
    auth_data = {
        "client_id": "user_login",
        "redirect_uri": f"{SERVER_URL}/login/success",
        "original_state": state,
        "timestamp": time.time(),
        "is_user_login": True
    }
    await store_pending_auth(our_state, auth_data)
    
    encoded_redirect = quote(f"{SERVER_URL}/oauth/callback", safe='')
    blackboard_auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?redirect_uri={encoded_redirect}"
        f"&response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&scope=read%20write"
        f"&state={our_state}"
    )
    
    logger.info(f"Login: Redirecting to Blackboard")
    return RedirectResponse(blackboard_auth_url)


@mcp.custom_route("/login/success", methods=["GET"])
async def login_success(request):
    """Success page after user login"""
    return JSONResponse({
        "status": "success",
        "message": "✅ Login successful! You can close this window and return to Claude."
    })


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_config(request):
    """OAuth server configuration"""
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
    """OAuth authorization endpoint - redirects to Blackboard"""
    client_id = request.query_params.get("client_id")
    redirect_uri = request.query_params.get("redirect_uri")
    state = request.query_params.get("state")
    code_challenge = request.query_params.get("code_challenge")
    
    logger.info(f"OAuth: Authorization request - client_id={client_id}, state={state}")
    
    our_state = secrets.token_urlsafe(32)
    
    auth_data = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "original_state": state,
        "code_challenge": code_challenge,
        "timestamp": time.time(),
        "is_user_login": False
    }
    await store_pending_auth(our_state, auth_data)
    
    encoded_redirect = quote(f"{SERVER_URL}/oauth/callback", safe='')
    blackboard_auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?redirect_uri={encoded_redirect}"
        f"&response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&scope=read%20write"
        f"&state={our_state}"
    )
    
    logger.info(f"OAuth: Redirecting to Blackboard")
    return RedirectResponse(blackboard_auth_url)


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request):
    """OAuth callback from Blackboard"""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    logger.info(f"OAuth: Callback - state={state[:30] if state else 'None'}...")
    
    if error:
        logger.error(f"OAuth: Blackboard error: {error}")
        return JSONResponse({"error": error}, status_code=400)
    
    if not code or not state:
        return JSONResponse({"error": "missing_parameters"}, status_code=400)
    
    # Check for duplicate callback
    completed = await get_completed_state(state)
    if completed:
        logger.info(f"OAuth: Duplicate callback - showing success")
        return JSONResponse({
            "status": "success",
            "message": "✅ Already authenticated! Close this window and return to Claude."
        })
    
    # Get pending auth
    original = await get_pending_auth(state)
    if not original:
        token_count = await count_tokens()
        if token_count > 0:
            logger.info(f"OAuth: Unknown state but have {token_count} active tokens")
            return JSONResponse({
                "status": "success",
                "message": "✅ Authentication successful! Close this window and return to Claude."
            })
        
        logger.error(f"OAuth: Invalid state")
        return JSONResponse({"error": "invalid_state"}, status_code=400)
    
    is_user_login = original.get("is_user_login", False)
    
    try:
        # Exchange code with Blackboard
        logger.info("OAuth: Exchanging code for token...")
        
        credentials = f"{BLACKBOARD_APP_KEY}:{BLACKBOARD_APP_SECRET}"
        auth_header = base64.b64encode(credentials.encode()).decode()
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
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
            
            if response.status_code != 200:
                logger.error(f"OAuth: Token exchange failed: {response.text}")
                return JSONResponse({"error": "token_exchange_failed"}, status_code=500)
            
            bb_token = response.json()
            access_token = bb_token["access_token"]
            user_id = bb_token.get("user_id", "unknown")
            logger.info(f"OAuth: ✅ Got token for user {user_id}")
        
        # Store token
        token_record = {
            "access_token": access_token,
            "token_type": bb_token.get("token_type", "bearer"),
            "expires_in": bb_token.get("expires_in", 3600),
            "refresh_token": bb_token.get("refresh_token"),
            "user_id": user_id,
            "timestamp": time.time()
        }
        await store_token(access_token, token_record)
        
        # Generate code for Claude
        claude_code = secrets.token_urlsafe(32)
        await store_auth_code(claude_code, token_record)
        
        # Mark state as completed
        await store_completed_state(state, {
            "claude_code": claude_code,
            "redirect_uri": original["redirect_uri"],
            "original_state": original["original_state"]
        })
        
        # Delete pending auth
        await delete_pending_auth(state)
        
        # Redirect
        if is_user_login:
            redirect_url = f"{original['redirect_uri']}?code={claude_code}"
        else:
            redirect_url = f"{original['redirect_uri']}?code={claude_code}&state={original['original_state']}"
        
        logger.info(f"OAuth: Redirecting to {redirect_url[:60]}...")
        return RedirectResponse(redirect_url)
        
    except Exception as e:
        logger.exception(f"OAuth: Error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request):
    """Token endpoint for Claude"""
    form = await request.form()
    code = form.get("code")
    
    logger.info(f"OAuth: Token request from Claude")
    
    if not code:
        return JSONResponse({"error": "missing_code"}, status_code=400)
    
    token_data = await get_and_delete_auth_code(code)
    if not token_data:
        logger.error(f"OAuth: Invalid auth code")
        return JSONResponse({"error": "invalid_code"}, status_code=400)
    
    access_token = token_data["access_token"]
    
    # Ensure token is stored
    existing = await get_token(access_token)
    if not existing:
        await store_token(access_token, token_data)
    
    logger.info(f"OAuth: ✅ Issued token to Claude for user {token_data.get('user_id')}")
    
    return JSONResponse({
        "access_token": access_token,
        "token_type": token_data["token_type"],
        "expires_in": token_data["expires_in"],
        "scope": "read write"
    })


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def protected_resource_config(request):
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
    token, token_data, authenticated = get_user_session()
    
    if not authenticated or not token:
        return get_auth_url()
    
    user_id = token_data.get("user_id", "unknown") if token_data else "unknown"
    logger.info(f"Tool get_my_courses: Fetching for user {user_id}")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses?limit=100",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            if response.status_code == 401:
                await delete_token(token)
                return "⚠️ Session expired.\n\n" + get_auth_url()
            
            if response.status_code != 200:
                return f"Error: {response.status_code} - {response.text}"
            
            courses = response.json().get("results", [])
            
            if not courses:
                return "No courses found."
            
            result = f"📚 Found {len(courses)} courses:\n\n"
            for course in courses:
                result += f"• **{course.get('name', 'Unnamed')}** (ID: `{course.get('id')}`)\n"
            
            return result
            
    except Exception as e:
        logger.exception(f"Tool get_my_courses: Error: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_course_assignments(course_id: str) -> str:
    """Get assignments for a specific course."""
    token, token_data, authenticated = get_user_session()
    
    if not authenticated or not token:
        return get_auth_url()
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses/{course_id}/gradebook/columns",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            if response.status_code == 401:
                await delete_token(token)
                return "⚠️ Session expired.\n\n" + get_auth_url()
            
            if response.status_code != 200:
                return f"Error: {response.status_code} - {response.text}"
            
            columns = response.json().get("results", [])
            assignments = [c for c in columns if c.get("grading", {}).get("due")]
            
            if not assignments:
                return f"No assignments with due dates found in course `{course_id}`"
            
            result = f"📝 Found {len(assignments)} assignments:\n\n"
            for a in assignments:
                result += f"• **{a.get('name', 'Unnamed')}** ({a.get('score', {}).get('possible', '?')} pts) - Due: {a.get('grading', {}).get('due', 'N/A')}\n"
            
            return result
            
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def get_current_user() -> str:
    """Get information about the currently authenticated Blackboard user."""
    token, token_data, authenticated = get_user_session()
    
    if not authenticated or not token:
        return get_auth_url()
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            if response.status_code == 401:
                await delete_token(token)
                return "⚠️ Session expired.\n\n" + get_auth_url()
            
            if response.status_code != 200:
                return f"Error: {response.status_code} - {response.text}"
            
            user = response.json()
            
            result = "👤 **Current User**\n\n"
            result += f"• **User ID:** `{user.get('id', 'N/A')}`\n"
            result += f"• **Username:** `{user.get('userName', 'N/A')}`\n"
            
            name = user.get('name', {})
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
    token, token_data, authenticated = get_user_session()
    
    if authenticated and token:
        await delete_token(token)
        return "✅ Successfully logged out."
    
    return "ℹ️ You are not currently logged in."


@mcp.tool()
async def check_auth_status() -> str:
    """Check your current authentication status with Blackboard."""
    logger.info("Tool check_auth_status: Starting")
    
    token_count = await count_tokens()
    logger.info(f"Tool check_auth_status: Storage has {token_count} tokens")
    
    token, token_data, authenticated = get_user_session()
    
    if not authenticated or not token_data:
        return "🔒 **Not Authenticated**\n\n" + get_auth_url()
    
    user_id = token_data.get("user_id", "unknown")
    expires_in = token_data.get("expires_in", TOKEN_EXPIRY_SECONDS)
    
    return (
        f"✅ **Authenticated**\n\n"
        f"• **User ID:** `{user_id}`\n"
        f"• **Token expires in:** ~{expires_in // 60} minutes"
    )


@mcp.tool()
async def debug_session() -> str:
    """Debug tool to see session and storage information."""
    result = "🔧 **Debug Info**\n\n"
    
    # Storage status
    try:
        token_count = await count_tokens()
        result += f"**Storage:** DiskStore at `{STORAGE_DIR}`\n"
        result += f"• Active tokens: {token_count}\n\n"
    except Exception as e:
        result += f"**Storage:** ❌ Error: {e}\n\n"
    
    # Context/session info
    token, token_data, authenticated = get_user_session()
    result += f"**Session:**\n"
    result += f"• Authenticated: {authenticated}\n"
    result += f"• User ID: {token_data.get('user_id', 'N/A') if token_data else 'N/A'}\n\n"
    
    # Headers
    try:
        headers = get_http_headers()
        auth = headers.get("authorization", "")
        result += f"**Headers:**\n"
        result += f"• Auth header: {'Bearer token present' if auth.startswith('Bearer ') else 'Missing'}\n"
    except Exception as e:
        result += f"**Headers:** Error: {e}\n"
    
    return result


@mcp.tool()
async def check_config() -> str:
    """Check server configuration."""
    return (
        f"⚙️ **Server Configuration**\n\n"
        f"• **Blackboard URL:** `{BLACKBOARD_URL}`\n"
        f"• **App Key:** `{BLACKBOARD_APP_KEY[:8] if BLACKBOARD_APP_KEY else 'NOT SET'}...`\n"
        f"• **Server URL:** `{SERVER_URL}`\n"
        f"• **Storage:** DiskStore at `{STORAGE_DIR}`\n"
    )
