"""
Blackboard MCP Server - Simple Working Version
Based on the code that was working on January 15th, 2026
No middleware, no complex session management - just works!
"""
import os
import base64
import secrets
import time
import logging
import httpx
from fastmcp import FastMCP
from starlette.responses import RedirectResponse, JSONResponse

# ============================================================================
# LOGGING SETUP
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
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

TOKEN_EXPIRY_SECONDS = 3600

# ============================================================================
# SIMPLE TOKEN STORAGE (in-memory)
# ============================================================================
_pending_auths = {}  # state -> {redirect_uri, original_state, timestamp}
_tokens = {}  # Various token storage: "code:xxx" for auth codes, access_token for sessions


def cleanup_expired_tokens():
    """Remove expired tokens"""
    current_time = time.time()
    expired = []
    
    for key, data in _tokens.items():
        timestamp = data.get("timestamp", 0)
        if key.startswith("code:"):
            # Auth codes expire in 10 minutes
            if current_time - timestamp > 600:
                expired.append(key)
        else:
            # Access tokens expire based on expires_in
            expires_in = data.get("expires_in", TOKEN_EXPIRY_SECONDS)
            if current_time - timestamp > expires_in:
                expired.append(key)
    
    for key in expired:
        del _tokens[key]
        logger.info(f"Cleaned up expired token: {key[:20]}...")


def get_valid_token():
    """Find any valid token in storage - simple approach that works!"""
    cleanup_expired_tokens()
    
    for key, data in _tokens.items():
        if not key.startswith("code:") and "access_token" in data:
            return data
    
    return None


def get_auth_url() -> str:
    """Generate the authentication URL"""
    return (
        f"🔐 **Authentication Required**\n\n"
        f"Please log in to Blackboard by clicking the link below:\n\n"
        f"👉 [{SERVER_URL}/oauth/authorize]({SERVER_URL}/oauth/authorize?client_id=claude&redirect_uri={SERVER_URL}/oauth/callback&response_type=code&state=auth&scope=read%20write%20offline)\n\n"
        f"After logging in, return here and try your request again."
    )


# ============================================================================
# MCP SERVER
# ============================================================================
mcp = FastMCP("Blackboard")


# ============================================================================
# OAUTH ROUTES
# ============================================================================

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
    """OAuth authorization - redirects to Blackboard"""
    client_id = request.query_params.get("client_id")
    redirect_uri = request.query_params.get("redirect_uri")
    state = request.query_params.get("state")
    
    logger.info(f"OAuth: Authorization request from client_id={client_id}")
    
    # Generate our own state to track this flow
    our_state = secrets.token_urlsafe(32)
    
    _pending_auths[our_state] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "timestamp": time.time()
    }
    
    # Clean up old pending auths
    current_time = time.time()
    old_states = [s for s, data in _pending_auths.items() 
                  if current_time - data.get("timestamp", 0) > 600]
    for old_state in old_states:
        del _pending_auths[old_state]
    
    # Redirect to Blackboard
    blackboard_auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?redirect_uri={SERVER_URL}/oauth/callback"
        f"&response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&scope=read%20write%20offline"
        f"&state={our_state}"
    )
    
    logger.info("OAuth: Redirecting to Blackboard")
    return RedirectResponse(blackboard_auth_url)


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request):
    """OAuth callback from Blackboard"""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    logger.info("OAuth: Callback received")
    
    if error:
        logger.error(f"OAuth: Error from Blackboard: {error}")
        return JSONResponse({"error": error}, status_code=400)
    
    if not code or not state:
        return JSONResponse({"error": "missing_parameters"}, status_code=400)
    
    original = _pending_auths.get(state)
    if not original:
        return JSONResponse({"error": "invalid_state"}, status_code=400)
    
    del _pending_auths[state]
    
    try:
        # Exchange code with Blackboard
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
            
            token_data = response.json()
            user_id = token_data.get("user_id", "unknown")
            logger.info(f"OAuth: Got token for user {user_id}")
        
        # Generate code for Claude
        claude_code = secrets.token_urlsafe(32)
        
        # Store the token data with the code
        _tokens[f"code:{claude_code}"] = {
            "access_token": token_data["access_token"],
            "token_type": token_data.get("token_type", "bearer"),
            "expires_in": token_data.get("expires_in", 3600),
            "refresh_token": token_data.get("refresh_token"),
            "user_id": user_id,
            "timestamp": time.time()
        }
        
        # Redirect back to Claude
        redirect_url = f"{original['redirect_uri']}?code={claude_code}&state={original['state']}"
        logger.info("OAuth: Redirecting back to Claude")
        return RedirectResponse(redirect_url)
        
    except Exception as e:
        logger.exception(f"OAuth: Error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request):
    """Token endpoint for Claude"""
    form = await request.form()
    code = form.get("code")
    
    logger.info("OAuth: Token request from Claude")
    
    if not code:
        return JSONResponse({"error": "missing_code"}, status_code=400)
    
    code_key = f"code:{code}"
    token_data = _tokens.get(code_key)
    
    if not token_data:
        return JSONResponse({"error": "invalid_code"}, status_code=400)
    
    # Remove code (one-time use)
    del _tokens[code_key]
    
    # Store by access_token for later lookup
    access_token = token_data["access_token"]
    _tokens[access_token] = token_data
    
    logger.info(f"OAuth: Issued token for user {token_data.get('user_id')}")
    
    return JSONResponse({
        "access_token": access_token,
        "token_type": token_data["token_type"],
        "expires_in": token_data["expires_in"],
        "scope": "read write offline"
    })


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def protected_resource_config(request):
    return JSONResponse({
        "resource": SERVER_URL,
        "authorization_servers": [SERVER_URL]
    })


# ============================================================================
# MCP TOOLS - Simple versions that just work!
# ============================================================================

@mcp.tool()
async def get_my_courses() -> str:
    """Get all courses you have access to in Blackboard."""
    token_data = get_valid_token()
    
    if not token_data:
        return get_auth_url()
    
    access_token = token_data["access_token"]
    logger.info(f"get_my_courses: Using token for user {token_data.get('user_id')}")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses?limit=100",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=30.0
            )
            
            if response.status_code == 401:
                # Token expired, remove it
                if access_token in _tokens:
                    del _tokens[access_token]
                return "⚠️ Your session has expired.\n\n" + get_auth_url()
            
            if response.status_code != 200:
                return f"Error: {response.status_code} - {response.text}"
            
            data = response.json()
            courses = data.get("results", [])
            
            if not courses:
                return "No courses found."
            
            result = f"📚 Found {len(courses)} courses:\n\n"
            for course in courses:
                result += f"• **{course.get('name', 'Unnamed')}** (ID: `{course.get('id')}`)\n"
            
            return result
            
    except Exception as e:
        logger.exception(f"get_my_courses error: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_course_assignments(course_id: str) -> str:
    """Get assignments for a specific course."""
    token_data = get_valid_token()
    
    if not token_data:
        return get_auth_url()
    
    access_token = token_data["access_token"]
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses/{course_id}/gradebook/columns",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=30.0
            )
            
            if response.status_code == 401:
                if access_token in _tokens:
                    del _tokens[access_token]
                return "⚠️ Your session has expired.\n\n" + get_auth_url()
            
            if response.status_code != 200:
                return f"Error: {response.status_code} - {response.text}"
            
            data = response.json()
            columns = data.get("results", [])
            assignments = [c for c in columns if c.get("grading", {}).get("due")]
            
            if not assignments:
                return f"No assignments with due dates found in course `{course_id}`"
            
            result = f"📝 Found {len(assignments)} assignments:\n\n"
            for assignment in assignments:
                name = assignment.get("name", "Unnamed")
                points = assignment.get("score", {}).get("possible", "?")
                due = assignment.get("grading", {}).get("due", "No due date")
                result += f"• **{name}** ({points} points) - Due: {due}\n"
            
            return result
            
    except Exception as e:
        logger.exception(f"get_course_assignments error: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_current_user() -> str:
    """Get information about the currently authenticated user."""
    token_data = get_valid_token()
    
    if not token_data:
        return get_auth_url()
    
    access_token = token_data["access_token"]
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=30.0
            )
            
            if response.status_code == 401:
                if access_token in _tokens:
                    del _tokens[access_token]
                return "⚠️ Your session has expired.\n\n" + get_auth_url()
            
            if response.status_code != 200:
                return f"Error: {response.status_code} - {response.text}"
            
            user = response.json()
            
            result = "👤 **Current User**\n\n"
            result += f"• **User ID:** `{user.get('id', 'N/A')}`\n"
            result += f"• **Username:** `{user.get('userName', 'N/A')}`\n"
            
            name = user.get('name', {})
            given = name.get('given', '')
            family = name.get('family', '')
            if given or family:
                result += f"• **Name:** {given} {family}\n"
            
            email = user.get('contact', {}).get('email', '')
            if email:
                result += f"• **Email:** {email}\n"
            
            return result
            
    except Exception as e:
        logger.exception(f"get_current_user error: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def logout() -> str:
    """Log out from Blackboard by clearing all stored tokens."""
    cleanup_expired_tokens()
    
    # Find and remove all session tokens (not code: prefixed)
    to_delete = [k for k in _tokens.keys() if not k.startswith("code:")]
    
    for key in to_delete:
        del _tokens[key]
    
    logger.info(f"Logged out, removed {len(to_delete)} tokens")
    return "✅ Successfully logged out from Blackboard."


@mcp.tool()
async def check_auth_status() -> str:
    """Check your current authentication status."""
    token_data = get_valid_token()
    
    if not token_data:
        return "🔒 **Not Authenticated**\n\n" + get_auth_url()
    
    timestamp = token_data.get("timestamp", 0)
    expires_in = token_data.get("expires_in", TOKEN_EXPIRY_SECONDS)
    elapsed = time.time() - timestamp
    remaining = expires_in - elapsed
    
    if remaining <= 0:
        return "⏰ **Session Expired**\n\n" + get_auth_url()
    
    user_id = token_data.get("user_id", "unknown")
    minutes_remaining = int(remaining / 60)
    
    return (
        f"✅ **Authenticated**\n\n"
        f"• **User ID:** `{user_id}`\n"
        f"• **Session expires in:** {minutes_remaining} minutes"
    )


@mcp.tool()
async def debug_tokens() -> str:
    """Debug tool to see token storage status."""
    cleanup_expired_tokens()
    
    code_tokens = sum(1 for k in _tokens if k.startswith("code:"))
    session_tokens = len(_tokens) - code_tokens
    
    return (
        f"🔧 **Token Storage**\n\n"
        f"• Pending auth codes: {code_tokens}\n"
        f"• Active sessions: {session_tokens}\n"
        f"• Pending OAuth flows: {len(_pending_auths)}"
    )


@mcp.tool()
async def check_config() -> str:
    """Check server configuration."""
    return (
        f"⚙️ **Configuration**\n\n"
        f"• **Blackboard URL:** `{BLACKBOARD_URL}`\n"
        f"• **App Key:** `{BLACKBOARD_APP_KEY[:8] if BLACKBOARD_APP_KEY else 'NOT SET'}...`\n"
        f"• **Server URL:** `{SERVER_URL}`\n"
    )
