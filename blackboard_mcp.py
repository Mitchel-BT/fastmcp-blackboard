"""
Blackboard MCP Server - Cloud Version with Custom OAuth
Uses FastMCP middleware for session isolation via Bearer token
"""
import os
import base64
import secrets
import time
import logging
import httpx
from fastmcp import FastMCP, Context
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_http_headers, get_context
from fastmcp.exceptions import ToolError
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

# Token expiry time (1 hour default from Blackboard)
TOKEN_EXPIRY_SECONDS = 3600

# ============================================================================
# TOKEN STORAGE
# ============================================================================
# Key: access_token (from Blackboard) -> token_data dict
_pending_auths = {}
_tokens = {}


def cleanup_expired_tokens():
    """Remove expired tokens from storage"""
    current_time = time.time()
    expired_keys = []
    
    for key, token_data in _tokens.items():
        if key.startswith("code:"):
            if current_time - token_data.get("timestamp", 0) > 600:
                expired_keys.append(key)
        else:
            timestamp = token_data.get("timestamp", 0)
            expires_in = token_data.get("expires_in", TOKEN_EXPIRY_SECONDS)
            if current_time - timestamp > expires_in:
                expired_keys.append(key)
    
    for key in expired_keys:
        del _tokens[key]
        logger.info(f"Cleaned up expired token: {key[:20]}...")


def get_auth_url() -> str:
    """Generate the authentication URL for users to log in"""
    return (
        f"🔐 **Authentication Required**\n\n"
        f"Please log in to Blackboard by clicking the link below:\n\n"
        f"👉 [{SERVER_URL}/oauth/authorize]({SERVER_URL}/oauth/authorize?client_id=claude&redirect_uri={SERVER_URL}/oauth/callback&response_type=code&state=auth&scope=read%20write%20offline)\n\n"
        f"After logging in, return here and try your request again."
    )


# ============================================================================
# AUTHENTICATION MIDDLEWARE
# ============================================================================

class BlackboardAuthMiddleware(Middleware):
    """
    Middleware that extracts Bearer token from Authorization header
    and loads user session data into context state.
    """
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Intercept tool calls to inject user session data"""
        logger.debug(f"Middleware: Processing tool call: {context.message.name}")
        
        # Try to get the Authorization header
        try:
            headers = get_http_headers()
            auth_header = headers.get("authorization", "") or headers.get("Authorization", "")
            logger.debug(f"Middleware: Auth header present: {bool(auth_header)}")
            
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]  # Remove "Bearer " prefix
                logger.debug(f"Middleware: Found Bearer token: {token[:15]}...")
                
                # Look up the token in our storage
                cleanup_expired_tokens()
                token_data = _tokens.get(token)
                
                if token_data:
                    # Store session data in context state for tools to access
                    context.fastmcp_context.set_state("access_token", token)
                    context.fastmcp_context.set_state("user_id", token_data.get("user_id"))
                    context.fastmcp_context.set_state("token_data", token_data)
                    context.fastmcp_context.set_state("authenticated", True)
                    logger.info(f"Middleware: Authenticated user {token_data.get('user_id')} for tool {context.message.name}")
                else:
                    logger.warning(f"Middleware: Token not found in storage: {token[:15]}...")
                    context.fastmcp_context.set_state("authenticated", False)
            else:
                logger.debug("Middleware: No Bearer token in Authorization header")
                context.fastmcp_context.set_state("authenticated", False)
                
        except Exception as e:
            logger.error(f"Middleware: Error extracting auth: {e}")
            context.fastmcp_context.set_state("authenticated", False)
        
        return await call_next(context)
    
    async def on_message(self, context: MiddlewareContext, call_next):
        """Log all MCP messages for debugging"""
        logger.debug(f"Middleware: MCP message: {context.method} from {context.source}")
        return await call_next(context)


# ============================================================================
# MCP SERVER SETUP
# ============================================================================
mcp = FastMCP("Blackboard")

# Add authentication middleware
mcp.add_middleware(BlackboardAuthMiddleware())


# ============================================================================
# HELPER FUNCTIONS FOR TOOLS
# ============================================================================

def get_user_session() -> tuple[str | None, dict | None, bool]:
    """
    Get the current user's session from context state.
    Returns (access_token, token_data, is_authenticated)
    """
    try:
        ctx = get_context()
        authenticated = ctx.get_state("authenticated")
        
        if authenticated:
            token = ctx.get_state("access_token")
            token_data = ctx.get_state("token_data")
            return token, token_data, True
        
        # Fallback: Check if there are any tokens at all (backwards compatibility)
        cleanup_expired_tokens()
        for key, data in _tokens.items():
            if not key.startswith("code:") and "access_token" in data:
                logger.warning("Using fallback token lookup - middleware may not be working")
                return data.get("access_token"), data, True
                
    except Exception as e:
        logger.error(f"Error getting user session: {e}")
    
    return None, None, False


# ============================================================================
# OAUTH ROUTES
# ============================================================================

@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_config(request):
    """OAuth server configuration"""
    logger.info("OAuth: Server metadata requested")
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
    
    logger.info(f"OAuth: Authorization request from client_id={client_id}")
    logger.debug(f"OAuth: Redirect URI: {redirect_uri}")
    
    # Generate state to track this flow
    our_state = secrets.token_urlsafe(32)
    
    _pending_auths[our_state] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "timestamp": time.time()
    }
    
    # Clean up old pending auths (older than 10 minutes)
    current_time = time.time()
    old_states = [s for s, data in _pending_auths.items() 
                  if current_time - data.get("timestamp", 0) > 600]
    for old_state in old_states:
        del _pending_auths[old_state]
        logger.debug(f"OAuth: Cleaned up old pending auth state")
    
    # Redirect to Blackboard
    blackboard_auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?redirect_uri={SERVER_URL}/oauth/callback"
        f"&response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&scope=read%20write%20offline"
        f"&state={our_state}"
    )
    
    logger.info(f"OAuth: Redirecting to Blackboard for authentication")
    return RedirectResponse(blackboard_auth_url)


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request):
    """OAuth callback from Blackboard"""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    logger.info(f"OAuth: Callback received from Blackboard")
    
    if error:
        logger.error(f"OAuth: Blackboard returned error: {error}")
        return JSONResponse({"error": error}, status_code=400)
    
    if not code or not state:
        logger.error("OAuth: Missing code or state in callback")
        return JSONResponse({"error": "missing_parameters"}, status_code=400)
    
    original = _pending_auths.get(state)
    if not original:
        logger.error("OAuth: Invalid state - possible CSRF or expired flow")
        return JSONResponse({"error": "invalid_state"}, status_code=400)
    
    del _pending_auths[state]
    
    try:
        # Exchange code with Blackboard
        logger.info("OAuth: Exchanging authorization code for token...")
        
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
                logger.error(f"OAuth: Token exchange failed: {response.status_code} - {response.text}")
                return JSONResponse({"error": "token_exchange_failed"}, status_code=500)
            
            token_data = response.json()
            user_id = token_data.get("user_id", "unknown")
            logger.info(f"OAuth: Successfully obtained token for user {user_id}")
        
        # Generate code for Claude
        claude_code = secrets.token_urlsafe(32)
        
        # Store temporarily by code
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
        logger.info(f"OAuth: Redirecting back to Claude with authorization code")
        return RedirectResponse(redirect_url)
        
    except Exception as e:
        logger.exception(f"OAuth: Error during token exchange: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request):
    """Token endpoint for Claude"""
    form = await request.form()
    code = form.get("code")
    
    logger.info("OAuth: Token exchange request from Claude")
    
    if not code:
        logger.error("OAuth: Missing code in token request")
        return JSONResponse({"error": "missing_code"}, status_code=400)
    
    code_key = f"code:{code}"
    token_data = _tokens.get(code_key)
    
    if not token_data:
        logger.error("OAuth: Invalid or expired authorization code")
        return JSONResponse({"error": "invalid_code"}, status_code=400)
    
    # Remove the code-based entry (one-time use)
    del _tokens[code_key]
    
    # Store by the Blackboard access_token for session lookup
    access_token = token_data["access_token"]
    _tokens[access_token] = token_data
    
    logger.info(f"OAuth: Issued token to Claude for user {token_data.get('user_id')}")
    
    # Return the Blackboard token - Claude will send this as Bearer token
    return JSONResponse({
        "access_token": access_token,
        "token_type": token_data["token_type"],
        "expires_in": token_data["expires_in"],
        "scope": "read write offline"
    })


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def protected_resource_config(request):
    """Indicate that this resource requires OAuth"""
    logger.debug("OAuth: Protected resource metadata requested")
    return JSONResponse({
        "resource": SERVER_URL,
        "authorization_servers": [SERVER_URL]
    })


# ============================================================================
# MCP TOOLS
# ============================================================================

@mcp.tool()
async def get_my_courses() -> str:
    """
    Get all courses you have access to in Blackboard.
    Requires authentication.
    """
    token, token_data, authenticated = get_user_session()
    
    if not authenticated or not token:
        logger.info("Tool get_my_courses: User not authenticated")
        return get_auth_url()
    
    user_id = token_data.get("user_id", "unknown") if token_data else "unknown"
    logger.info(f"Tool get_my_courses: Fetching courses for user {user_id}")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses?limit=100",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            logger.debug(f"Tool get_my_courses: Blackboard API response: {response.status_code}")
            
            if response.status_code == 401:
                if token in _tokens:
                    del _tokens[token]
                logger.warning(f"Tool get_my_courses: Token expired for user {user_id}")
                return "⚠️ Your session has expired.\n\n" + get_auth_url()
            
            if response.status_code != 200:
                logger.error(f"Tool get_my_courses: API error {response.status_code}")
                return f"Error: {response.status_code} - {response.text}"
            
            data = response.json()
            courses = data.get("results", [])
            
            if not courses:
                return "No courses found."
            
            result = f"📚 Found {len(courses)} courses:\n\n"
            for course in courses:
                result += f"• **{course.get('name', 'Unnamed')}** (ID: `{course.get('id')}`)\n"
            
            logger.info(f"Tool get_my_courses: Returned {len(courses)} courses for user {user_id}")
            return result
            
    except Exception as e:
        logger.exception(f"Tool get_my_courses: Error: {e}")
        return f"Error calling Blackboard API: {str(e)}"


@mcp.tool()
async def get_course_assignments(course_id: str) -> str:
    """
    Get assignments for a specific course.
    
    Args:
        course_id: The course ID from get_my_courses (e.g., "_123_1")
    """
    token, token_data, authenticated = get_user_session()
    
    if not authenticated or not token:
        logger.info("Tool get_course_assignments: User not authenticated")
        return get_auth_url()
    
    user_id = token_data.get("user_id", "unknown") if token_data else "unknown"
    logger.info(f"Tool get_course_assignments: Fetching assignments for course {course_id}, user {user_id}")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses/{course_id}/gradebook/columns",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            if response.status_code == 401:
                if token in _tokens:
                    del _tokens[token]
                logger.warning(f"Tool get_course_assignments: Token expired for user {user_id}")
                return "⚠️ Your session has expired.\n\n" + get_auth_url()
            
            if response.status_code != 200:
                logger.error(f"Tool get_course_assignments: API error {response.status_code}")
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
            
            logger.info(f"Tool get_course_assignments: Returned {len(assignments)} assignments")
            return result
            
    except Exception as e:
        logger.exception(f"Tool get_course_assignments: Error: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_current_user() -> str:
    """
    Get information about the currently authenticated Blackboard user.
    Returns details like name, username, email, and user ID.
    """
    token, token_data, authenticated = get_user_session()
    
    if not authenticated or not token:
        logger.info("Tool get_current_user: User not authenticated")
        return get_auth_url()
    
    logger.info("Tool get_current_user: Fetching current user info")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            if response.status_code == 401:
                if token in _tokens:
                    del _tokens[token]
                logger.warning("Tool get_current_user: Token expired")
                return "⚠️ Your session has expired.\n\n" + get_auth_url()
            
            if response.status_code != 200:
                logger.error(f"Tool get_current_user: API error {response.status_code}")
                return f"Error: {response.status_code} - {response.text}"
            
            user = response.json()
            
            result = "👤 **Current Authenticated User**\n\n"
            result += f"• **User ID:** `{user.get('id', 'N/A')}`\n"
            result += f"• **Username:** `{user.get('userName', 'N/A')}`\n"
            
            name = user.get('name', {})
            given = name.get('given', '')
            family = name.get('family', '')
            if given or family:
                result += f"• **Name:** {given} {family}\n"
            
            contact = user.get('contact', {})
            email = contact.get('email', '')
            if email:
                result += f"• **Email:** {email}\n"
            
            external_id = user.get('externalId', '')
            if external_id:
                result += f"• **External ID:** `{external_id}`\n"
            
            student_id = user.get('studentId', '')
            if student_id:
                result += f"• **Student ID:** `{student_id}`\n"
            
            inst_roles = user.get('institutionRoleIds', [])
            if inst_roles:
                result += f"• **Institution Roles:** {', '.join(inst_roles)}\n"
            
            availability = user.get('availability', {})
            available = availability.get('available', 'Unknown')
            result += f"• **Account Status:** {available}\n"
            
            logger.info(f"Tool get_current_user: Returned info for {user.get('userName')}")
            return result
            
    except Exception as e:
        logger.exception(f"Tool get_current_user: Error: {e}")
        return f"Error calling Blackboard API: {str(e)}"


@mcp.tool()
async def logout() -> str:
    """
    Log out from Blackboard by clearing your authentication token.
    You will need to re-authenticate to use Blackboard tools again.
    """
    token, token_data, authenticated = get_user_session()
    
    if authenticated and token and token in _tokens:
        user_id = token_data.get("user_id", "unknown") if token_data else "unknown"
        del _tokens[token]
        logger.info(f"Tool logout: Logged out user {user_id}")
        return "✅ Successfully logged out from Blackboard.\n\nYou will need to re-authenticate to use Blackboard tools again."
    
    logger.info("Tool logout: No active session to log out")
    return "ℹ️ You are not currently logged in."


@mcp.tool()
async def check_auth_status() -> str:
    """
    Check your current authentication status with Blackboard.
    """
    token, token_data, authenticated = get_user_session()
    
    if not authenticated or not token_data:
        logger.info("Tool check_auth_status: Not authenticated")
        return "🔒 **Not Authenticated**\n\n" + get_auth_url()
    
    timestamp = token_data.get("timestamp", 0)
    expires_in = token_data.get("expires_in", TOKEN_EXPIRY_SECONDS)
    elapsed = time.time() - timestamp
    remaining = expires_in - elapsed
    
    if remaining <= 0:
        if token in _tokens:
            del _tokens[token]
        logger.info("Tool check_auth_status: Session expired")
        return "⏰ **Session Expired**\n\n" + get_auth_url()
    
    user_id = token_data.get("user_id", "unknown")
    minutes_remaining = int(remaining / 60)
    
    logger.info(f"Tool check_auth_status: User {user_id} authenticated, {minutes_remaining}m remaining")
    return (
        f"✅ **Authenticated**\n\n"
        f"• **User ID:** `{user_id}`\n"
        f"• **Session expires in:** {minutes_remaining} minutes"
    )


@mcp.tool()
async def debug_session() -> str:
    """
    Debug tool to see session and token information.
    Useful for troubleshooting authentication issues.
    """
    cleanup_expired_tokens()
    
    # Count tokens
    code_tokens = sum(1 for k in _tokens if k.startswith("code:"))
    session_tokens = len(_tokens) - code_tokens
    
    # Try to get current session info
    token, token_data, authenticated = get_user_session()
    
    # Try to get context state
    ctx_info = "Unable to access"
    try:
        ctx = get_context()
        ctx_authenticated = ctx.get_state("authenticated")
        ctx_user_id = ctx.get_state("user_id")
        ctx_info = f"authenticated={ctx_authenticated}, user_id={ctx_user_id}"
    except Exception as e:
        ctx_info = f"Error: {e}"
    
    # Try to get headers
    headers_info = "Unable to access"
    try:
        headers = get_http_headers()
        auth_header = headers.get("authorization", "")
        headers_info = f"Auth header present: {bool(auth_header)}, starts with Bearer: {auth_header.startswith('Bearer ') if auth_header else False}"
    except Exception as e:
        headers_info = f"Error: {e}"
    
    result = (
        f"🔧 **Debug Session Info**\n\n"
        f"**Token Storage:**\n"
        f"• Pending auth codes: {code_tokens}\n"
        f"• Active sessions: {session_tokens}\n"
        f"• Pending OAuth flows: {len(_pending_auths)}\n\n"
        f"**Current Session:**\n"
        f"• Authenticated: {authenticated}\n"
        f"• User ID: {token_data.get('user_id', 'N/A') if token_data else 'N/A'}\n\n"
        f"**Context State:**\n"
        f"• {ctx_info}\n\n"
        f"**HTTP Headers:**\n"
        f"• {headers_info}\n"
    )
    
    logger.debug(f"Tool debug_session: {result}")
    return result


@mcp.tool()
async def check_config() -> str:
    """Check server configuration and OAuth endpoints"""
    return (
        f"⚙️ **Server Configuration**\n\n"
        f"• **Blackboard URL:** `{BLACKBOARD_URL}`\n"
        f"• **App Key:** `{BLACKBOARD_APP_KEY[:8] if BLACKBOARD_APP_KEY else 'NOT SET'}...`\n"
        f"• **Server URL:** `{SERVER_URL}`\n\n"
        f"**OAuth Endpoints:**\n"
        f"• Discovery: `{SERVER_URL}/.well-known/oauth-authorization-server`\n"
        f"• Authorize: `{SERVER_URL}/oauth/authorize`\n"
        f"• Token: `{SERVER_URL}/oauth/token`\n"
        f"• Callback: `{SERVER_URL}/oauth/callback`\n"
    )
