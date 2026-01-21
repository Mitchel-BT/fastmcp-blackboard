"""
Blackboard MCP Server - Cloud Version with Server-Side Token Storage
Stores Blackboard access tokens on server, issues opaque session tokens to Claude
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
# Pending OAuth flows: state -> flow data
_pending_auths = {}

# Authorization codes (one-time use): code -> session_token
_auth_codes = {}

# Session storage: session_token -> { blackboard_access_token, refresh_token, user_id, ... }
_sessions = {}


def cleanup_expired():
    """Remove expired tokens and sessions from storage"""
    current_time = time.time()
    
    # Clean up expired auth codes (10 minute TTL)
    expired_codes = [
        code for code, data in _auth_codes.items()
        if current_time - data.get("timestamp", 0) > 600
    ]
    for code in expired_codes:
        del _auth_codes[code]
        logger.debug(f"Cleaned up expired auth code")
    
    # Clean up expired sessions
    expired_sessions = [
        token for token, data in _sessions.items()
        if current_time - data.get("timestamp", 0) > data.get("expires_in", TOKEN_EXPIRY_SECONDS)
    ]
    for token in expired_sessions:
        del _sessions[token]
        logger.info(f"Cleaned up expired session: {token[:20]}...")
    
    # Clean up old pending auths (10 minute TTL)
    expired_pending = [
        state for state, data in _pending_auths.items()
        if current_time - data.get("timestamp", 0) > 600
    ]
    for state in expired_pending:
        del _pending_auths[state]


def get_auth_url() -> str:
    """Generate the authentication URL for users to log in"""
    return (
        f"🔐 **Authentication Required**\n\n"
        f"Please log in to Blackboard by clicking the link below:\n\n"
        f"👉 [{SERVER_URL}/oauth/authorize]({SERVER_URL}/oauth/authorize?client_id=claude&redirect_uri={SERVER_URL}/oauth/callback&response_type=code&state=auth&scope=read%20write%20offline)\n\n"
        f"After logging in, return here and try your request again."
    )


def generate_session_token() -> str:
    """Generate a cryptographically secure session token"""
    return secrets.token_urlsafe(48)  # 64 characters, 384 bits of entropy


# ============================================================================
# AUTHENTICATION MIDDLEWARE
# ============================================================================

class BlackboardAuthMiddleware(Middleware):
    """
    Middleware that extracts Bearer token from Authorization header
    and loads user session data into context state.
    
    The Bearer token is our opaque session token, NOT the Blackboard access token.
    """
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Intercept tool calls to inject user session data"""
        logger.debug(f"Middleware: Processing tool call: {context.message.name}")
        
        try:
            headers = get_http_headers()
            auth_header = headers.get("authorization", "") or headers.get("Authorization", "")
            
            if auth_header.startswith("Bearer "):
                session_token = auth_header[7:]  # Remove "Bearer " prefix
                logger.debug(f"Middleware: Found session token: {session_token[:15]}...")
                
                # Look up the session
                cleanup_expired()
                session_data = _sessions.get(session_token)
                
                if session_data:
                    # Verify session hasn't expired
                    elapsed = time.time() - session_data.get("timestamp", 0)
                    if elapsed < session_data.get("expires_in", TOKEN_EXPIRY_SECONDS):
                        # Store session data in context state for tools to access
                        context.fastmcp_context.set_state("session_token", session_token)
                        context.fastmcp_context.set_state("blackboard_token", session_data.get("blackboard_access_token"))
                        context.fastmcp_context.set_state("user_id", session_data.get("user_id"))
                        context.fastmcp_context.set_state("session_data", session_data)
                        context.fastmcp_context.set_state("authenticated", True)
                        logger.info(f"Middleware: Authenticated user {session_data.get('user_id')} for tool {context.message.name}")
                    else:
                        logger.warning(f"Middleware: Session expired for user {session_data.get('user_id')}")
                        context.fastmcp_context.set_state("authenticated", False)
                else:
                    logger.warning(f"Middleware: Session not found: {session_token[:15]}...")
                    context.fastmcp_context.set_state("authenticated", False)
            else:
                logger.debug("Middleware: No Bearer token in Authorization header")
                context.fastmcp_context.set_state("authenticated", False)
                
        except Exception as e:
            logger.error(f"Middleware: Error extracting auth: {e}")
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

def get_user_session() -> tuple[str | None, str | None, dict | None, bool]:
    """
    Get the current user's session from context state.
    Returns (session_token, blackboard_token, session_data, is_authenticated)
    """
    try:
        ctx = get_context()
        authenticated = ctx.get_state("authenticated")
        
        if authenticated:
            session_token = ctx.get_state("session_token")
            blackboard_token = ctx.get_state("blackboard_token")
            session_data = ctx.get_state("session_data")
            return session_token, blackboard_token, session_data, True
                
    except Exception as e:
        logger.error(f"Error getting user session: {e}")
    
    return None, None, None, False


async def refresh_blackboard_token(session_token: str, session_data: dict) -> bool:
    """
    Attempt to refresh the Blackboard access token using the refresh token.
    Returns True if successful, False otherwise.
    """
    refresh_token = session_data.get("refresh_token")
    if not refresh_token:
        logger.warning("No refresh token available")
        return False
    
    try:
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
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token
                }
            )
            
            if response.status_code == 200:
                token_data = response.json()
                
                # Update session with new tokens
                _sessions[session_token].update({
                    "blackboard_access_token": token_data["access_token"],
                    "refresh_token": token_data.get("refresh_token", refresh_token),
                    "expires_in": token_data.get("expires_in", TOKEN_EXPIRY_SECONDS),
                    "timestamp": time.time()
                })
                
                logger.info(f"Successfully refreshed token for session {session_token[:15]}...")
                return True
            else:
                logger.error(f"Token refresh failed: {response.status_code}")
                return False
                
    except Exception as e:
        logger.exception(f"Error refreshing token: {e}")
        return False


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
        "grant_types_supported": ["authorization_code", "refresh_token"],
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
    
    # Generate state to track this flow
    our_state = secrets.token_urlsafe(32)
    
    _pending_auths[our_state] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "timestamp": time.time()
    }
    
    cleanup_expired()
    
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
            
            blackboard_tokens = response.json()
            user_id = blackboard_tokens.get("user_id", "unknown")
            logger.info(f"OAuth: Successfully obtained token for user {user_id}")
        
        # Generate our own session token (this is what Claude will use)
        session_token = generate_session_token()
        
        # Generate a one-time authorization code for the token exchange
        auth_code = secrets.token_urlsafe(32)
        
        # Store the mapping: auth_code -> session_token
        _auth_codes[auth_code] = {
            "session_token": session_token,
            "timestamp": time.time()
        }
        
        # Store the session: session_token -> Blackboard credentials
        _sessions[session_token] = {
            "blackboard_access_token": blackboard_tokens["access_token"],
            "refresh_token": blackboard_tokens.get("refresh_token"),
            "token_type": blackboard_tokens.get("token_type", "bearer"),
            "expires_in": blackboard_tokens.get("expires_in", TOKEN_EXPIRY_SECONDS),
            "user_id": user_id,
            "timestamp": time.time()
        }
        
        logger.info(f"OAuth: Created session for user {user_id}, session_token: {session_token[:15]}...")
        
        # Redirect back to Claude with our auth code
        redirect_url = f"{original['redirect_uri']}?code={auth_code}&state={original['state']}"
        logger.info(f"OAuth: Redirecting back to Claude with authorization code")
        return RedirectResponse(redirect_url)
        
    except Exception as e:
        logger.exception(f"OAuth: Error during token exchange: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request):
    """Token endpoint for Claude - exchanges auth code for session token"""
    form = await request.form()
    code = form.get("code")
    grant_type = form.get("grant_type", "authorization_code")
    
    logger.info(f"OAuth: Token request, grant_type={grant_type}")
    
    if grant_type == "authorization_code":
        if not code:
            logger.error("OAuth: Missing code in token request")
            return JSONResponse({"error": "missing_code"}, status_code=400)
        
        auth_code_data = _auth_codes.get(code)
        if not auth_code_data:
            logger.error("OAuth: Invalid or expired authorization code")
            return JSONResponse({"error": "invalid_code"}, status_code=400)
        
        # One-time use - remove the code
        del _auth_codes[code]
        
        session_token = auth_code_data["session_token"]
        session_data = _sessions.get(session_token)
        
        if not session_data:
            logger.error("OAuth: Session not found for auth code")
            return JSONResponse({"error": "session_not_found"}, status_code=400)
        
        logger.info(f"OAuth: Issued session token to Claude for user {session_data.get('user_id')}")
        
        # Return OUR session token (not the Blackboard token!)
        return JSONResponse({
            "access_token": session_token,
            "token_type": "bearer",
            "expires_in": session_data.get("expires_in", TOKEN_EXPIRY_SECONDS),
            "scope": "read write offline"
        })
    
    elif grant_type == "refresh_token":
        # Claude is trying to refresh - we handle this by refreshing with Blackboard
        refresh_token = form.get("refresh_token")
        # In this model, the "refresh_token" from Claude's perspective is the session_token
        # We look up the session and refresh the underlying Blackboard token
        
        session_data = _sessions.get(refresh_token)
        if not session_data:
            return JSONResponse({"error": "invalid_refresh_token"}, status_code=400)
        
        if await refresh_blackboard_token(refresh_token, session_data):
            updated_session = _sessions[refresh_token]
            return JSONResponse({
                "access_token": refresh_token,  # Same session token
                "token_type": "bearer",
                "expires_in": updated_session.get("expires_in", TOKEN_EXPIRY_SECONDS),
                "scope": "read write offline"
            })
        else:
            # Refresh failed, invalidate session
            del _sessions[refresh_token]
            return JSONResponse({"error": "refresh_failed"}, status_code=400)
    
    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def protected_resource_config(request):
    """Indicate that this resource requires OAuth"""
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
    session_token, bb_token, session_data, authenticated = get_user_session()
    
    if not authenticated or not bb_token:
        return get_auth_url()
    
    user_id = session_data.get("user_id", "unknown") if session_data else "unknown"
    logger.info(f"Tool get_my_courses: Fetching courses for user {user_id}")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses?limit=100",
                headers={"Authorization": f"Bearer {bb_token}"},
                timeout=30.0
            )
            
            if response.status_code == 401:
                # Try to refresh
                if session_token and await refresh_blackboard_token(session_token, session_data):
                    # Retry with new token
                    new_bb_token = _sessions[session_token]["blackboard_access_token"]
                    response = await client.get(
                        f"{BLACKBOARD_URL}/learn/api/public/v1/courses?limit=100",
                        headers={"Authorization": f"Bearer {new_bb_token}"},
                        timeout=30.0
                    )
                else:
                    if session_token and session_token in _sessions:
                        del _sessions[session_token]
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
        logger.exception(f"Tool get_my_courses: Error: {e}")
        return f"Error calling Blackboard API: {str(e)}"


@mcp.tool()
async def get_course_assignments(course_id: str) -> str:
    """Get assignments for a specific course."""
    session_token, bb_token, session_data, authenticated = get_user_session()
    
    if not authenticated or not bb_token:
        return get_auth_url()
    
    user_id = session_data.get("user_id", "unknown") if session_data else "unknown"
    logger.info(f"Tool get_course_assignments: Fetching for course {course_id}, user {user_id}")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses/{course_id}/gradebook/columns",
                headers={"Authorization": f"Bearer {bb_token}"},
                timeout=30.0
            )
            
            if response.status_code == 401:
                if session_token and await refresh_blackboard_token(session_token, session_data):
                    new_bb_token = _sessions[session_token]["blackboard_access_token"]
                    response = await client.get(
                        f"{BLACKBOARD_URL}/learn/api/public/v1/courses/{course_id}/gradebook/columns",
                        headers={"Authorization": f"Bearer {new_bb_token}"},
                        timeout=30.0
                    )
                else:
                    if session_token and session_token in _sessions:
                        del _sessions[session_token]
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
        logger.exception(f"Tool get_course_assignments: Error: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_current_user() -> str:
    """Get information about the currently authenticated Blackboard user."""
    session_token, bb_token, session_data, authenticated = get_user_session()
    
    if not authenticated or not bb_token:
        return get_auth_url()
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
                headers={"Authorization": f"Bearer {bb_token}"},
                timeout=30.0
            )
            
            if response.status_code == 401:
                if session_token and await refresh_blackboard_token(session_token, session_data):
                    new_bb_token = _sessions[session_token]["blackboard_access_token"]
                    response = await client.get(
                        f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
                        headers={"Authorization": f"Bearer {new_bb_token}"},
                        timeout=30.0
                    )
                else:
                    if session_token and session_token in _sessions:
                        del _sessions[session_token]
                    return "⚠️ Your session has expired.\n\n" + get_auth_url()
            
            if response.status_code != 200:
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
            
            return result
            
    except Exception as e:
        logger.exception(f"Tool get_current_user: Error: {e}")
        return f"Error calling Blackboard API: {str(e)}"


@mcp.tool()
async def logout() -> str:
    """Log out from Blackboard by clearing your session."""
    session_token, _, session_data, authenticated = get_user_session()
    
    if authenticated and session_token and session_token in _sessions:
        user_id = session_data.get("user_id", "unknown") if session_data else "unknown"
        del _sessions[session_token]
        logger.info(f"Tool logout: Logged out user {user_id}")
        return "✅ Successfully logged out from Blackboard."
    
    return "ℹ️ You are not currently logged in."


@mcp.tool()
async def check_auth_status() -> str:
    """Check your current authentication status with Blackboard."""
    session_token, _, session_data, authenticated = get_user_session()
    
    if not authenticated or not session_data:
        return "🔒 **Not Authenticated**\n\n" + get_auth_url()
    
    timestamp = session_data.get("timestamp", 0)
    expires_in = session_data.get("expires_in", TOKEN_EXPIRY_SECONDS)
    elapsed = time.time() - timestamp
    remaining = expires_in - elapsed
    
    if remaining <= 0:
        if session_token and session_token in _sessions:
            del _sessions[session_token]
        return "⏰ **Session Expired**\n\n" + get_auth_url()
    
    user_id = session_data.get("user_id", "unknown")
    minutes_remaining = int(remaining / 60)
    
    return (
        f"✅ **Authenticated**\n\n"
        f"• **User ID:** `{user_id}`\n"
        f"• **Session expires in:** {minutes_remaining} minutes\n"
        f"• **Has refresh token:** {'Yes' if session_data.get('refresh_token') else 'No'}"
    )


@mcp.tool()
async def debug_session() -> str:
    """Debug tool to see session and storage information."""
    cleanup_expired()
    
    session_token, bb_token, session_data, authenticated = get_user_session()
    
    # Count storage items
    pending_count = len(_pending_auths)
    auth_code_count = len(_auth_codes)
    session_count = len(_sessions)
    
    result = (
        f"🔧 **Debug Session Info**\n\n"
        f"**Storage Counts:**\n"
        f"• Pending OAuth flows: {pending_count}\n"
        f"• Pending auth codes: {auth_code_count}\n"
        f"• Active sessions: {session_count}\n\n"
        f"**Current Session:**\n"
        f"• Authenticated: {authenticated}\n"
        f"• Session token: {session_token[:20] + '...' if session_token else 'N/A'}\n"
        f"• Has Blackboard token: {bool(bb_token)}\n"
        f"• User ID: {session_data.get('user_id', 'N/A') if session_data else 'N/A'}\n"
    )
    
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
