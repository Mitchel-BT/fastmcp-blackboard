"""
Blackboard MCP Server - Cloud Version with FastMCP OAuth Support
Multi-tenant session management with connection-based isolation
"""
import os
import base64
import secrets
import time
import logging
import httpx
from urllib.parse import urlencode
from fastmcp import FastMCP, Context
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_context
from starlette.responses import RedirectResponse, JSONResponse

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
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL")  # e.g., https://your-school.blackboard.com
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET")
SERVER_URL = os.environ.get("SERVER_URL")

TOKEN_EXPIRY_SECONDS = 3600

# ============================================================================
# SESSION STORAGE - Per Connection
# ============================================================================
_sessions = {}  # connection_id -> {token_data, timestamp, user_id}
_pending_auths = {}  # state -> {connection_id, redirect_uri, etc}
_auth_codes = {}  # code -> {connection_id, token_data}
_completed_states = {}  # state -> cached redirect info


def cleanup_expired():
    """Remove expired sessions and states"""
    current_time = time.time()
    
    expired_sessions = [
        conn_id for conn_id, session in _sessions.items()
        if current_time - session.get("timestamp", 0) > session.get("expires_in", TOKEN_EXPIRY_SECONDS)
    ]
    for conn_id in expired_sessions:
        user_id = _sessions[conn_id].get("user_id", "unknown")
        del _sessions[conn_id]
        logger.info(f"Cleaned up expired session for connection {conn_id[:20]}... (user {user_id})")
    
    # Clean up old auth codes (10 min expiry)
    expired_codes = [
        key for key, data in _auth_codes.items()
        if current_time - data.get("timestamp", 0) > 600
    ]
    for key in expired_codes:
        del _auth_codes[key]
    
    # Clean up old pending auths (10 min expiry)
    expired_pending = [
        key for key, data in _pending_auths.items()
        if current_time - data.get("timestamp", 0) > 600
    ]
    for key in expired_pending:
        del _pending_auths[key]
    
    # Clean up old completed states (10 min expiry)
    expired_completed = [
        key for key, data in _completed_states.items()
        if current_time - data.get("timestamp", 0) > 600
    ]
    for key in expired_completed:
        del _completed_states[key]


def get_auth_url(connection_id: str) -> str:
    """Generate authentication URL with connection context"""
    params = {
        'client_id': 'claude',
        'redirect_uri': f'{SERVER_URL}/oauth/callback',
        'response_type': 'code',
        'state': connection_id,
        'scope': 'read write offline'
    }
    auth_url = f"{SERVER_URL}/oauth/authorize?{urlencode(params)}"
    
    return (
        f"🔐 **Authentication Required**\n\n"
        f"Please log in to Blackboard:\n\n"
        f"👉 [Click here to authenticate]({auth_url})\n\n"
        f"After logging in, return here and try your request again."
    )


# ============================================================================
# CONNECTION-AWARE MIDDLEWARE - FastMCP OAuth Compatible
# ============================================================================

class ConnectionSessionMiddleware(Middleware):
    """
    Middleware that extracts Bearer token from Authorization header.
    FastMCP OAuth client sends the token we returned from /oauth/token.
    """
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Extract token from Authorization header and load session"""
        tool_name = context.message.name
        
        try:
            # FastMCP client sends: Authorization: Bearer <connection_id>
            # We returned connection_id as the access_token in /oauth/token
            
            request = context.fastmcp_context.request
            
            connection_id = None
            auth_header = None
            
            # Get Authorization header (primary method for OAuth)
            if hasattr(request, 'headers'):
                auth_header = request.headers.get('authorization') or request.headers.get('Authorization')
            
            if auth_header and auth_header.startswith('Bearer '):
                # Extract the token (which is our connection_id)
                connection_id = auth_header[7:]  # Remove "Bearer " prefix
                logger.info(f"Middleware: Found Bearer token (connection_id): {connection_id[:20]}...")
            else:
                # Fallback to other methods for non-OAuth requests
                if hasattr(request, 'query_params'):
                    connection_id = request.query_params.get('connection_id')
                
                if not connection_id and hasattr(request, 'headers'):
                    connection_id = request.headers.get('X-Connection-ID')
                
                if not connection_id:
                    connection_id = getattr(request.state, 'connection_id', None)
                    if not connection_id:
                        connection_id = secrets.token_urlsafe(16)
                        request.state.connection_id = connection_id
            
            logger.debug(f"Middleware: Tool {tool_name} - connection_id={connection_id[:20]}...")
            
            cleanup_expired()
            
            # Look up session by connection_id
            session = _sessions.get(connection_id)
            
            if session:
                context.fastmcp_context.set_state("connection_id", connection_id)
                context.fastmcp_context.set_state("authenticated", True)
                context.fastmcp_context.set_state("token_data", session)
                context.fastmcp_context.set_state("access_token", session.get("access_token"))
                context.fastmcp_context.set_state("user_id", session.get("user_id"))
                logger.info(f"Middleware: ✅ Session found for {connection_id[:20]}... (user {session.get('user_id')})")
            else:
                context.fastmcp_context.set_state("connection_id", connection_id)
                context.fastmcp_context.set_state("authenticated", False)
                logger.debug(f"Middleware: ⚠️ No session found for {connection_id[:20]}...")
                
        except Exception as e:
            logger.exception(f"Middleware: Error: {e}")
            connection_id = secrets.token_urlsafe(16)
            context.fastmcp_context.set_state("connection_id", connection_id)
            context.fastmcp_context.set_state("authenticated", False)
        
        return await call_next(context)


# ============================================================================
# MCP SERVER SETUP - MUST COME BEFORE TOOL DEFINITIONS
# ============================================================================
mcp = FastMCP("Blackboard")
mcp.add_middleware(ConnectionSessionMiddleware())


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_user_session() -> tuple[str | None, dict | None, bool, str | None]:
    """
    Get the current connection's session from context.
    Returns (access_token, token_data, is_authenticated, connection_id)
    """
    try:
        ctx = get_context()
        authenticated = ctx.get_state("authenticated")
        connection_id = ctx.get_state("connection_id")
        
        if authenticated:
            token = ctx.get_state("access_token")
            token_data = ctx.get_state("token_data")
            return token, token_data, True, connection_id
        
        return None, None, False, connection_id
                
    except Exception as e:
        logger.error(f"Error getting user session: {e}")
        return None, None, False, None


async def refresh_token_if_needed(connection_id: str) -> bool:
    """
    Check if token needs refresh and refresh it if necessary.
    Returns True if token was refreshed.
    """
    session = _sessions.get(connection_id)
    if not session:
        return False
    
    # Check if token is about to expire (within 5 minutes)
    expires_in = session.get("expires_in", TOKEN_EXPIRY_SECONDS)
    elapsed = time.time() - session.get("timestamp", 0)
    remaining = expires_in - elapsed
    
    if remaining > 300:  # More than 5 minutes remaining
        return False
    
    # Token expiring soon, try to refresh
    refresh_token = session.get("refresh_token")
    if not refresh_token:
        logger.warning(f"No refresh token available for connection {connection_id[:20]}...")
        return False
    
    try:
        logger.info(f"Refreshing token for connection {connection_id[:20]}...")
        
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
                },
                timeout=30.0
            )
            
            if response.status_code != 200:
                logger.error(f"Token refresh failed: {response.status_code}")
                return False
            
            token_data = response.json()
            
            # Update session with new token
            session["access_token"] = token_data["access_token"]
            session["expires_in"] = token_data.get("expires_in", 3600)
            session["timestamp"] = time.time()
            if "refresh_token" in token_data:
                session["refresh_token"] = token_data["refresh_token"]
            
            _sessions[connection_id] = session
            logger.info(f"✅ Token refreshed successfully for connection {connection_id[:20]}...")
            return True
            
    except Exception as e:
        logger.exception(f"Error refreshing token: {e}")
        return False


# ============================================================================
# OAUTH ROUTES - FastMCP Compatible
# ============================================================================

@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_config(request):
    """OAuth server configuration - FastMCP client compatible"""
    logger.info("OAuth: Server metadata requested")
    return JSONResponse({
        "issuer": SERVER_URL,
        "authorization_endpoint": f"{SERVER_URL}/oauth/authorize",
        "token_endpoint": f"{SERVER_URL}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["read", "write", "offline"],
        "token_endpoint_auth_methods_supported": ["none"],
    })


@mcp.custom_route("/oauth/authorize", methods=["GET"])
async def oauth_authorize(request):
    """OAuth authorization - redirects to Blackboard"""
    client_id = request.query_params.get("client_id")
    redirect_uri = request.query_params.get("redirect_uri")
    state = request.query_params.get("state")
    code_challenge = request.query_params.get("code_challenge")
    scope = request.query_params.get("scope", "read write offline")
    
    logger.info(f"OAuth: Authorization request - state/connection_id={state[:20] if state else 'missing'}...")
    
    connection_id = state
    our_state = secrets.token_urlsafe(32)
    
    _pending_auths[our_state] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "original_state": state,
        "connection_id": connection_id,
        "code_challenge": code_challenge,
        "timestamp": time.time()
    }
    
    logger.info(f"OAuth: Created pending auth for connection {connection_id[:20] if connection_id else 'unknown'}...")
    
    cleanup_expired()
    
    blackboard_params = {
        'redirect_uri': f'{SERVER_URL}/oauth/callback',
        'response_type': 'code',
        'client_id': BLACKBOARD_APP_KEY,
        'scope': scope,
        'state': our_state
    }
    
    blackboard_auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode?"
        f"{urlencode(blackboard_params)}"
    )
    
    logger.info(f"OAuth: Redirecting to Blackboard")
    return RedirectResponse(blackboard_auth_url)


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request):
    """OAuth callback from Blackboard"""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    logger.info(f"OAuth: Callback from Blackboard - state={state[:20] if state else 'None'}...")
    
    if error:
        logger.error(f"OAuth: Blackboard returned error: {error}")
        return JSONResponse({"error": error}, status_code=400)
    
    if not code or not state:
        logger.error("OAuth: Missing code or state")
        return JSONResponse({"error": "missing_parameters"}, status_code=400)
    
    if state in _completed_states:
        completed = _completed_states[state]
        logger.warning(f"OAuth: Duplicate callback")
        redirect_url = f"{completed['redirect_uri']}?code={completed['claude_code']}&state={completed['original_state']}"
        return RedirectResponse(redirect_url)
    
    original = _pending_auths.get(state)
    if not original:
        logger.error(f"OAuth: Invalid state")
        return JSONResponse({"error": "invalid_state"}, status_code=400)
    
    connection_id = original.get("connection_id")
    logger.info(f"OAuth: Processing callback for connection {connection_id[:20] if connection_id else 'unknown'}...")
    
    try:
        logger.info("OAuth: Exchanging authorization code...")
        
        credentials = f"{BLACKBOARD_APP_KEY}:{BLACKBOARD_APP_SECRET}"
        auth_header = base64.b64encode(credentials.encode()).decode()
        
        token_data_params = {
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": f"{SERVER_URL}/oauth/callback"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/token",
                headers={
                    "Authorization": f"Basic {auth_header}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                data=token_data_params,
                timeout=30.0
            )
            
            logger.debug(f"OAuth: Blackboard response: {response.status_code}")
            
            if response.status_code != 200:
                logger.error(f"OAuth: Token exchange failed: {response.status_code} - {response.text}")
                return JSONResponse({"error": "token_exchange_failed", "details": response.text}, status_code=500)
            
            token_data = response.json()
            access_token = token_data["access_token"]
            user_id = token_data.get("user_id", "unknown")
            
            logger.info(f"OAuth: ✅ Got token for user {user_id}")
        
        session = {
            "access_token": access_token,
            "token_type": token_data.get("token_type", "bearer"),
            "expires_in": token_data.get("expires_in", 3600),
            "refresh_token": token_data.get("refresh_token"),
            "user_id": user_id,
            "scope": token_data.get("scope", ""),
            "timestamp": time.time()
        }
        
        if connection_id:
            _sessions[connection_id] = session
            logger.info(f"OAuth: ✅ Stored session for connection {connection_id[:20]}... (user {user_id})")
            logger.info(f"OAuth: Total active sessions: {len(_sessions)}")
        
        claude_code = secrets.token_urlsafe(32)
        
        _auth_codes[claude_code] = {
            "connection_id": connection_id,
            "session": session,
            "timestamp": time.time()
        }
        
        _completed_states[state] = {
            "claude_code": claude_code,
            "redirect_uri": original["redirect_uri"],
            "original_state": original["original_state"],
            "timestamp": time.time()
        }
        
        del _pending_auths[state]
        
        redirect_url = f"{original['redirect_uri']}?code={claude_code}&state={original['original_state']}"
        logger.info(f"OAuth: Redirecting to Claude")
        return RedirectResponse(redirect_url)
        
    except Exception as e:
        logger.exception(f"OAuth: Error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request):
    """Token endpoint for Claude - returns connection_id as access token"""
    form = await request.form()
    code = form.get("code")
    grant_type = form.get("grant_type")
    
    logger.info(f"OAuth: Token request from Claude - grant_type={grant_type}")
    
    if grant_type == "refresh_token":
        # Handle token refresh
        refresh_token_value = form.get("refresh_token")
        
        # Find session by refresh token (connection_id)
        connection_id = refresh_token_value
        
        if not connection_id or connection_id not in _sessions:
            logger.error("OAuth: Invalid refresh token")
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        
        # Attempt to refresh the Blackboard token
        refreshed = await refresh_token_if_needed(connection_id)
        
        if not refreshed:
            logger.error("OAuth: Token refresh failed")
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        
        session = _sessions[connection_id]
        
        return JSONResponse({
            "access_token": connection_id,
            "token_type": "bearer",
            "expires_in": session["expires_in"],
            "refresh_token": connection_id,  # Same as access token for our implementation
            "scope": session.get("scope", "read write offline")
        })
    
    # Normal authorization code flow
    if not code:
        return JSONResponse({"error": "missing_code"}, status_code=400)
    
    auth_data = _auth_codes.get(code)
    
    if not auth_data:
        logger.error(f"OAuth: Invalid code")
        return JSONResponse({"error": "invalid_code"}, status_code=400)
    
    del _auth_codes[code]
    
    connection_id = auth_data["connection_id"]
    session = auth_data["session"]
    
    if connection_id and connection_id not in _sessions:
        _sessions[connection_id] = session
    
    user_id = session.get("user_id")
    logger.info(f"OAuth: ✅ Issued token for connection {connection_id[:20] if connection_id else 'unknown'}... (user {user_id})")
    
    # Return connection_id as access_token
    # FastMCP client will send this in Authorization: Bearer header
    return JSONResponse({
        "access_token": connection_id,
        "token_type": "bearer",
        "expires_in": session["expires_in"],
        "refresh_token": connection_id,  # Same as access token for simplicity
        "scope": session.get("scope", "read write offline")
    })


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def protected_resource_config(request):
    """Protected resource config"""
    return JSONResponse({
        "resource": SERVER_URL,
        "authorization_servers": [SERVER_URL]
    })


# ============================================================================
# MCP TOOLS - Blackboard API Integration
# ============================================================================

@mcp.tool()
async def get_my_courses() -> str:
    """Get all courses you have access to in Blackboard"""
    token, token_data, authenticated, connection_id = get_user_session()
    
    if not authenticated or not token:
        return get_auth_url(connection_id)
    
    user_id = token_data.get("user_id", "unknown")
    logger.info(f"Tool: get_my_courses for user {user_id}")
    
    # Try to refresh token if needed
    await refresh_token_if_needed(connection_id)
    
    # Get fresh token after potential refresh
    token = _sessions.get(connection_id, {}).get("access_token", token)
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses?limit=100",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            if response.status_code == 401:
                if connection_id and connection_id in _sessions:
                    del _sessions[connection_id]
                return "⚠️ Your session has expired.\n\n" + get_auth_url(connection_id)
            
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
        logger.exception(f"Tool error: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_course_assignments(course_id: str) -> str:
    """
    Get assignments for a specific course.
    
    Args:
        course_id: The course ID from get_my_courses (e.g., "_123_1")
    """
    token, token_data, authenticated, connection_id = get_user_session()
    
    if not authenticated or not token:
        return get_auth_url(connection_id)
    
    # Try to refresh token if needed
    await refresh_token_if_needed(connection_id)
    token = _sessions.get(connection_id, {}).get("access_token", token)
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses/{course_id}/gradebook/columns",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            if response.status_code == 401:
                if connection_id and connection_id in _sessions:
                    del _sessions[connection_id]
                return "⚠️ Your session has expired.\n\n" + get_auth_url(connection_id)
            
            if response.status_code != 200:
                return f"Error: {response.status_code} - {response.text}"
            
            data = response.json()
            columns = data.get("results", [])
            assignments = [c for c in columns if c.get("grading", {}).get("due")]
            
            if not assignments:
                return f"No assignments found in course `{course_id}`"
            
            result = f"📝 Found {len(assignments)} assignments:\n\n"
            for assignment in assignments:
                name = assignment.get("name", "Unnamed")
                points = assignment.get("score", {}).get("possible", "?")
                due = assignment.get("grading", {}).get("due", "No due date")
                result += f"• **{name}** ({points} points) - Due: {due}\n"
            
            return result
            
    except Exception as e:
        logger.exception(f"Tool error: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_current_user() -> str:
    """Get information about the currently authenticated user"""
    token, token_data, authenticated, connection_id = get_user_session()
    
    if not authenticated or not token:
        return get_auth_url(connection_id)
    
    # Try to refresh token if needed
    await refresh_token_if_needed(connection_id)
    token = _sessions.get(connection_id, {}).get("access_token", token)
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            if response.status_code == 401:
                if connection_id and connection_id in _sessions:
                    del _sessions[connection_id]
                return "⚠️ Your session has expired.\n\n" + get_auth_url(connection_id)
            
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
        logger.exception(f"Tool error: {e}")
        return f"Error: {str(e)}"


# ============================================================================
# SESSION MANAGEMENT TOOLS - For Demo & Testing
# ============================================================================

@mcp.tool()
async def logout() -> str:
    """Log out from Blackboard"""
    token, token_data, authenticated, connection_id = get_user_session()
    
    if not authenticated or not connection_id:
        return "ℹ️ You are not currently logged in."
    
    if connection_id in _sessions:
        user_id = token_data.get("user_id", "unknown") if token_data else "unknown"
        del _sessions[connection_id]
        
        logger.info(f"Tool: logout - connection {connection_id[:20]}... (user {user_id})")
        
        return (
            f"✅ **Successfully Logged Out**\n\n"
            f"• User: `{user_id}`\n"
            f"• Connection: `{connection_id[:20]}...`\n\n"
            f"You can now authenticate as a different user."
        )
    
    return "ℹ️ No active session found."


@mcp.tool()
async def force_logout(connection_id_prefix: str) -> str:
    """
    Force logout a specific session by connection ID prefix.
    
    Args:
        connection_id_prefix: First 8+ characters of the connection ID
    """
    if len(connection_id_prefix) < 8:
        return "❌ Please provide at least 8 characters of the connection ID."
    
    cleanup_expired()
    
    matches = [conn_id for conn_id in _sessions.keys() if conn_id.startswith(connection_id_prefix)]
    
    if not matches:
        return f"❌ No sessions found matching `{connection_id_prefix}`"
    
    if len(matches) > 1:
        result = f"⚠️ Found {len(matches)} matching sessions:\n\n"
        for conn_id in matches:
            session = _sessions[conn_id]
            user_id = session.get("user_id", "unknown")
            result += f"• `{conn_id[:20]}...` - User: {user_id}\n"
        return result + "\nProvide a longer prefix."
    
    conn_id = matches[0]
    session = _sessions[conn_id]
    user_id = session.get("user_id", "unknown")
    
    del _sessions[conn_id]
    
    return (
        f"✅ **Force Logged Out**\n\n"
        f"• Connection: `{conn_id[:20]}...`\n"
        f"• User: `{user_id}`\n\n"
        f"Active sessions: {len(_sessions)}"
    )


@mcp.tool()
async def logout_all_sessions() -> str:
    """Log out ALL active sessions"""
    cleanup_expired()
    
    if not _sessions:
        return "ℹ️ No active sessions to log out."
    
    session_count = len(_sessions)
    users = [f"{s.get('user_id', 'unknown')} ({c[:12]}...)" for c, s in _sessions.items()]
    
    _sessions.clear()
    
    logger.warning(f"Tool: logout_all_sessions - Cleared {session_count} sessions")
    
    result = f"✅ **All Sessions Logged Out**\n\nRemoved {session_count} session(s):\n\n"
    for user in users:
        result += f"• {user}\n"
    
    return result


@mcp.tool()
async def list_active_sessions() -> str:
    """List all currently active sessions"""
    cleanup_expired()
    
    if not _sessions:
        return "ℹ️ **No Active Sessions**\n\nNo users are currently authenticated."
    
    result = f"👥 **Active Sessions** ({len(_sessions)} total)\n\n"
    
    sorted_sessions = sorted(_sessions.items(), key=lambda x: x[1].get("timestamp", 0), reverse=True)
    
    for conn_id, session in sorted_sessions:
        user_id = session.get("user_id", "unknown")
        timestamp = session.get("timestamp", 0)
        expires_in = session.get("expires_in", TOKEN_EXPIRY_SECONDS)
        
        age_minutes = int((time.time() - timestamp) / 60)
        remaining_minutes = max(0, int((expires_in - (time.time() - timestamp)) / 60))
        
        result += f"**Connection:** `{conn_id[:20]}...`\n"
        result += f"• User: `{user_id}`\n"
        result += f"• Active for: {age_minutes} minutes\n"
        result += f"• Expires in: {remaining_minutes} minutes\n\n"
    
    return result


@mcp.tool()
async def get_my_connection_id() -> str:
    """Get your current connection ID"""
    _, token_data, authenticated, connection_id = get_user_session()
    
    if not connection_id:
        return "❌ Unable to determine connection ID."
    
    result = f"🔑 **Your Connection ID**\n\n• Full ID: `{connection_id}`\n• Short: `{connection_id[:20]}...`\n\n"
    
    if authenticated and token_data:
        user_id = token_data.get("user_id", "unknown")
        age_minutes = int((time.time() - token_data.get("timestamp", 0)) / 60)
        result += f"**Session:**\n• Authenticated: ✅\n• User: `{user_id}`\n• Age: {age_minutes} minutes\n"
    else:
        result += "**Session:**\n• Authenticated: ❌\n"
    
    return result


@mcp.tool()
async def switch_user() -> str:
    """Log out and get auth link to switch users"""
    token, token_data, authenticated, connection_id = get_user_session()
    
    old_user = "None"
    if authenticated and token_data:
        old_user = token_data.get("user_id", "unknown")
        if connection_id and connection_id in _sessions:
            del _sessions[connection_id]
            logger.info(f"Tool: switch_user - Logged out {old_user}")
    
    if not connection_id:
        connection_id = secrets.token_urlsafe(16)
    
    result = f"🔄 **Switching Users**\n\n• Previous: `{old_user}`\n\n"
    result += get_auth_url(connection_id).replace("🔐 **Authentication Required**\n\n", "")
    
    return result


@mcp.tool()
async def demo_status() -> str:
    """Get demo environment status"""
    cleanup_expired()
    
    result = "📊 **Demo Environment Status**\n\n"
    result += f"**Active Sessions:** {len(_sessions)}\n"
    
    if _sessions:
        for conn_id, session in list(_sessions.items())[:5]:
            user_id = session.get("user_id", "unknown")
            age = int((time.time() - session.get("timestamp", 0)) / 60)
            result += f"  • {user_id} - {age}m ago\n"
        if len(_sessions) > 5:
            result += f"  • ...and {len(_sessions) - 5} more\n"
    
    result += f"\n**Pending OAuth:** {len(_pending_auths)}\n"
    result += f"**Auth Codes:** {len(_auth_codes)}\n\n"
    
    result += "**Configuration:**\n"
    result += f"  • Blackboard URL: {'✅' if BLACKBOARD_URL else '❌'}\n"
    result += f"  • App Key: {'✅' if BLACKBOARD_APP_KEY else '❌'}\n"
    result += f"  • App Secret: {'✅' if BLACKBOARD_APP_SECRET else '❌'}\n"
    result += f"  • Server URL: {'✅' if SERVER_URL else '❌'}\n"
    
    return result


@mcp.tool()
async def check_auth_status() -> str:
    """Check your current authentication status"""
    cleanup_expired()
    
    token, token_data, authenticated, connection_id = get_user_session()
    
    if not authenticated or not token_data:
        result = f"🔒 **Not Authenticated**\n\n• Connection: `{connection_id[:20] if connection_id else 'unknown'}...`\n\n"
        return result + get_auth_url(connection_id)
    
    timestamp = token_data.get("timestamp", 0)
    expires_in = token_data.get("expires_in", TOKEN_EXPIRY_SECONDS)
    elapsed = time.time() - timestamp
    remaining = expires_in - elapsed
    
    if remaining <= 0:
        if connection_id and connection_id in _sessions:
            del _sessions[connection_id]
        return "⏰ **Session Expired**\n\n" + get_auth_url(connection_id)
    
    user_id = token_data.get("user_id", "unknown")
    minutes_remaining = int(remaining / 60)
    minutes_active = int(elapsed / 60)
    
    return (
        f"✅ **Authenticated**\n\n"
        f"• User: `{user_id}`\n"
        f"• Connection: `{connection_id[:20] if connection_id else 'unknown'}...`\n"
        f"• Active: {minutes_active} minutes\n"
        f"• Expires: {minutes_remaining} minutes\n"
        f"• Scope: {token_data.get('scope', 'N/A')}\n\n"
        f"**System:** {len(_sessions)} active sessions\n"
    )


@mcp.tool()
async def debug_session() -> str:
    """Debug session information"""
    cleanup_expired()
    
    token, token_data, authenticated, connection_id = get_user_session()
    
    result = (
        f"🔧 **Debug Info**\n\n"
        f"**Storage:**\n"
        f"• Active sessions: {len(_sessions)}\n"
        f"• Pending codes: {len(_auth_codes)}\n"
        f"• Pending OAuth: {len(_pending_auths)}\n\n"
        f"**Current:**\n"
        f"• Connection: `{connection_id[:20] if connection_id else 'None'}...`\n"
        f"• Authenticated: {authenticated}\n"
        f"• User: {token_data.get('user_id', 'N/A') if token_data else 'N/A'}\n\n"
        f"**Config:**\n"
        f"• Blackboard: `{BLACKBOARD_URL}`\n"
        f"• Server: `{SERVER_URL}`\n\n"
        f"**Sessions:**\n"
    )
    
    if _sessions:
        for conn_id, session in _sessions.items():
            elapsed = int(time.time() - session.get("timestamp", 0))
            result += f"• `{conn_id[:20]}...` - {session.get('user_id', 'unknown')} - {elapsed}s\n"
    else:
        result += "• No active sessions\n"
    
    return result


@mcp.tool()
async def check_config() -> str:
    """Check server configuration"""
    return (
        f"⚙️ **Server Configuration**\n\n"
        f"• **Blackboard URL:** `{BLACKBOARD_URL}`\n"
        f"• **App Key:** `{BLACKBOARD_APP_KEY[:8] if BLACKBOARD_APP_KEY else 'NOT SET'}...`\n"
        f"• **Server URL:** `{SERVER_URL}`\n\n"
        f"**OAuth Endpoints:**\n"
        f"• Authorize: `{SERVER_URL}/oauth/authorize`\n"
        f"• Token: `{SERVER_URL}/oauth/token`\n"
        f"• Callback: `{SERVER_URL}/oauth/callback`\n\n"
        f"**Blackboard:**\n"
        f"• Auth: `{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode`\n"
        f"• Token: `{BLACKBOARD_URL}/learn/api/public/v1/oauth2/token`\n"
    )


@mcp.tool()
async def demo_scenario(scenario: str) -> str:
    """
    Quick setup for demo scenarios.
    
    Args:
        scenario: "reset", "status", "student", "instructor", "admin", or "ta"
    """
    scenario = scenario.lower().strip()
    
    if scenario == "reset":
        count = len(_sessions)
        _sessions.clear()
        return f"✅ Demo reset! Cleared {count} session(s)."
    
    elif scenario == "status":
        return await demo_status()
    
    elif scenario in ["student", "instructor", "admin", "ta"]:
        _, token_data, authenticated, connection_id = get_user_session()
        
        if authenticated and connection_id and connection_id in _sessions:
            old_user = token_data.get("user_id", "unknown") if token_data else "None"
            del _sessions[connection_id]
        else:
            old_user = "None"
        
        if not connection_id:
            connection_id = secrets.token_urlsafe(16)
        
        emoji = {"student": "🎓", "instructor": "👨‍🏫", "admin": "👑", "ta": "📚"}
        
        return (
            f"{emoji.get(scenario, '👤')} **Demo: {scenario.title()}**\n\n"
            f"• Previous: `{old_user}`\n\n" +
            get_auth_url(connection_id).replace("🔐 **Authentication Required**\n\n", "")
        )
    
    else:
        return (
            f"❌ Unknown scenario\n\n"
            f"Available: reset, status, student, instructor, admin, ta"
        )
