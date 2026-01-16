"""
Blackboard MCP Server - Cloud Version with Custom OAuth
Adapts the working local OAuth flow for FastMCP Cloud
With session isolation and logout support
"""
import os
import base64
import secrets
import time
import hashlib
import httpx
from urllib.parse import urlencode
from fastmcp import FastMCP, Context
from starlette.responses import RedirectResponse, JSONResponse
from starlette.requests import Request

# ============================================================================
# CONFIGURATION
# ============================================================================
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET")
SERVER_URL = os.environ.get("SERVER_URL")

# Token expiry time (e.g., 1 hour)
TOKEN_EXPIRY_SECONDS = 3600

# ============================================================================
# MCP SERVER
# ============================================================================
mcp = FastMCP("Blackboard")

# Store pending OAuth flows and tokens in memory
# Key structure for _tokens: {session_id: {token_data}}
_pending_auths = {}
_tokens = {}  # Now keyed by session_id for isolation


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_session_id(ctx: Context) -> str:
    """
    Extract a unique session identifier from the MCP context.
    This ties tokens to specific user sessions.
    """
    # FastMCP Context should provide session/client info
    # The exact attribute depends on FastMCP version - common options:
    if hasattr(ctx, 'session_id'):
        return ctx.session_id
    if hasattr(ctx, 'client_id'):
        return ctx.client_id
    if hasattr(ctx, 'request_context') and ctx.request_context:
        # Hash any unique identifiers from request context
        rc = ctx.request_context
        if hasattr(rc, 'session_id'):
            return rc.session_id
        if hasattr(rc, 'meta') and rc.meta:
            # Create a hash from available metadata
            meta_str = str(rc.meta)
            return hashlib.sha256(meta_str.encode()).hexdigest()[:32]
    
    # Fallback: if no session info available, raise an error
    # This prevents the "shared token" security issue
    raise Exception("Unable to determine session identity. Authentication cannot proceed securely.")


def cleanup_expired_tokens():
    """Remove expired tokens from storage"""
    current_time = time.time()
    expired_sessions = []
    
    for session_id, token_data in _tokens.items():
        timestamp = token_data.get("timestamp", 0)
        expires_in = token_data.get("expires_in", TOKEN_EXPIRY_SECONDS)
        if current_time - timestamp > expires_in:
            expired_sessions.append(session_id)
    
    for session_id in expired_sessions:
        del _tokens[session_id]
        print(f"[Cleanup] Removed expired token for session: {session_id[:8]}...")


def get_token_for_session(session_id: str) -> str:
    """Get a valid token for the given session, or raise an error"""
    cleanup_expired_tokens()
    
    token_data = _tokens.get(session_id)
    if not token_data:
        raise Exception("Authentication required. Please log in to Blackboard.")
    
    # Check if token is expired
    timestamp = token_data.get("timestamp", 0)
    expires_in = token_data.get("expires_in", TOKEN_EXPIRY_SECONDS)
    if time.time() - timestamp > expires_in:
        del _tokens[session_id]
        raise Exception("Session expired. Please log in again.")
    
    access_token = token_data.get("access_token")
    if not access_token:
        raise Exception("Invalid token data. Please log in again.")
    
    return access_token


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
    """OAuth authorization endpoint - redirects to Blackboard"""
    client_id = request.query_params.get("client_id")
    redirect_uri = request.query_params.get("redirect_uri")
    state = request.query_params.get("state")
    code_challenge = request.query_params.get("code_challenge")
    
    print(f"[OAuth] Authorization request")
    print(f"[OAuth] Redirect URI: {redirect_uri}")
    
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
    
    # Redirect to Blackboard
    blackboard_auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?redirect_uri={SERVER_URL}/oauth/callback"
        f"&response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&scope=read%20write%20offline"
        f"&state={our_state}"
    )
    
    print(f"[OAuth] Redirecting to: {blackboard_auth_url[:80]}...")
    return RedirectResponse(blackboard_auth_url)


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request):
    """OAuth callback from Blackboard"""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    print(f"[Callback] Received from Blackboard")
    
    if error:
        return JSONResponse({"error": error}, status_code=400)
    
    if not code or not state:
        return JSONResponse({"error": "missing_parameters"}, status_code=400)
    
    original = _pending_auths.get(state)
    if not original:
        return JSONResponse({"error": "invalid_state"}, status_code=400)
    
    del _pending_auths[state]
    
    try:
        # Exchange with Blackboard
        print(f"[Callback] Exchanging code...")
        
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
                print(f"[Callback ERROR] {response.text}")
                return JSONResponse({"error": "token_exchange_failed"}, status_code=500)
            
            token_data = response.json()
            print(f"[Callback] Got token from Blackboard")
        
        # Generate code for Claude - this code is tied to the session
        claude_code = secrets.token_urlsafe(32)
        
        # Store token data temporarily by claude_code
        # It will be moved to session-based storage on token exchange
        _tokens[f"code:{claude_code}"] = {
            "access_token": token_data["access_token"],
            "token_type": token_data.get("token_type", "bearer"),
            "expires_in": token_data.get("expires_in", TOKEN_EXPIRY_SECONDS),
            "refresh_token": token_data.get("refresh_token"),
            "user_id": token_data.get("user_id"),
            "timestamp": time.time(),
            "original_client_id": original.get("client_id")
        }
        
        # Redirect back to Claude
        redirect_url = f"{original['redirect_uri']}?code={claude_code}&state={original['state']}"
        print(f"[Callback] Redirecting to Claude")
        return RedirectResponse(redirect_url)
        
    except Exception as e:
        print(f"[Callback ERROR] {str(e)}")
        return JSONResponse({"error": str(e)}, status_code=500)


@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request):
    """Token endpoint for Claude"""
    form = await request.form()
    code = form.get("code")
    client_id = form.get("client_id")
    
    print(f"[Token] Exchange request from client: {client_id}")
    
    if not code:
        return JSONResponse({"error": "missing_code"}, status_code=400)
    
    code_key = f"code:{code}"
    token_data = _tokens.get(code_key)
    if not token_data:
        return JSONResponse({"error": "invalid_code"}, status_code=400)
    
    # Remove the code-based entry (one-time use)
    del _tokens[code_key]
    
    # Generate a session ID for this token exchange
    # In production, this should come from the MCP session
    # For now, we use client_id + a unique identifier
    session_id = hashlib.sha256(f"{client_id}:{code}".encode()).hexdigest()[:32]
    
    # Store by session ID
    token_data["session_id"] = session_id
    token_data["exchanged"] = True
    _tokens[session_id] = token_data
    
    print(f"[Token] Issued token for session: {session_id[:8]}...")
    
    return JSONResponse({
        "access_token": token_data["access_token"],
        "token_type": token_data["token_type"],
        "expires_in": token_data["expires_in"],
        "scope": "read write offline"
    })


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
async def get_my_courses(ctx: Context) -> str:
    """
    Get all courses you have access to in Blackboard.
    Requires authentication.
    """
    try:
        session_id = get_session_id(ctx)
        token = get_token_for_session(session_id)
    except Exception as e:
        return f"Error: {str(e)}"
    
    print(f"[Tool] get_my_courses - session: {session_id[:8]}...")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses?limit=100",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            print(f"[Tool] Blackboard API response: {response.status_code}")
            
            if response.status_code == 401:
                # Token might be invalid, clear it
                if session_id in _tokens:
                    del _tokens[session_id]
                return "Error: Authentication expired. Please log in again."
            
            if response.status_code != 200:
                return f"Error: {response.status_code} - {response.text}"
            
            data = response.json()
            courses = data.get("results", [])
            
            if not courses:
                return "No courses found"
            
            result = f"Found {len(courses)} courses:\n\n"
            for course in courses:
                result += f"- {course.get('name', 'Unnamed')} (ID: {course.get('id')})\n"
            
            return result
    except Exception as e:
        print(f"[Tool ERROR] {str(e)}")
        return f"Error calling Blackboard API: {str(e)}"


@mcp.tool()
async def get_course_assignments(ctx: Context, course_id: str) -> str:
    """
    Get assignments for a specific course.
    
    Args:
        course_id: The course ID from get_my_courses (e.g., "_123_1")
    """
    try:
        session_id = get_session_id(ctx)
        token = get_token_for_session(session_id)
    except Exception as e:
        return f"Error: {str(e)}"
    
    print(f"[Tool] get_course_assignments for course: {course_id}, session: {session_id[:8]}...")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses/{course_id}/gradebook/columns",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            if response.status_code == 401:
                if session_id in _tokens:
                    del _tokens[session_id]
                return "Error: Authentication expired. Please log in again."
            
            if response.status_code != 200:
                return f"Error: {response.status_code} - {response.text}"
            
            data = response.json()
            columns = data.get("results", [])
            
            # Filter to assignments with due dates  
            assignments = [c for c in columns if c.get("grading", {}).get("due")]
            
            if not assignments:
                return f"No assignments with due dates found in course {course_id}"
            
            result = f"Found {len(assignments)} assignments:\n\n"
            for assignment in assignments:
                name = assignment.get("name", "Unnamed")
                points = assignment.get("score", {}).get("possible", "?")
                due = assignment.get("grading", {}).get("due", "No due date")
                result += f"- {name} ({points} points) - Due: {due}\n"
            
            return result
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def get_current_user(ctx: Context) -> str:
    """
    Get information about the currently authenticated Blackboard user.
    Returns details like name, username, email, and user ID.
    """
    try:
        session_id = get_session_id(ctx)
        token = get_token_for_session(session_id)
    except Exception as e:
        return f"Error: {str(e)}"
    
    print(f"[Tool] get_current_user - session: {session_id[:8]}...")
    
    try:
        async with httpx.AsyncClient() as client:
            # Use 'me' as the userId to get the current authenticated user
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            print(f"[Tool] Blackboard API response: {response.status_code}")
            
            if response.status_code == 401:
                if session_id in _tokens:
                    del _tokens[session_id]
                return "Error: Authentication expired. Please log in again."
            
            if response.status_code != 200:
                return f"Error: {response.status_code} - {response.text}"
            
            user = response.json()
            
            # Format user information nicely
            result = "Current Authenticated User:\n\n"
            result += f"User ID: {user.get('id', 'N/A')}\n"
            result += f"UUID: {user.get('uuid', 'N/A')}\n"
            result += f"Username: {user.get('userName', 'N/A')}\n"
            
            # Name information
            name = user.get('name', {})
            given = name.get('given', '')
            family = name.get('family', '')
            if given or family:
                result += f"Name: {given} {family}\n"
            
            # Contact information
            contact = user.get('contact', {})
            email = contact.get('email', '')
            if email:
                result += f"Email: {email}\n"
            
            # External ID (student/employee ID)
            external_id = user.get('externalId', '')
            if external_id:
                result += f"External ID: {external_id}\n"
            
            # Student ID
            student_id = user.get('studentId', '')
            if student_id:
                result += f"Student ID: {student_id}\n"
            
            # Institution roles
            inst_roles = user.get('institutionRoleIds', [])
            if inst_roles:
                result += f"Institution Roles: {', '.join(inst_roles)}\n"
            
            # System roles
            sys_roles = user.get('systemRoleIds', [])
            if sys_roles:
                result += f"System Roles: {', '.join(sys_roles)}\n"
            
            # Availability
            availability = user.get('availability', {})
            available = availability.get('available', 'Unknown')
            result += f"Account Status: {available}\n"
            
            # Dates
            created = user.get('created', '')
            if created:
                result += f"Created: {created}\n"
            
            last_login = user.get('lastLogin', '')
            if last_login:
                result += f"Last Login: {last_login}\n"
            
            return result
            
    except Exception as e:
        print(f"[Tool ERROR] {str(e)}")
        return f"Error calling Blackboard API: {str(e)}"


@mcp.tool()
async def logout(ctx: Context) -> str:
    """
    Log out from Blackboard by clearing your authentication token.
    You will need to re-authenticate to use Blackboard tools again.
    """
    try:
        session_id = get_session_id(ctx)
    except Exception as e:
        return "You are not currently logged in."
    
    if session_id in _tokens:
        del _tokens[session_id]
        print(f"[Tool] Logged out session: {session_id[:8]}...")
        return "Successfully logged out from Blackboard. You will need to re-authenticate to use Blackboard tools again."
    else:
        return "You are not currently logged in."


@mcp.tool()
async def check_auth_status(ctx: Context) -> str:
    """
    Check your current authentication status with Blackboard.
    """
    try:
        session_id = get_session_id(ctx)
    except Exception as e:
        return f"Unable to determine session: {str(e)}"
    
    token_data = _tokens.get(session_id)
    
    if not token_data:
        return "Not authenticated. Please log in to Blackboard."
    
    # Check expiry
    timestamp = token_data.get("timestamp", 0)
    expires_in = token_data.get("expires_in", TOKEN_EXPIRY_SECONDS)
    elapsed = time.time() - timestamp
    remaining = expires_in - elapsed
    
    if remaining <= 0:
        del _tokens[session_id]
        return "Session expired. Please log in again."
    
    user_id = token_data.get("user_id", "unknown")
    minutes_remaining = int(remaining / 60)
    
    return f"Authenticated as user: {user_id}\nSession expires in: {minutes_remaining} minutes"


@mcp.tool()
async def debug_tokens() -> str:
    """Debug tool to see stored token count (admin only)"""
    cleanup_expired_tokens()
    
    # Only show counts, not actual tokens for security
    code_tokens = sum(1 for k in _tokens if k.startswith("code:"))
    session_tokens = len(_tokens) - code_tokens
    
    return (
        f"Token storage status:\n"
        f"- Pending auth codes: {code_tokens}\n"
        f"- Active sessions: {session_tokens}\n"
        f"- Pending OAuth flows: {len(_pending_auths)}"
    )


@mcp.tool()
async def check_config() -> str:
    """Check server configuration and OAuth endpoints"""
    return (
        f"Blackboard URL: {BLACKBOARD_URL}\n"
        f"App Key: {BLACKBOARD_APP_KEY[:8]}...\n"
        f"Server URL: {SERVER_URL}\n"
        f"\nOAuth Endpoints:\n"
        f"- Discovery: {SERVER_URL}/.well-known/oauth-authorization-server\n"
        f"- Authorize: {SERVER_URL}/oauth/authorize\n"
        f"- Token: {SERVER_URL}/oauth/token\n"
        f"- Callback: {SERVER_URL}/oauth/callback\n"
    )
