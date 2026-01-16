"""
Blackboard MCP Server - Cloud Version with Custom OAuth
Adapts the working local OAuth flow for FastMCP Cloud
"""
import os
import base64
import secrets
import time
import httpx
from urllib.parse import urlencode
from fastmcp import FastMCP
from starlette.responses import RedirectResponse, JSONResponse, Response
from starlette.requests import Request
from starlette.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

# ============================================================================
# CONFIGURATION
# ============================================================================
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL", "https://anthropic.bt-retool.shop")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY", "a743ef51-d7bc-4a7e-97e6-bae6f086a0d4")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET", "2DXuZHi9QFZgKfIAkt8JJKhVWDBRdT0q")
SERVER_URL = os.environ.get("SERVER_URL", "https://blackboard-mcp.fastmcp.app")

# ============================================================================
# MCP SERVER
# ============================================================================
mcp = FastMCP("Blackboard")

# Store pending OAuth flows and tokens in memory
_pending_auths = {}
_tokens = {}


# ============================================================================
# AUTHENTICATION MIDDLEWARE (ASGI-level)
# ============================================================================

class BlackboardAuthMiddleware(BaseHTTPMiddleware):
    """
    ASGI middleware that validates tokens at the HTTP level.
    Returns proper 401 with WWW-Authenticate header to trigger OAuth flow.
    """
    
    # Paths that don't require authentication
    PUBLIC_PATHS = [
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource", 
        "/oauth/authorize",
        "/oauth/callback",
        "/oauth/token",
        "/oauth/register",
    ]
    
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        # Allow public OAuth endpoints without auth
        if any(path.startswith(p) for p in self.PUBLIC_PATHS):
            return await call_next(request)
        
        # Check for Bearer token
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return self._unauthorized_response()
        
        token = auth_header[7:]
        
        # Validate token against Blackboard
        is_valid = await self._validate_token_with_blackboard(token)
        if not is_valid:
            return self._unauthorized_response()
        
        # Token is valid, continue
        return await call_next(request)
    
    async def _validate_token_with_blackboard(self, token: str) -> bool:
        """Check if token is valid by making a test call to Blackboard API"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10.0
                )
                return response.status_code == 200
        except Exception as e:
            print(f"[Auth] Token validation error: {e}")
            return False
    
    def _unauthorized_response(self) -> Response:
        """Return 401 with WWW-Authenticate header to trigger OAuth flow"""
        return Response(
            content='{"error": "unauthorized", "message": "Authentication required"}',
            status_code=401,
            media_type="application/json",
            headers={
                "WWW-Authenticate": f'Bearer resource_metadata="{SERVER_URL}/.well-known/oauth-protected-resource", scope="read write offline"'
            }
        )


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
        "registration_endpoint": f"{SERVER_URL}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "scopes_supported": ["read", "write", "offline"]
    })


@mcp.custom_route("/oauth/register", methods=["POST"])
async def oauth_register(request):
    """Dynamic Client Registration - accepts any client (proxy pattern)"""
    try:
        body = await request.json()
    except:
        body = {}
    
    client_id = secrets.token_urlsafe(16)
    redirect_uris = body.get("redirect_uris", [])
    
    print(f"[OAuth] Client registration: {client_id}")
    
    return JSONResponse({
        "client_id": client_id,
        "client_secret": "",
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none"
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
        
        # Generate code for Claude
        claude_code = secrets.token_urlsafe(32)
        
        _tokens[claude_code] = {
            "access_token": token_data["access_token"],
            "token_type": token_data.get("token_type", "bearer"),
            "expires_in": token_data.get("expires_in", 3600),
            "refresh_token": token_data.get("refresh_token"),
            "user_id": token_data.get("user_id"),
            "timestamp": time.time()
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
    
    print(f"[Token] Exchange request")
    
    if not code:
        return JSONResponse({"error": "missing_code"}, status_code=400)
    
    token_data = _tokens.get(code)
    if not token_data:
        return JSONResponse({"error": "invalid_code"}, status_code=400)
    
    # Mark as exchanged and store by access token
    token_data["exchanged"] = True
    _tokens[token_data["access_token"]] = token_data
    
    print(f"[Token] Returning token to Claude: {token_data['access_token'][:10]}...")
    
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
        "authorization_servers": [SERVER_URL],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["read", "write", "offline"]
    })


# ============================================================================
# HELPER: Make Blackboard API calls
# ============================================================================

async def blackboard_request(method: str, endpoint: str, token: str, **kwargs) -> httpx.Response:
    """Make a request to Blackboard API."""
    async with httpx.AsyncClient() as client:
        response = await client.request(
            method,
            f"{BLACKBOARD_URL}{endpoint}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
            **kwargs
        )
        print(f"[Blackboard API] {method} {endpoint} -> {response.status_code}")
        return response


def get_token_from_header(request_headers: dict) -> str:
    """Extract Bearer token from Authorization header"""
    auth_header = request_headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return ""


# ============================================================================
# MCP TOOLS
# ============================================================================

@mcp.tool()
async def get_my_courses() -> str:
    """
    Get all courses you have access to in Blackboard.
    Requires authentication.
    """
    # Get token from request context
    from fastmcp.server.dependencies import get_http_headers
    headers = get_http_headers()
    token = get_token_from_header(headers)
    
    if not token:
        return "Error: No authentication token found"
    
    response = await blackboard_request("GET", "/learn/api/public/v1/courses?limit=100", token)
    
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


@mcp.tool()
async def get_course_assignments(course_id: str) -> str:
    """
    Get assignments for a specific course.
    
    Args:
        course_id: The course ID from get_my_courses (e.g., "_123_1")
    """
    from fastmcp.server.dependencies import get_http_headers
    headers = get_http_headers()
    token = get_token_from_header(headers)
    
    if not token:
        return "Error: No authentication token found"
    
    response = await blackboard_request(
        "GET",
        f"/learn/api/public/v1/courses/{course_id}/gradebook/columns",
        token
    )
    
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


@mcp.tool()
async def debug_tokens() -> str:
    """Debug tool to see stored tokens"""
    if not _tokens:
        return "No tokens stored"
    
    return f"Found {len(_tokens)} token(s). Latest user: {list(_tokens.values())[-1].get('user_id', 'unknown')}"


@mcp.tool()
async def check_config() -> str:
    """Check server configuration and OAuth endpoints"""
    return (
        f"Blackboard URL: {BLACKBOARD_URL}\n"
        f"App Key: {BLACKBOARD_APP_KEY[:8]}...\n"
        f"Server URL: {SERVER_URL}\n"
        f"\nOAuth Endpoints:\n"
        f"- Discovery: {SERVER_URL}/.well-known/oauth-authorization-server\n"
        f"- Protected Resource: {SERVER_URL}/.well-known/oauth-protected-resource\n"
        f"- Register: {SERVER_URL}/oauth/register\n"
        f"- Authorize: {SERVER_URL}/oauth/authorize\n"
        f"- Token: {SERVER_URL}/oauth/token\n"
        f"- Callback: {SERVER_URL}/oauth/callback\n"
    )


# ============================================================================
# APP SETUP - Add middleware to the ASGI app
# ============================================================================

def create_app():
    """Create the ASGI app with authentication middleware"""
    from starlette.applications import Starlette
    
    # Get the base app from FastMCP
    app = mcp.http_app()
    
    # Add our auth middleware
    app.add_middleware(BlackboardAuthMiddleware)
    
    return app


# For FastMCP Cloud deployment
app = create_app()
