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
    
    # Don't delete the token - keep it for tool calls
    # Just mark it as used
    token_data["exchanged"] = True
    
    # Also store by access token for easy lookup
    _tokens[token_data["access_token"]] = token_data
    
    print(f"[Token] Returning token to Claude: {token_data['access_token'][:10]}...")
    
    return JSONResponse({
        "access_token": token_data["access_token"],
        "token_type": token_data["token_type"],
        "expires_in": token_data["expires_in"],
        "scope": "read write offline"
    })


# ============================================================================
# MIDDLEWARE TO REQUIRE AUTH
# ============================================================================

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

# ============================================================================
# MCP TOOLS
# ============================================================================

def check_authentication():
    """Check if we have a valid token, raise 401 with proper headers if not"""
    # Try to get token from request context first
    try:
        from fastmcp.server.context import request_ctx
        ctx = request_ctx.get()
        auth_header = ctx.request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if token not in _tokens:
                _tokens[token] = {"access_token": token, "exchanged": True}
            return token
    except Exception:
        pass
    
    # Fall back to stored tokens
    if _tokens:
        for value in _tokens.values():
            if value.get("exchanged") and "access_token" in value:
                return value["access_token"]
        for value in _tokens.values():
            if "access_token" in value and len(value["access_token"]) > 20:
                return value["access_token"]
    
    # THIS IS THE KEY: Include WWW-Authenticate header with resource_metadata
    raise HTTPException(
        status_code=401,
        detail="Authentication required",
        headers={
            "WWW-Authenticate": f'Bearer resource_metadata="{SERVER_URL}/.well-known/oauth-protected-resource", scope="read write offline"'
        }
    )
@mcp.tool()
async def get_my_courses() -> str:
    """
    Get all courses you have access to in Blackboard.
    Requires authentication.
    """
    token = check_authentication()  # Let HTTPException propagate (don't catch it)
    
    print(f"[Tool] get_my_courses - using token: {token[:10]}...")
    
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses?limit=100",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            print(f"[Tool] Blackboard API response: {response.status_code}")
            
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
async def get_course_assignments(course_id: str) -> str:
    """
    Get assignments for a specific course.
    
    Args:
        course_id: The course ID from get_my_courses (e.g., "_123_1")
    """
    if not _tokens:
        return "Error: Not authenticated."
    
    latest_token = list(_tokens.values())[-1]
    token = latest_token["access_token"]
    
    print(f"[Tool] get_course_assignments for course: {course_id}")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses/{course_id}/gradebook/columns",
                headers={"Authorization": f"Bearer {token}"}
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
    except Exception as e:
        return f"Error: {str(e)}"


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
        f"- Authorize: {SERVER_URL}/oauth/authorize\n"
        f"- Token: {SERVER_URL}/oauth/token\n"
        f"- Callback: {SERVER_URL}/oauth/callback\n"
    )
