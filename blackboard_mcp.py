"""
Blackboard MCP Server - Cloud Version with Custom OAuth
Provides authentication links directly in tool responses
"""
import os
import base64
import secrets
import time
import httpx
from urllib.parse import urlencode, quote
from fastmcp import FastMCP
from starlette.responses import RedirectResponse, JSONResponse, HTMLResponse
from starlette.requests import Request

# ============================================================================
# CONFIGURATION - All secrets loaded from environment variables
# ============================================================================
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET")
SERVER_URL = os.environ.get("SERVER_URL")

# Validate required environment variables
_required_vars = ["BLACKBOARD_URL", "BLACKBOARD_APP_KEY", "BLACKBOARD_APP_SECRET", "SERVER_URL"]
_missing = [var for var in _required_vars if not os.environ.get(var)]
if _missing:
    raise EnvironmentError(f"Missing required environment variables: {', '.join(_missing)}")

# ============================================================================
# MCP SERVER
# ============================================================================
mcp = FastMCP("Blackboard")

# Store pending OAuth flows and tokens in memory
_pending_auths = {}
_tokens = {}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_auth_link() -> str:
    """Generate an authentication link for the user"""
    our_state = secrets.token_urlsafe(32)
    
    _pending_auths[our_state] = {
        "timestamp": time.time()
    }
    
    callback_uri = f"{SERVER_URL}/oauth/callback"
    
    blackboard_auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&redirect_uri={quote(callback_uri, safe='')}"
        f"&scope=read+write+offline"
        f"&state={our_state}"
    )
    
    return blackboard_auth_url


def get_access_token() -> str | None:
    """Get a valid access token if available"""
    if not _tokens:
        return None
    
    latest_token = max(_tokens.values(), key=lambda x: x['timestamp'])
    
    age = time.time() - latest_token['timestamp']
    if age > (latest_token.get('expires_in', 3600) - 300):
        return None
    
    return latest_token['access_token']


def get_current_user_id() -> str | None:
    """Get the user ID from the stored token"""
    if not _tokens:
        return None
    
    latest_token = max(_tokens.values(), key=lambda x: x['timestamp'])
    return latest_token.get('user_id')


async def make_blackboard_request(endpoint: str, method: str = "GET", **kwargs):
    """Make an authenticated request to Blackboard API"""
    token = get_access_token()
    
    if not token:
        auth_url = get_auth_link()
        return {
            "error": "authentication_required",
            "message": "Please authenticate with Blackboard by clicking this link:",
            "auth_url": auth_url
        }
    
    url = f"{BLACKBOARD_URL}/learn/api/public/v1/{endpoint}"
    headers = {
        "Authorization": f"Bearer {token}",
        **kwargs.pop("headers", {})
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.request(method, url, headers=headers, **kwargs)
            
            if response.status_code == 401:
                auth_url = get_auth_link()
                return {
                    "error": "authentication_required",
                    "message": "Your session has expired. Please authenticate again:",
                    "auth_url": auth_url
                }
            
            response.raise_for_status()
            return response.json()
            
    except httpx.HTTPStatusError as e:
        return {
            "error": "api_error",
            "message": f"Blackboard API error: {e.response.status_code}",
            "details": e.response.text
        }
    except Exception as e:
        return {
            "error": "request_failed",
            "message": str(e)
        }


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
    """OAuth authorization endpoint - redirects immediately to Blackboard"""
    client_id = request.query_params.get("client_id")
    redirect_uri = request.query_params.get("redirect_uri")
    state = request.query_params.get("state")
    code_challenge = request.query_params.get("code_challenge")
    
    print(f"[OAuth] Authorization request")
    
    our_state = secrets.token_urlsafe(32)
    
    _pending_auths[our_state] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "timestamp": time.time()
    }
    
    callback_uri = f"{SERVER_URL}/oauth/callback"
    
    blackboard_auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&redirect_uri={quote(callback_uri, safe='')}"
        f"&scope=read+write+offline"
        f"&state={our_state}"
    )
    
    return RedirectResponse(blackboard_auth_url)


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request):
    """OAuth callback from Blackboard"""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    print(f"[Callback] Received from Blackboard")
    
    if error:
        return HTMLResponse(
            f"""
            <html>
            <body style="font-family: sans-serif; padding: 2rem; text-align: center;">
                <h1>❌ Authentication Error</h1>
                <p>{error}</p>
                <p>You can close this window and try again.</p>
            </body>
            </html>
            """, 
            status_code=400
        )
    
    if not code or not state:
        return HTMLResponse(
            """
            <html>
            <body style="font-family: sans-serif; padding: 2rem; text-align: center;">
                <h1>❌ Error</h1>
                <p>Missing required parameters</p>
            </body>
            </html>
            """, 
            status_code=400
        )
    
    original = _pending_auths.get(state)
    if not original:
        return HTMLResponse(
            """
            <html>
            <body style="font-family: sans-serif; padding: 2rem; text-align: center;">
                <h1>❌ Error</h1>
                <p>Invalid or expired authentication session</p>
            </body>
            </html>
            """, 
            status_code=400
        )
    
    del _pending_auths[state]
    
    try:
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
                return HTMLResponse(
                    f"""
                    <html>
                    <body style="font-family: sans-serif; padding: 2rem; text-align: center;">
                        <h1>❌ Token Exchange Failed</h1>
                        <p>{response.text}</p>
                    </body>
                    </html>
                    """, 
                    status_code=500
                )
            
            token_data = response.json()
            print(f"[Callback] Got token from Blackboard")
        
        claude_code = secrets.token_urlsafe(32)
        
        _tokens[claude_code] = {
            "access_token": token_data["access_token"],
            "token_type": token_data.get("token_type", "bearer"),
            "expires_in": token_data.get("expires_in", 3600),
            "refresh_token": token_data.get("refresh_token"),
            "user_id": token_data.get("user_id"),
            "timestamp": time.time()
        }
        
        if original.get("redirect_uri"):
            redirect_url = f"{original['redirect_uri']}?code={claude_code}&state={original['state']}"
            print(f"[Callback] Redirecting to Claude")
            return RedirectResponse(redirect_url)
        else:
            return HTMLResponse(
                """
                <html>
                <body style="font-family: sans-serif; padding: 2rem; text-align: center;">
                    <h1>✅ Authentication Successful!</h1>
                    <p>You can now close this window and return to Claude.</p>
                    <p>Your Blackboard account is connected.</p>
                </body>
                </html>
                """
            )
        
    except Exception as e:
        print(f"[Callback ERROR] {str(e)}")
        return HTMLResponse(
            f"""
            <html>
            <body style="font-family: sans-serif; padding: 2rem; text-align: center;">
                <h1>❌ Error</h1>
                <p>{str(e)}</p>
            </body>
            </html>
            """, 
            status_code=500
        )


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
    
    print(f"[Token] Returning token to Claude")
    
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
async def get_my_courses() -> dict:
    """
    Get all courses you have access to in Blackboard.
    Returns authentication link if not logged in.
    """
    # Use the user memberships endpoint to get only enrolled courses
    result = await make_blackboard_request("users/me/courses")
    
    if isinstance(result, dict) and result.get("error") == "authentication_required":
        return result
    
    if isinstance(result, dict) and "results" in result:
        memberships = result["results"]
        
        # Extract course info from memberships
        courses = []
        for membership in memberships:
            courses.append({
                "courseId": membership.get("courseId"),
                "role": membership.get("courseRoleId"),
                "availability": membership.get("availability", {}).get("available"),
                "created": membership.get("created"),
                # Include the full membership data for reference
                "_membership": membership
            })
        
        return {
            "success": True,
            "courses": courses,
            "count": len(courses)
        }
    
    return result


@mcp.tool()
async def get_course_assignments(course_id: str) -> dict:
    """
    Get assignments for a specific course.
    
    Args:
        course_id: The course ID from get_my_courses (e.g., "_123_1")
    """
    result = await make_blackboard_request(f"courses/{course_id}/contents")
    
    if isinstance(result, dict) and result.get("error") == "authentication_required":
        return result
    
    return result


@mcp.tool()
async def check_config() -> str:
    """Check server configuration and OAuth endpoints"""
    token_status = "No tokens stored"
    if _tokens:
        latest = max(_tokens.values(), key=lambda x: x['timestamp'])
        age = int(time.time() - latest['timestamp'])
        token_status = f"Token exists (age: {age}s, user: {latest.get('user_id', 'N/A')})"
    
    # Mask the app key for security
    masked_key = f"{BLACKBOARD_APP_KEY[:8]}..." if BLACKBOARD_APP_KEY else "Not set"
    
    return (
        f"Blackboard URL: {BLACKBOARD_URL}\n"
        f"App Key: {masked_key}\n"
        f"Server URL: {SERVER_URL}\n"
        f"\nToken Status: {token_status}\n"
        f"\nOAuth Endpoints:\n"
        f"- Discovery: {SERVER_URL}/.well-known/oauth-authorization-server\n"
        f"- Authorize: {SERVER_URL}/oauth/authorize\n"
        f"- Token: {SERVER_URL}/oauth/token\n"
        f"- Callback: {SERVER_URL}/oauth/callback\n"
    )


@mcp.tool()
async def debug_tokens() -> str:
    """Debug tool to see stored tokens"""
    if not _tokens:
        return "No tokens stored"
    
    token_info = []
    for code, data in _tokens.items():
        age = int(time.time() - data['timestamp'])
        expires_in = data.get('expires_in', 3600)
        status = "expired" if age > expires_in else "valid"
        token_info.append(
            f"Code: {code[:16]}... | User: {data.get('user_id', 'N/A')} | "
            f"Age: {age}s / {expires_in}s | Status: {status}"
        )
    
    return "\n".join(token_info)
