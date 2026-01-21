"""
Blackboard MCP Server - Cloud Version with Custom OAuth
Adapts the working local OAuth flow for FastMCP Cloud
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


@mcp.custom_route("/oauth/start", methods=["GET"])
async def oauth_start(request):
    """Generate and return an authorization URL for the user to click"""
    # Generate state to track this flow
    our_state = secrets.token_urlsafe(32)
    
    # Store minimal info - we'll get the rest when callback happens
    _pending_auths[our_state] = {
        "timestamp": time.time()
    }
    
    # Build the Blackboard auth URL
    callback_uri = f"{SERVER_URL}/oauth/callback"
    
    blackboard_auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&redirect_uri={quote(callback_uri, safe='')}"
        f"&scope=read+write+offline"
        f"&state={our_state}"
    )
    
    print(f"[OAuth Start] Generated auth URL")
    
    return JSONResponse({
        "auth_url": blackboard_auth_url,
        "message": "Please click this link to authenticate with Blackboard"
    })


@mcp.custom_route("/oauth/authorize", methods=["GET"])
async def oauth_authorize(request):
    """OAuth authorization endpoint - redirects immediately to Blackboard"""
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
    
    # Build the Blackboard auth URL with proper encoding
    callback_uri = f"{SERVER_URL}/oauth/callback"
    
    blackboard_auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&redirect_uri={quote(callback_uri, safe='')}"
        f"&scope=read+write+offline"
        f"&state={our_state}"
    )
    
    print(f"[OAuth] Redirecting to: {blackboard_auth_url[:100]}...")
    
    # Redirect directly to Blackboard
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
                <p>You can close this window and try again.</p>
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
                <p>You can close this window and try again.</p>
            </body>
            </html>
            """, 
            status_code=400
        )
    
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
                return HTMLResponse(
                    f"""
                    <html>
                    <body style="font-family: sans-serif; padding: 2rem; text-align: center;">
                        <h1>❌ Token Exchange Failed</h1>
                        <p>{response.text}</p>
                        <p>You can close this window and try again.</p>
                    </body>
                    </html>
                    """, 
                    status_code=500
                )
            
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
        
        # If we have the original redirect_uri (from Claude), redirect back
        if original.get("redirect_uri"):
            redirect_url = f"{original['redirect_uri']}?code={claude_code}&state={original['state']}"
            print(f"[Callback] Redirecting to Claude")
            return RedirectResponse(redirect_url)
        else:
            # Otherwise, show success page
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
                <p>You can close this window and try again.</p>
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
# MCP TOOLS (These will automatically require authentication)
# ============================================================================

@mcp.tool()
async def get_my_courses() -> str:
    """
    Get all courses you have access to in Blackboard.
    This will prompt for authentication if needed.
    """
    # Claude will automatically inject the access token
    # For now, return instructions
    return (
        "To use this tool, Claude needs to authenticate with Blackboard first.\n"
        "You should be prompted to log in. If not, try reconnecting the MCP server."
    )


@mcp.tool()
async def get_course_assignments(course_id: str) -> str:
    """
    Get assignments for a specific course.
    
    Args:
        course_id: The course ID from get_my_courses (e.g., "_123_1")
    """
    return f"Getting assignments for course {course_id}..."


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
        f"- Start: {SERVER_URL}/oauth/start\n"
    )


@mcp.tool()
async def debug_tokens() -> str:
    """Debug tool to see stored tokens"""
    if not _tokens:
        return "No tokens stored"
    
    token_info = []
    for code, data in _tokens.items():
        token_info.append(f"Code: {code[:16]}... | User: {data.get('user_id', 'N/A')} | Age: {int(time.time() - data['timestamp'])}s")
    
    return "\n".join(token_info)
