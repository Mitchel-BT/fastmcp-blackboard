"""
Blackboard MCP Server - Cloud Version with Custom OAuth
Adapts the working local OAuth flow for FastMCP Cloud
"""
import os
import base64
import secrets
import time
import httpx
from urllib.parse import urlencode, parse_qs
from fastmcp import FastMCP
from starlette.responses import RedirectResponse, JSONResponse, HTMLResponse

# ============================================================================
# CONFIGURATION
# ============================================================================
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL", "https://anthropic.bt-retool.shop")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY", "a743ef51-d7bc-4a7e-97e6-bae6f086a0d4")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET", "2DXuZHi9QFZgKfIAkt8JJKhVWDBRdT0q")
SERVER_URL = os.environ.get("SERVER_URL", "https://blackboard-mcp.fastmcp.app")

# ============================================================================
# MCP SERVER (NO AUTH - We'll handle it manually)
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
    """OAuth server configuration - directs clients to our authorize endpoint"""
    return JSONResponse({
        "issuer": SERVER_URL,
        "authorization_endpoint": f"{SERVER_URL}/oauth/authorize",
        "token_endpoint": f"{SERVER_URL}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
    })


@mcp.custom_route("/oauth/authorize", methods=["GET"])
async def oauth_authorize(request):
    """
    OAuth authorization endpoint - redirects to Blackboard for actual auth
    This is called by Claude when it wants to authenticate
    """
    # Get OAuth params from Claude
    client_id = request.query_params.get("client_id")
    redirect_uri = request.query_params.get("redirect_uri")
    state = request.query_params.get("state")
    code_challenge = request.query_params.get("code_challenge")
    
    print(f"[OAuth] Authorization request from Claude")
    print(f"[OAuth] Client redirect_uri: {redirect_uri}")
    print(f"[OAuth] State: {state}")
    
    # Generate our own state to track this flow
    our_state = secrets.token_urlsafe(32)
    
    # Store the original OAuth params
    _pending_auths[our_state] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "timestamp": time.time()
    }
    
    # Build Blackboard authorization URL
    blackboard_auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?redirect_uri={SERVER_URL}/oauth/callback"
        f"&response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&scope=read%20write%20offline"
        f"&state={our_state}"
    )
    
    print(f"[OAuth] Redirecting to Blackboard: {blackboard_auth_url[:80]}...")
    
    # Redirect user to Blackboard for authentication
    return RedirectResponse(blackboard_auth_url)


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request):
    """
    OAuth callback from Blackboard
    Exchange the code for a token, then redirect back to Claude
    """
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    print(f"[Callback] Received from Blackboard")
    print(f"[Callback] Code: {'present' if code else 'missing'}")
    print(f"[Callback] State: {state[:8]}..." if state else "missing")
    
    if error:
        return JSONResponse({"error": error}, status_code=400)
    
    if not code or not state:
        return JSONResponse({"error": "missing_parameters"}, status_code=400)
    
    # Get the original OAuth flow
    original = _pending_auths.get(state)
    if not original:
        return JSONResponse({"error": "invalid_state"}, status_code=400)
    
    # Remove from pending
    del _pending_auths[state]
    
    try:
        # Exchange code with Blackboard for token
        print(f"[Callback] Exchanging code with Blackboard...")
        
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
                print(f"[Callback ERROR] Token exchange failed: {response.text}")
                return JSONResponse({"error": "token_exchange_failed"}, status_code=500)
            
            token_data = response.json()
            print(f"[Callback] Successfully got token from Blackboard")
        
        # Generate a code to give back to Claude
        claude_code = secrets.token_urlsafe(32)
        
        # Store the Blackboard token mapped to this code
        _tokens[claude_code] = {
            "access_token": token_data["access_token"],
            "token_type": token_data.get("token_type", "bearer"),
            "expires_in": token_data.get("expires_in", 3600),
            "refresh_token": token_data.get("refresh_token"),
            "user_id": token_data.get("user_id"),
            "timestamp": time.time()
        }
        
        # Redirect back to Claude with the code
        claude_callback = original["redirect_uri"]
        redirect_url = f"{claude_callback}?code={claude_code}&state={original['state']}"
        
        print(f"[Callback] Redirecting to Claude: {redirect_url[:60]}...")
        return RedirectResponse(redirect_url)
        
    except Exception as e:
        print(f"[Callback ERROR] {str(e)}")
        return JSONResponse({"error": str(e)}, status_code=500)


@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request):
    """
    Token endpoint - Claude exchanges the code for an access token
    """
    form = await request.form()
    grant_type = form.get("grant_type")
    code = form.get("code")
    
    print(f"[Token] Token exchange request")
    print(f"[Token] Grant type: {grant_type}")
    print(f"[Token] Code: {code[:8]}..." if code else "missing")
    
    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    
    if not code:
        return JSONResponse({"error": "missing_code"}, status_code=400)
    
    # Get the stored token
    token_data = _tokens.get(code)
    if not token_data:
        return JSONResponse({"error": "invalid_code"}, status_code=400)
    
    # Return the token to Claude
    print(f"[Token] Returning access token to Claude")
    
    return JSONResponse({
        "access_token": token_data["access_token"],
        "token_type": token_data["token_type"],
        "expires_in": token_data["expires_in"],
        "scope": "read write offline"
    })


# ============================================================================
# MCP TOOLS
# ============================================================================

@mcp.tool()
async def get_my_courses() -> str:
    """Get all courses the authenticated user has access to"""
    # Note: The token will be in the MCP context after authentication
    # For now, return a message
    return "Authentication flow configured. Please authenticate through Claude."


@mcp.tool()
async def check_config() -> str:
    """Check server configuration"""
    return (
        f"Blackboard URL: {BLACKBOARD_URL}\n"
        f"App Key: {BLACKBOARD_APP_KEY[:8]}...\n"
        f"Server URL: {SERVER_URL}\n"
        f"Authorization endpoint: {SERVER_URL}/oauth/authorize\n"
        f"Callback URL: {SERVER_URL}/oauth/callback\n"
    )
