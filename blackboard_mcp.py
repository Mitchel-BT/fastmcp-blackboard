"""
Blackboard MCP Server - User Token Authentication
User completes OAuth once, receives a personal access token, and provides it when using tools.
"""
import os
import base64
import secrets
import time
import httpx
from urllib.parse import quote
from fastmcp import FastMCP
from starlette.responses import RedirectResponse, JSONResponse, HTMLResponse

# ============================================================================
# CONFIGURATION
# ============================================================================
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET")
SERVER_URL = os.environ.get("SERVER_URL")

_required_vars = ["BLACKBOARD_URL", "BLACKBOARD_APP_KEY", "BLACKBOARD_APP_SECRET", "SERVER_URL"]
_missing = [var for var in _required_vars if not os.environ.get(var)]
if _missing:
    raise EnvironmentError(f"Missing required environment variables: {', '.join(_missing)}")

# ============================================================================
# MCP SERVER
# ============================================================================
mcp = FastMCP("Blackboard")

# Storage
_pending_auths = {}  # Temporary OAuth state
_user_tokens = {}    # user_token -> blackboard credentials


# ============================================================================
# TOKEN HELPERS
# ============================================================================

def generate_user_token() -> str:
    """Generate a random opaque token (not derived from any user data)"""
    return secrets.token_urlsafe(24)  # 32 chars, URL-safe


def store_user_credentials(user_token: str, bb_access_token: str, bb_refresh_token: str, 
                           user_id: str, expires_in: int):
    """Store Blackboard credentials mapped to our opaque user token"""
    _user_tokens[user_token] = {
        "bb_access_token": bb_access_token,
        "bb_refresh_token": bb_refresh_token,
        "bb_user_id": user_id,
        "bb_expires_in": expires_in,
        "obtained_at": time.time()
    }


def get_bb_token(user_token: str) -> str | None:
    """Get Blackboard access token for a user token"""
    creds = _user_tokens.get(user_token)
    if not creds:
        return None
    
    # Check if expired (with 5 min buffer)
    age = time.time() - creds["obtained_at"]
    if age > (creds["bb_expires_in"] - 300):
        # TODO: Could auto-refresh here using bb_refresh_token
        return None
    
    return creds["bb_access_token"]


def get_user_info(user_token: str) -> dict | None:
    """Get user info for a token (without exposing BB credentials)"""
    creds = _user_tokens.get(user_token)
    if not creds:
        return None
    
    age = time.time() - creds["obtained_at"]
    return {
        "user_id": creds["bb_user_id"],
        "token_age_seconds": int(age),
        "expires_in_seconds": max(0, int(creds["bb_expires_in"] - age))
    }


# ============================================================================
# BLACKBOARD API HELPER
# ============================================================================

async def make_blackboard_request(user_token: str, endpoint: str, method: str = "GET", **kwargs):
    """Make authenticated request to Blackboard API"""
    
    if not user_token:
        return {
            "error": "missing_token",
            "message": "Please provide your access token. Get one at:",
            "auth_url": f"{SERVER_URL}/auth/start"
        }
    
    bb_token = get_bb_token(user_token)
    
    if not bb_token:
        return {
            "error": "invalid_or_expired_token",
            "message": "Your token is invalid or expired. Please re-authenticate at:",
            "auth_url": f"{SERVER_URL}/auth/start"
        }
    
    url = f"{BLACKBOARD_URL}/learn/api/public/v1/{endpoint}"
    headers = {"Authorization": f"Bearer {bb_token}", **kwargs.pop("headers", {})}
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.request(method, url, headers=headers, **kwargs)
            
            if response.status_code == 401:
                return {
                    "error": "session_expired",
                    "message": "Your Blackboard session expired. Please re-authenticate at:",
                    "auth_url": f"{SERVER_URL}/auth/start"
                }
            
            response.raise_for_status()
            return response.json()
            
    except httpx.HTTPStatusError as e:
        return {"error": "api_error", "status": e.response.status_code, "details": e.response.text}
    except Exception as e:
        return {"error": "request_failed", "message": str(e)}


# ============================================================================
# AUTH ROUTES
# ============================================================================

@mcp.custom_route("/auth/start", methods=["GET"])
async def auth_start(request):
    """Start the authentication flow - user visits this URL"""
    state = secrets.token_urlsafe(32)
    _pending_auths[state] = {"timestamp": time.time()}
    
    callback_uri = f"{SERVER_URL}/auth/callback"
    
    blackboard_auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&redirect_uri={quote(callback_uri, safe='')}"
        f"&scope=read+write+offline"
        f"&state={state}"
    )
    
    return RedirectResponse(blackboard_auth_url)


@mcp.custom_route("/auth/callback", methods=["GET"])
async def auth_callback(request):
    """OAuth callback from Blackboard"""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    if error:
        return HTMLResponse(error_page(f"Authentication failed: {error}"), status_code=400)
    
    if not code or not state:
        return HTMLResponse(error_page("Missing required parameters"), status_code=400)
    
    if state not in _pending_auths:
        return HTMLResponse(error_page("Invalid or expired session. Please try again."), status_code=400)
    
    del _pending_auths[state]
    
    # Exchange code for tokens
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
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": f"{SERVER_URL}/auth/callback"
                }
            )
            
            if response.status_code != 200:
                return HTMLResponse(error_page(f"Token exchange failed: {response.text}"), status_code=500)
            
            token_data = response.json()
        
        # Generate opaque user token (not derived from any BB data)
        user_token = generate_user_token()
        bb_user_id = token_data.get("user_id", "unknown")
        
        # Store BB credentials on server, mapped to our opaque token
        store_user_credentials(
            user_token=user_token,
            bb_access_token=token_data["access_token"],
            bb_refresh_token=token_data.get("refresh_token"),
            user_id=bb_user_id,
            expires_in=token_data.get("expires_in", 3600)
        )
        
        return HTMLResponse(success_page(user_token, bb_user_id))
        
    except Exception as e:
        return HTMLResponse(error_page(f"An error occurred: {str(e)}"), status_code=500)


# ============================================================================
# HTML TEMPLATES
# ============================================================================

def success_page(token: str, user_id: str) -> str:
    masked_token = "•" * 28 + token[-4:]
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Authentication Successful</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .card {{
                background: white;
                border-radius: 16px;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
                padding: 40px;
                max-width: 520px;
                width: 100%;
                text-align: center;
            }}
            .icon {{
                width: 80px;
                height: 80px;
                background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 24px;
            }}
            .icon svg {{
                width: 40px;
                height: 40px;
                color: white;
            }}
            h1 {{
                color: #1f2937;
                font-size: 24px;
                font-weight: 700;
                margin-bottom: 8px;
            }}
            .subtitle {{
                color: #6b7280;
                font-size: 14px;
                margin-bottom: 24px;
            }}
            .warning-box {{
                background: #fef3c7;
                border: 1px solid #f59e0b;
                border-radius: 8px;
                padding: 12px 16px;
                margin-bottom: 20px;
                display: flex;
                align-items: flex-start;
                gap: 10px;
                text-align: left;
            }}
            .warning-box svg {{
                width: 20px;
                height: 20px;
                color: #d97706;
                flex-shrink: 0;
                margin-top: 1px;
            }}
            .warning-box p {{
                color: #92400e;
                font-size: 13px;
                line-height: 1.4;
            }}
            .token-section {{
                background: #f9fafb;
                border: 2px solid #e5e7eb;
                border-radius: 12px;
                padding: 20px;
                margin-bottom: 20px;
            }}
            .token-label {{
                color: #374151;
                font-size: 12px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                margin-bottom: 12px;
            }}
            .token-container {{
                position: relative;
            }}
            .token-value {{
                font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
                font-size: 16px;
                color: #374151;
                background: white;
                padding: 12px 16px;
                border-radius: 8px;
                border: 1px solid #e5e7eb;
                word-break: break-all;
                min-height: 44px;
                display: flex;
                align-items: center;
                justify-content: center;
            }}
            .token-hidden {{
                color: #9ca3af;
                letter-spacing: 2px;
            }}
            .token-revealed {{
                color: #7c3aed;
            }}
            .btn-row {{
                display: flex;
                gap: 10px;
                margin-top: 16px;
            }}
            .btn {{
                flex: 1;
                padding: 12px 20px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
                border: none;
            }}
            .btn:hover {{
                transform: translateY(-2px);
            }}
            .btn-reveal {{
                background: #f3f4f6;
                color: #374151;
                border: 1px solid #d1d5db;
            }}
            .btn-reveal:hover {{
                background: #e5e7eb;
            }}
            .btn-copy {{
                background: linear-gradient(135deg, #7c3aed 0%, #6d28d9 100%);
                color: white;
            }}
            .btn-copy:hover {{
                box-shadow: 0 10px 20px -10px rgba(124, 58, 237, 0.5);
            }}
            .instructions {{
                background: #eff6ff;
                border-left: 4px solid #3b82f6;
                padding: 16px;
                border-radius: 0 8px 8px 0;
                text-align: left;
            }}
            .instructions h3 {{
                color: #1e40af;
                font-size: 14px;
                font-weight: 600;
                margin-bottom: 8px;
            }}
            .instructions p {{
                color: #1e3a8a;
                font-size: 13px;
                line-height: 1.5;
            }}
            .instructions code {{
                background: #dbeafe;
                padding: 2px 6px;
                border-radius: 4px;
                font-family: monospace;
                font-size: 12px;
            }}
            .user-info {{
                color: #9ca3af;
                font-size: 12px;
                margin-top: 20px;
            }}
            .copied-toast {{
                position: fixed;
                bottom: 30px;
                left: 50%;
                transform: translateX(-50%) translateY(100px);
                background: #1f2937;
                color: white;
                padding: 12px 24px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 500;
                opacity: 0;
                transition: transform 0.3s, opacity 0.3s;
                z-index: 1000;
            }}
            .copied-toast.show {{
                transform: translateX(-50%) translateY(0);
                opacity: 1;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="icon">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                </svg>
            </div>
            <h1>Authentication Successful!</h1>
            <p class="subtitle">Your Blackboard account is now connected</p>
            
            <div class="warning-box">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                </svg>
                <p>
                    <strong>Keep this token secret!</strong> It provides access to your Blackboard account. 
                    Copy it now and store it securely – you'll need it for this session.
                </p>
            </div>
            
            <div class="token-section">
                <div class="token-label">Your Personal Access Token</div>
                <div class="token-container">
                    <div class="token-value" id="tokenDisplay">
                        <span id="tokenText" class="token-hidden">{masked_token}</span>
                    </div>
                </div>
                <div class="btn-row">
                    <button class="btn btn-reveal" id="revealBtn" onclick="toggleReveal()">
                        👁 Reveal
                    </button>
                    <button class="btn btn-copy" onclick="copyToken()">
                        📋 Copy
                    </button>
                </div>
            </div>
            
            <div class="instructions">
                <h3>How to use this token</h3>
                <p>
                    When using Blackboard tools in Claude, provide this token as the 
                    <code>access_token</code> parameter. The token is valid for this session only.
                </p>
            </div>
            
            <p class="user-info">Authenticated as user: {user_id}</p>
        </div>
        
        <div class="copied-toast" id="toast">✓ Token copied to clipboard</div>
        
        <script>
            const actualToken = "{token}";
            const maskedToken = "{masked_token}";
            let isRevealed = false;
            let hideTimeout = null;
            
            function toggleReveal() {{
                const tokenText = document.getElementById('tokenText');
                const revealBtn = document.getElementById('revealBtn');
                
                if (isRevealed) {{
                    tokenText.textContent = maskedToken;
                    tokenText.className = 'token-hidden';
                    revealBtn.textContent = '👁 Reveal';
                    isRevealed = false;
                    if (hideTimeout) clearTimeout(hideTimeout);
                }} else {{
                    tokenText.textContent = actualToken;
                    tokenText.className = 'token-revealed';
                    revealBtn.textContent = '🙈 Hide';
                    isRevealed = true;
                    
                    // Auto-hide after 10 seconds
                    hideTimeout = setTimeout(() => {{
                        if (isRevealed) toggleReveal();
                    }}, 10000);
                }}
            }}
            
            function copyToken() {{
                navigator.clipboard.writeText(actualToken).then(() => {{
                    const toast = document.getElementById('toast');
                    toast.classList.add('show');
                    setTimeout(() => toast.classList.remove('show'), 2500);
                    
                    // Hide token after copying
                    if (isRevealed) {{
                        setTimeout(toggleReveal, 500);
                    }}
                }});
            }}
        </script>
    </body>
    </html>
    """


def error_page(message: str) -> str:
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Authentication Error</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .card {{
                background: white;
                border-radius: 16px;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
                padding: 40px;
                max-width: 450px;
                width: 100%;
                text-align: center;
            }}
            .icon {{
                width: 80px;
                height: 80px;
                background: linear-gradient(135deg, #fca5a5 0%, #f87171 100%);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 24px;
            }}
            .icon svg {{
                width: 40px;
                height: 40px;
                color: #dc2626;
            }}
            h1 {{
                color: #1f2937;
                font-size: 24px;
                font-weight: 700;
                margin-bottom: 16px;
            }}
            .message {{
                color: #6b7280;
                font-size: 14px;
                line-height: 1.6;
                margin-bottom: 24px;
            }}
            .retry-btn {{
                background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="icon">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                </svg>
            </div>
            <h1>Authentication Failed</h1>
            <p class="message">{message}</p>
            <a href="/auth/start" class="retry-btn">Try Again</a>
        </div>
    </body>
    </html>
    """


# ============================================================================
# MCP TOOLS
# ============================================================================

@mcp.tool()
async def get_my_courses(access_token: str) -> dict:
    """
    Get all courses you are enrolled in on Blackboard.
    
    Args:
        access_token: Your personal access token from authentication
    """
    result = await make_blackboard_request(access_token, "users/me/courses")
    
    if isinstance(result, dict) and result.get("error"):
        return result
    
    if isinstance(result, dict) and "results" in result:
        memberships = result["results"]
        courses = []
        for m in memberships:
            courses.append({
                "courseId": m.get("courseId"),
                "role": m.get("courseRoleId"),
                "availability": m.get("availability", {}).get("available"),
                "created": m.get("created")
            })
        return {"success": True, "courses": courses, "count": len(courses)}
    
    return result


@mcp.tool()
async def get_course_assignments(access_token: str, course_id: str) -> dict:
    """
    Get assignments/content for a specific course.
    
    Args:
        access_token: Your personal access token from authentication
        course_id: The course ID from get_my_courses (e.g., "_123_1")
    """
    return await make_blackboard_request(access_token, f"courses/{course_id}/contents")


@mcp.tool()
async def get_my_profile(access_token: str) -> dict:
    """
    Get your Blackboard user profile information.
    
    Args:
        access_token: Your personal access token from authentication
    """
    return await make_blackboard_request(access_token, "users/me")


@mcp.tool()
async def get_auth_link() -> dict:
    """
    Get the link to authenticate with Blackboard and receive your personal access token.
    """
    return {
        "message": "Visit this URL to authenticate with Blackboard and get your access token:",
        "auth_url": f"{SERVER_URL}/auth/start",
        "instructions": "After authenticating, you'll receive a token to use with other Blackboard tools."
    }


@mcp.tool()
async def check_token_status(access_token: str) -> dict:
    """
    Check if your access token is valid and see remaining time.
    
    Args:
        access_token: Your personal access token from authentication
    """
    user_info = get_user_info(access_token)
    
    if not user_info:
        return {
            "valid": False,
            "message": "Token not found or expired. Please re-authenticate.",
            "auth_url": f"{SERVER_URL}/auth/start"
        }
    
    return {
        "valid": True,
        "user_id": user_info["user_id"],
        "token_age": f"{user_info['token_age_seconds']} seconds",
        "expires_in": f"{user_info['expires_in_seconds']} seconds",
        "message": "Token is valid."
    }
