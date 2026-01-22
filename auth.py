"""
Authentication for Blackboard MCP Server.
Works in both local (stdio) and cloud (HTTP) modes:

- Local: Automatically opens browser for OAuth, runs local callback server
- Cloud: Uses OAuthProxy for automatic authentication via Claude
"""
import os
import sys

import asyncio
import base64
import webbrowser
import httpx
from typing import Optional
from urllib.parse import quote
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET")
SERVER_URL = os.environ.get("SERVER_URL")
print(f"DEBUG: BLACKBOARD_URL = {os.environ.get('BLACKBOARD_URL', 'NOT SET')}", file=sys.stderr)
print(f"DEBUG: BLACKBOARD_APP_KEY = {os.environ.get('BLACKBOARD_APP_KEY', 'NOT SET')}", file=sys.stderr)
# Optional: Pre-set token skips OAuth entirely (useful for CI/testing)
BLACKBOARD_TOKEN = os.environ.get("BLACKBOARD_TOKEN")

# Optional: For production deployments with multiple instances
JWT_SIGNING_KEY = os.environ.get("JWT_SIGNING_KEY")

# Determine mode based on SERVER_URL
# - If SERVER_URL is set and not localhost → Cloud mode (use OAuthProxy)
# - Otherwise → Local mode (use browser OAuth)
IS_LOCAL_MODE = not SERVER_URL or SERVER_URL.startswith("http://localhost")

if not BLACKBOARD_URL:
    raise EnvironmentError("Missing BLACKBOARD_URL environment variable")

if not BLACKBOARD_APP_KEY or not BLACKBOARD_APP_SECRET:
    raise EnvironmentError("Missing BLACKBOARD_APP_KEY or BLACKBOARD_APP_SECRET")


# ============================================================================
# LOCAL MODE: Token storage and browser-based OAuth
# ============================================================================

_local_token: str | None = BLACKBOARD_TOKEN  # May be pre-set or obtained via OAuth


def set_local_token(token: str):
    """Set the local token (called after OAuth completes)"""
    global _local_token
    _local_token = token


def get_local_token() -> str | None:
    """Get the current local token"""
    return _local_token


async def _do_local_oauth():
    """
    Perform OAuth flow locally:
    1. Start a local callback server
    2. Open browser to Blackboard auth
    3. Receive callback with code
    4. Exchange code for token
    """
    from aiohttp import web
    
    callback_code = None
    callback_received = asyncio.Event()
    
    async def callback_handler(request):
        nonlocal callback_code
        code = request.query.get('code')
        error = request.query.get('error')
        
        if error:
            return web.Response(
                text=f"""
                <html>
                <body style="font-family: Arial; text-align: center; margin-top: 100px;">
                    <h1 style="color: #dc3545;">✗ Authentication Failed</h1>
                    <p>Error: {error}</p>
                </body>
                </html>
                """,
                content_type='text/html'
            )
        
        if code:
            callback_code = code
            callback_received.set()
            return web.Response(
                text="""
                <html>
                <body style="font-family: Arial; text-align: center; margin-top: 100px;">
                    <h1 style="color: #28a745;">✓ Authentication Successful!</h1>
                    <p>You can close this window and return to Claude.</p>
                    <script>setTimeout(() => window.close(), 2000);</script>
                </body>
                </html>
                """,
                content_type='text/html'
            )
        
        return web.Response(text="No code received", status=400)
    
    # Start callback server
    app = web.Application()
    app.router.add_get('/callback', callback_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    
    # Try different ports
    port = 8080
    site = None
    for try_port in [8080, 8081, 8082, 3000, 5000]:
        try:
            site = web.TCPSite(runner, 'localhost', try_port)
            await site.start()
            port = try_port
            break
        except OSError:
            continue
    
    if not site:
        await runner.cleanup()
        raise RuntimeError("Could not start local callback server - all ports in use")
    
    redirect_uri = f"http://localhost:{port}/callback"
    
    print(f"\n{'='*60}", file=sys.stderr)
    print("BLACKBOARD AUTHENTICATION", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)
    print(f"\n1. Starting local callback server on {redirect_uri}", file=sys.stderr)
    print("2. Opening browser for authentication...", file=sys.stderr)
    print("   Please log in and authorize the application", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)
    
    # Build authorization URL
    auth_url = (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?redirect_uri={quote(redirect_uri, safe='')}"
        f"&response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&scope=read%20write%20offline"
    )
    
    # Open browser
    webbrowser.open(auth_url)
    
    # Wait for callback (with timeout)
    try:
        await asyncio.wait_for(callback_received.wait(), timeout=120)
    except asyncio.TimeoutError:
        await runner.cleanup()
        raise TimeoutError(
            "Authentication timeout (120s). Make sure to complete login in the browser. "
            f"Also verify {redirect_uri} is registered as a redirect URI in your Blackboard app."
        )
    
    # Cleanup server
    await runner.cleanup()
    
    if not callback_code:
        raise RuntimeError("No authorization code received")
    
    print("✓ Authorization code received", file=sys.stderr)
    
    # Exchange code for token
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
                "code": callback_code,
                "redirect_uri": redirect_uri
            }
        )
        
        if response.status_code != 200:
            raise RuntimeError(f"Token exchange failed: {response.text}")
        
        token_data = response.json()
        set_local_token(token_data["access_token"])
        
        print(f"\n{'='*60}", file=sys.stderr)
        print("✓ AUTHENTICATION COMPLETE!", file=sys.stderr)
        print(f"  Token: {token_data['access_token'][:8]}...{token_data['access_token'][-4:]}", file=sys.stderr)
        print(f"  Expires in: {token_data.get('expires_in', 'unknown')} seconds", file=sys.stderr)
        print(f"{'='*60}\n", file=sys.stderr)


async def ensure_local_auth():
    """Ensure we have a valid token in local mode"""
    if get_local_token():
        return  # Already have a token
    
    await _do_local_oauth()


# ============================================================================
# CLOUD MODE: OAuthProxy setup
# ============================================================================

auth = None  # Will be None in local mode, OAuthProxy in cloud mode

if not IS_LOCAL_MODE:
    from fastmcp.server.auth import OAuthProxy
    from fastmcp.server.auth.verifiers import TokenVerifier

    class BlackboardTokenVerifier(TokenVerifier):
        """Custom token verifier for Blackboard's opaque tokens."""
        
        def __init__(self, blackboard_url: str, required_scopes: list[str] = None):
            self.blackboard_url = blackboard_url.rstrip("/")
            self._required_scopes = required_scopes or ["read", "write", "offline"]
        
        @property
        def issuer(self) -> str:
            return self.blackboard_url
        
        @property
        def required_scopes(self) -> list[str]:
            return self._required_scopes
        
        async def verify_token(self, token: str) -> Optional[dict]:
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        f"{self.blackboard_url}/learn/api/public/v1/users/me",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=10.0
                    )
                    
                    if response.status_code == 200:
                        user_data = response.json()
                        name_parts = user_data.get("name", {})
                        full_name = f"{name_parts.get('given', '')} {name_parts.get('family', '')}".strip()
                        
                        return {
                            "sub": user_data.get("id"),
                            "name": full_name or user_data.get("userName"),
                            "email": user_data.get("contact", {}).get("email"),
                            "userName": user_data.get("userName"),
                            "scopes": self._required_scopes,
                        }
                    return None
            except Exception as e:
                logger.error(f"Token verification error: {e}")
                return None

    token_verifier = BlackboardTokenVerifier(
        blackboard_url=BLACKBOARD_URL,
        required_scopes=["read", "write", "offline"]
    )

    auth = OAuthProxy(
        upstream_authorization_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode",
        upstream_token_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/token",
        upstream_client_id=BLACKBOARD_APP_KEY,
        upstream_client_secret=BLACKBOARD_APP_SECRET,
        token_verifier=token_verifier,
        base_url=SERVER_URL,
        jwt_signing_key=JWT_SIGNING_KEY,
        token_endpoint_auth_method="client_secret_basic",
        forward_pkce=True,
        require_authorization_consent=True,
    )
    
    logger.info("Running in CLOUD mode with OAuthProxy")
else:
    logger.info("Running in LOCAL mode with browser OAuth")


# ============================================================================
# UNIFIED TOKEN GETTER
# ============================================================================

def get_bb_token() -> str:
    """
    Get the Blackboard access token for the current user.
    
    - Local mode: Returns token from browser OAuth flow
    - Cloud mode: Returns token from OAuthProxy
    """
    if IS_LOCAL_MODE:
        token = get_local_token()
        if not token:
            raise ValueError(
                "Not authenticated yet. Authentication should happen automatically on startup."
            )
        return token
    
    # Cloud mode
    from fastmcp.server.dependencies import get_access_token
    
    token = get_access_token()
    if not token:
        raise ValueError(
            "Not authenticated. Please connect this server through Claude's "
            "integrations/connectors to authenticate with Blackboard."
        )
    return token
