"""
Blackboard MCP Server - Custom OAuth Provider
Handles Blackboard's non-standard token endpoint format
"""
import os
import base64
import secrets
import time
import httpx
from urllib.parse import urlencode
from fastmcp import FastMCP
from fastmcp.server.auth.auth import OAuthProvider
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

# ============================================================================
# CONFIGURATION
# ============================================================================
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL", "https://anthropic.bt-retool.shop")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY", "a743ef51-d7bc-4a7e-97e6-bae6f086a0d4")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET", "2DXuZHi9QFZgKfIAkt8JJKhVWDBRdT0q")
BASE_URL = os.environ.get("BASE_URL", "https://blackboard-mcp.fastmcp.app")

# ============================================================================
# CUSTOM BLACKBOARD OAUTH PROVIDER
# ============================================================================
class BlackboardOAuthProvider(OAuthProvider):
    """Custom OAuth provider for Blackboard's non-standard OAuth implementation"""
    
    def __init__(
        self,
        blackboard_url: str,
        client_id: str,
        client_secret: str,
        base_url: str,
        redirect_path: str = "/auth/callback",
    ):
        self.blackboard_url = blackboard_url.rstrip('/')
        self.upstream_client_id = client_id
        self.upstream_client_secret = client_secret
        self.base_url = base_url.rstrip('/')
        self.redirect_path = redirect_path
        
        # Storage for auth codes and tokens
        self._pending_auth: dict[str, dict] = {}
        self._auth_codes: dict[str, dict] = {}
        self._clients: dict[str, OAuthClientInformationFull] = {}
        
        super().__init__(
            base_url=base_url,
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=["read", "write", "offline"],
                default_scopes=["read", "write"],
            ),
            required_scopes=["read"],
        )
    
    @property
    def authorization_endpoint(self) -> str:
        return f"{self.blackboard_url}/learn/api/public/v1/oauth2/authorizationcode"
    
    @property
    def token_endpoint(self) -> str:
        return f"{self.blackboard_url}/learn/api/public/v1/oauth2/token"
    
    @property
    def callback_url(self) -> str:
        return f"{self.base_url}{self.redirect_path}"
    
    async def register_client(self, client_info: OAuthClientInformationFull) -> OAuthClientInformationFull:
        """Register a new OAuth client (DCR)"""
        self._clients[client_info.client_id] = client_info
        return client_info
    
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get registered client info"""
        return self._clients.get(client_id)
    
    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        """Generate authorization URL for Blackboard"""
        # Generate our own state to track this auth flow
        our_state = secrets.token_urlsafe(32)
        
        # Store the original params for later
        self._pending_auth[our_state] = {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "code_challenge_method": params.code_challenge_method,
            "scope": params.scope,
            "original_state": params.state,
        }
        
        # Build Blackboard authorization URL
        bb_params = {
            "response_type": "code",
            "client_id": self.upstream_client_id,
            "redirect_uri": self.callback_url,
            "scope": params.scope or "read write",
            "state": our_state,
        }
        
        return f"{self.authorization_endpoint}?{urlencode(bb_params)}"
    
    async def handle_blackboard_callback(self, code: str, state: str) -> tuple[str, str, str]:
        """
        Handle the OAuth callback from Blackboard.
        Exchange the code for tokens using Blackboard's specific format.
        Returns (new_code, client_redirect_uri, original_state)
        """
        stored = self._pending_auth.get(state)
        if not stored:
            raise ValueError(f"Invalid state: {state}")
        
        # Remove from pending
        del self._pending_auth[state]
        
        # Exchange code with Blackboard using their specific format
        # Blackboard wants: POST /token?code=XXX&redirect_uri=YYY
        # with body: grant_type=authorization_code
        # and Basic auth header
        
        token_url = f"{self.token_endpoint}?code={code}&redirect_uri={self.callback_url}"
        
        # Create Basic auth header
        credentials = f"{self.upstream_client_id}:{self.upstream_client_secret}"
        auth_header = base64.b64encode(credentials.encode()).decode()
        
        async with httpx.AsyncClient() as http_client:
            response = await http_client.post(
                token_url,
                data="grant_type=authorization_code",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": f"Basic {auth_header}",
                },
            )
            
            if response.status_code != 200:
                raise ValueError(f"Token exchange failed: {response.status_code} - {response.text}")
            
            token_data = response.json()
        
        # Generate a new internal code for the MCP client
        new_code = secrets.token_urlsafe(32)
        
        # Store the tokens mapped to our internal code
        self._auth_codes[new_code] = {
            "access_token": token_data.get("access_token"),
            "token_type": token_data.get("token_type", "bearer"),
            "expires_in": token_data.get("expires_in", 3600),
            "refresh_token": token_data.get("refresh_token"),
            "scope": token_data.get("scope", "read write"),
            "client_id": stored["client_id"],
            "created_at": time.time(),
        }
        
        return new_code, stored["redirect_uri"], stored.get("original_state", "")
    
    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        """Exchange our internal auth code for tokens"""
        code = authorization_code.code
        token_data = self._auth_codes.get(code)
        
        if not token_data:
            raise ValueError(f"Invalid authorization code: {code}")
        
        # Remove the code (one-time use)
        del self._auth_codes[code]
        
        return OAuthToken(
            access_token=token_data["access_token"],
            token_type=token_data["token_type"],
            expires_in=token_data["expires_in"],
            refresh_token=token_data.get("refresh_token"),
            scope=token_data["scope"],
        )
    
    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
    ) -> OAuthToken:
        """Exchange refresh token for new access token"""
        token_url = f"{self.token_endpoint}?refresh_token={refresh_token.token}&redirect_uri={self.callback_url}"
        
        credentials = f"{self.upstream_client_id}:{self.upstream_client_secret}"
        auth_header = base64.b64encode(credentials.encode()).decode()
        
        async with httpx.AsyncClient() as http_client:
            response = await http_client.post(
                token_url,
                data="grant_type=refresh_token",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": f"Basic {auth_header}",
                },
            )
            
            if response.status_code != 200:
                raise ValueError(f"Refresh failed: {response.status_code}")
            
            token_data = response.json()
        
        return OAuthToken(
            access_token=token_data.get("access_token"),
            token_type=token_data.get("token_type", "bearer"),
            expires_in=token_data.get("expires_in", 3600),
            refresh_token=token_data.get("refresh_token"),
            scope=token_data.get("scope", "read write"),
        )
    
    async def verify_access_token(self, token: str) -> dict | None:
        """Verify an access token - Blackboard uses opaque tokens"""
        return {
            "active": True,
            "scope": "read write",
            "token": token,
        }


# ============================================================================
# MCP SERVER
# ============================================================================
auth_provider = BlackboardOAuthProvider(
    blackboard_url=BLACKBOARD_URL,
    client_id=BLACKBOARD_APP_KEY,
    client_secret=BLACKBOARD_APP_SECRET,
    base_url=BASE_URL,
    redirect_path="/auth/callback",
)

mcp = FastMCP(
    name="Blackboard",
    auth=auth_provider,
)


# Custom callback route to handle Blackboard's OAuth callback
@mcp.custom_route("/auth/callback", methods=["GET"])
async def oauth_callback(request):
    """Handle OAuth callback from Blackboard"""
    from starlette.responses import RedirectResponse, JSONResponse
    
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    if error:
        return JSONResponse({"error": error, "description": request.query_params.get("error_description")})
    
    if not code or not state:
        return JSONResponse({"error": "Missing code or state"})
    
    try:
        new_code, redirect_uri, original_state = await auth_provider.handle_blackboard_callback(code, state)
        
        # Build redirect URL back to the MCP client
        redirect_params = {"code": new_code}
        if original_state:
            redirect_params["state"] = original_state
        
        final_url = f"{redirect_uri}?{urlencode(redirect_params)}"
        return RedirectResponse(final_url)
    except Exception as e:
        return JSONResponse({"error": "callback_failed", "description": str(e)})


@mcp.tool()
def hello(name: str = "World") -> str:
    """Simple test tool"""
    return f"Hello, {name}! OAuth is configured."


@mcp.tool()
def check_config() -> str:
    """Check that environment variables are loaded"""
    return (
        f"BLACKBOARD_URL: {BLACKBOARD_URL[:30]}...\n"
        f"APP_KEY: {BLACKBOARD_APP_KEY[:8]}...\n"
        f"BASE_URL: {BASE_URL}\n"
    )
