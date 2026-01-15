"""
Blackboard MCP Server - Cloud Version
Fixed OAuth parameter names
"""

import os
from fastmcp import FastMCP
from fastmcp.server.auth import OAuthProxy
from fastmcp.server.auth.providers.jwt import JWTVerifier

# ============================================================================
# CONFIGURATION
# ============================================================================

BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL", "").rstrip('/')
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY", "")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET", "")
BASE_URL = os.environ.get("BASE_URL", "https://blackboard-mcp.fastmcp.app")

# ============================================================================
# TOKEN VERIFIER
# Blackboard uses opaque tokens, so we'll create a simple pass-through verifier
# ============================================================================

class BlackboardTokenVerifier:
    """Simple token verifier for Blackboard opaque tokens"""
    
    required_scopes = ["read", "write"]
    
    async def verify(self, token: str) -> dict:
        # Blackboard tokens are opaque - we trust them if received from OAuth flow
        # In production, you might want to call Blackboard's token info endpoint
        return {
            "active": True,
            "scope": "read write",
            "token": token
        }

# ============================================================================
# OAUTH PROXY - Using correct parameter names!
# ============================================================================

auth = OAuthProxy(
    # Upstream OAuth endpoints (Blackboard)
    upstream_authorization_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode",
    upstream_token_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/token",
    
    # Your registered app credentials
    upstream_client_id=BLACKBOARD_APP_KEY,
    upstream_client_secret=BLACKBOARD_APP_SECRET,
    
    # Token verifier
    token_verifier=BlackboardTokenVerifier(),
    
    # Your FastMCP server's public URL
    base_url=BASE_URL,
    
    # Callback path
    redirect_path="/auth/callback",
    
    # Try "none" or remove this line entirely
    token_endpoint_auth_method="none",
    
    # Blackboard supports PKCE with S256
    forward_pkce=True,
    enable_dcr=False,
)

# ============================================================================
# MCP SERVER
# ============================================================================

mcp = FastMCP(
    name="Blackboard",
    auth=auth,
)


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
