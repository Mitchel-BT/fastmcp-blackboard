"""
Authentication for Blackboard MCP Server using FastMCP's OAuthProxy.
Users authenticate once when connecting through Claude - no token copy/paste needed.
"""
import os
import httpx
from fastmcp.server.auth import OAuthProxy
from fastmcp.server.auth.verifiers import TokenVerifier
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET")
SERVER_URL = os.environ.get("SERVER_URL")

# Optional: For production deployments with multiple instances
JWT_SIGNING_KEY = os.environ.get("JWT_SIGNING_KEY")  # Any complex string

_required_vars = ["BLACKBOARD_URL", "BLACKBOARD_APP_KEY", "BLACKBOARD_APP_SECRET", "SERVER_URL"]
_missing = [var for var in _required_vars if not os.environ.get(var)]
if _missing:
    raise EnvironmentError(f"Missing required environment variables: {', '.join(_missing)}")


# ============================================================================
# CUSTOM TOKEN VERIFIER FOR BLACKBOARD
# ============================================================================
# Blackboard uses opaque tokens (not JWTs), so we need a custom verifier
# that validates tokens by calling Blackboard's API

class BlackboardTokenVerifier(TokenVerifier):
    """
    Custom token verifier for Blackboard's opaque tokens.
    Validates tokens by calling Blackboard's /users/me endpoint.
    """
    
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
        """
        Verify the Blackboard token by calling the API.
        Returns claims dict if valid, None if invalid.
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.blackboard_url}/learn/api/public/v1/users/me",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    user_data = response.json()
                    logger.info(f"Token verified for user: {user_data.get('userName', 'unknown')}")
                    
                    # Build name from parts
                    name_parts = user_data.get("name", {})
                    full_name = f"{name_parts.get('given', '')} {name_parts.get('family', '')}".strip()
                    
                    return {
                        "sub": user_data.get("id"),
                        "name": full_name or user_data.get("userName"),
                        "email": user_data.get("contact", {}).get("email"),
                        "userName": user_data.get("userName"),
                        "scopes": self._required_scopes,
                    }
                else:
                    logger.warning(f"Token verification failed: {response.status_code}")
                    return None
                    
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return None


# ============================================================================
# CREATE THE OAUTH PROXY
# ============================================================================

# Create the token verifier
token_verifier = BlackboardTokenVerifier(
    blackboard_url=BLACKBOARD_URL,
    required_scopes=["read", "write", "offline"]
)

# Create the OAuth Proxy - this is what gets passed to FastMCP
auth = OAuthProxy(
    # Blackboard OAuth endpoints
    upstream_authorization_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode",
    upstream_token_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/token",
    
    # Your Blackboard app credentials
    upstream_client_id=BLACKBOARD_APP_KEY,
    upstream_client_secret=BLACKBOARD_APP_SECRET,
    
    # Token verification
    token_verifier=token_verifier,
    
    # Your server's public URL (this is where OAuth callbacks go)
    base_url=SERVER_URL,
    
    # JWT signing key for FastMCP tokens
    # If not set, derives from upstream_client_secret
    jwt_signing_key=JWT_SIGNING_KEY,
    
    # Blackboard uses basic auth for token endpoint
    token_endpoint_auth_method="client_secret_basic",
    
    # Enable PKCE forwarding for security
    forward_pkce=True,
    
    # Show consent screen to prevent confused deputy attacks
    require_authorization_consent=True,
)


# ============================================================================
# HELPER FUNCTION FOR TOOLS
# ============================================================================

def get_bb_token() -> str:
    """
    Get the Blackboard access token for the current authenticated user.
    
    This replaces the old pattern where tools received access_token as a parameter.
    The OAuthProxy automatically provides the upstream (Blackboard) token.
    
    Raises ValueError if not authenticated.
    """
    from fastmcp.server.dependencies import get_access_token
    
    token = get_access_token()
    if not token:
        raise ValueError(
            "Not authenticated. Please connect this server through Claude's "
            "integrations/connectors to authenticate with Blackboard."
        )
    return token
