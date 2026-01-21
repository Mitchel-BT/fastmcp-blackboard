"""
Blackboard MCP Server - Using FastMCP's OAuth Proxy for proper multi-user support
This allows Claude to properly authenticate users via Blackboard OAuth
"""
import os
import logging
import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import OAuthProxy
from fastmcp.server.auth.token_verification import TokenVerifier, TokenVerificationResult
from fastmcp.server.dependencies import get_access_token

# For Redis storage
from key_value.aio.stores.redis import RedisStore

# ============================================================================
# LOGGING SETUP
# ============================================================================
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("blackboard-mcp")

# ============================================================================
# CONFIGURATION
# ============================================================================
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET")
SERVER_URL = os.environ.get("SERVER_URL")

# Upstash Redis for token storage
UPSTASH_REDIS_REST_URL = os.environ.get("UPSTASH_REDIS_REST_URL")
UPSTASH_REDIS_REST_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN")

# JWT signing key for production (generate a random string)
JWT_SIGNING_KEY = os.environ.get("JWT_SIGNING_KEY", BLACKBOARD_APP_SECRET)


# ============================================================================
# CUSTOM TOKEN VERIFIER FOR BLACKBOARD
# ============================================================================

class BlackboardTokenVerifier(TokenVerifier):
    """
    Custom token verifier for Blackboard OAuth tokens.
    Blackboard returns opaque tokens, so we verify by calling Blackboard's API.
    """
    
    def __init__(self, blackboard_url: str, required_scopes: list[str] | None = None):
        self.blackboard_url = blackboard_url
        self._required_scopes = required_scopes or ["read", "write"]
    
    @property
    def required_scopes(self) -> list[str]:
        return self._required_scopes
    
    async def verify_token(self, token: str) -> TokenVerificationResult:
        """Verify Blackboard token by calling the users/me endpoint"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.blackboard_url}/learn/api/public/v1/users/me",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    user_data = response.json()
                    user_id = user_data.get("id", "unknown")
                    username = user_data.get("userName", "unknown")
                    
                    logger.info(f"Token verified for user: {username} ({user_id})")
                    
                    return TokenVerificationResult(
                        valid=True,
                        client_id=user_id,
                        scopes=self._required_scopes,
                        claims={
                            "sub": user_id,
                            "username": username,
                            "user_data": user_data
                        }
                    )
                else:
                    logger.warning(f"Token verification failed: {response.status_code}")
                    return TokenVerificationResult(valid=False)
                    
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return TokenVerificationResult(valid=False)


# ============================================================================
# SETUP OAUTH PROXY
# ============================================================================

# Create token verifier
token_verifier = BlackboardTokenVerifier(
    blackboard_url=BLACKBOARD_URL,
    required_scopes=["read", "write"]
)

# Create Redis storage for OAuth client data
# Note: Using standard redis URL format for key_value store
redis_store = None
if UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN:
    # Parse Upstash REST URL to get host
    # Upstash REST URL is like https://xxx.upstash.io
    # We need to construct a redis:// URL for the key_value store
    import re
    match = re.search(r'https://([^/]+)', UPSTASH_REDIS_REST_URL)
    if match:
        redis_host = match.group(1)
        # For Upstash, use their Redis URL format
        logger.info(f"Using Redis storage at {redis_host}")

# Create the OAuth proxy for Blackboard
auth = OAuthProxy(
    # Blackboard OAuth endpoints
    upstream_authorization_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode",
    upstream_token_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/token",
    
    # Your Blackboard app credentials
    upstream_client_id=BLACKBOARD_APP_KEY,
    upstream_client_secret=BLACKBOARD_APP_SECRET,
    
    # Token verification
    token_verifier=token_verifier,
    
    # Your server's public URL
    base_url=SERVER_URL,
    
    # JWT signing key for production
    jwt_signing_key=JWT_SIGNING_KEY,
    
    # Token endpoint auth method (Blackboard uses basic auth)
    token_endpoint_auth_method="client_secret_basic",
)

# ============================================================================
# MCP SERVER
# ============================================================================

mcp = FastMCP(name="Blackboard", auth=auth)


# ============================================================================
# HELPER TO GET CURRENT USER
# ============================================================================

async def get_current_user_token() -> str | None:
    """Get the access token for the current authenticated user"""
    try:
        token = get_access_token()
        if token:
            logger.debug(f"Got access token: {token[:20]}...")
            return token
    except Exception as e:
        logger.error(f"Error getting access token: {e}")
    return None


# ============================================================================
# MCP TOOLS
# ============================================================================

@mcp.tool()
async def get_my_courses() -> str:
    """Get all courses you have access to in Blackboard."""
    token = await get_current_user_token()
    if not token:
        return "❌ Not authenticated. Please connect to this server through Claude's OAuth flow."
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses?limit=100",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            if resp.status_code == 401:
                return "⚠️ Session expired. Please reconnect."
            
            if resp.status_code != 200:
                return f"Error: {resp.status_code} - {resp.text}"
            
            courses = resp.json().get("results", [])
            if not courses:
                return "No courses found."
            
            result = f"📚 Found {len(courses)} courses:\n\n"
            for c in courses:
                result += f"• **{c.get('name', 'Unnamed')}** (ID: `{c.get('id')}`)\n"
            return result
            
    except Exception as e:
        logger.exception(f"Error in get_my_courses: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_course_assignments(course_id: str) -> str:
    """Get assignments for a specific course."""
    token = await get_current_user_token()
    if not token:
        return "❌ Not authenticated. Please connect through Claude's OAuth flow."
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/courses/{course_id}/gradebook/columns",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            if resp.status_code == 401:
                return "⚠️ Session expired. Please reconnect."
            
            if resp.status_code != 200:
                return f"Error: {resp.status_code} - {resp.text}"
            
            columns = resp.json().get("results", [])
            assignments = [c for c in columns if c.get("grading", {}).get("due")]
            
            if not assignments:
                return f"No assignments with due dates in course `{course_id}`"
            
            result = f"📝 Found {len(assignments)} assignments:\n\n"
            for a in assignments:
                result += f"• **{a.get('name')}** ({a.get('score', {}).get('possible', '?')} pts) - Due: {a.get('grading', {}).get('due')}\n"
            return result
            
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def get_current_user() -> str:
    """Get current authenticated Blackboard user info."""
    token = await get_current_user_token()
    if not token:
        return "❌ Not authenticated. Please connect through Claude's OAuth flow."
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            
            if resp.status_code == 401:
                return "⚠️ Session expired. Please reconnect."
            
            if resp.status_code != 200:
                return f"Error: {resp.status_code} - {resp.text}"
            
            user = resp.json()
            name = user.get('name', {})
            
            result = "👤 **Current User**\n\n"
            result += f"• **User ID:** `{user.get('id')}`\n"
            result += f"• **Username:** `{user.get('userName')}`\n"
            if name.get('given') or name.get('family'):
                result += f"• **Name:** {name.get('given', '')} {name.get('family', '')}\n"
            if user.get('contact', {}).get('email'):
                result += f"• **Email:** {user['contact']['email']}\n"
            return result
            
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def check_auth_status() -> str:
    """Check authentication status."""
    token = await get_current_user_token()
    
    if not token:
        return (
            "🔒 **Not Authenticated**\n\n"
            "To use Blackboard tools, you need to connect this server through Claude's OAuth flow.\n\n"
            "Go to **Settings > Integrations** and reconnect the Blackboard connector."
        )
    
    # Verify the token is still valid
    result = await token_verifier.verify_token(token)
    
    if result.valid:
        username = result.claims.get("username", "unknown")
        user_id = result.claims.get("sub", "unknown")
        return (
            f"✅ **Authenticated**\n\n"
            f"• **Username:** `{username}`\n"
            f"• **User ID:** `{user_id}`"
        )
    else:
        return "⚠️ **Token Invalid**\n\nPlease reconnect through Claude's OAuth flow."


@mcp.tool()
async def check_config() -> str:
    """Check server configuration."""
    return (
        f"⚙️ **Configuration**\n\n"
        f"• **Blackboard:** `{BLACKBOARD_URL}`\n"
        f"• **App Key:** `{BLACKBOARD_APP_KEY[:8] if BLACKBOARD_APP_KEY else 'NOT SET'}...`\n"
        f"• **Server URL:** `{SERVER_URL}`\n"
        f"• **Auth:** OAuth Proxy (DCR-compliant)\n"
    )
