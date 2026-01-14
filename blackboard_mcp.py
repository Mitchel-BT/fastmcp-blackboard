"""
Blackboard MCP Server - Step 1: Test OAuth Setup
"""

import os
from fastmcp import FastMCP
from fastmcp.server.auth import OAuthProxy

# ============================================================================
# CONFIGURATION
# ============================================================================

BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL", "").rstrip('/')
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY", "")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET", "")
BASE_URL = os.environ.get("BASE_URL", "https://blackboard-mcp.fastmcp.app")

# ============================================================================
# OAUTH PROXY
# ============================================================================

auth = OAuthProxy(
    client_id=BLACKBOARD_APP_KEY,
    client_secret=BLACKBOARD_APP_SECRET,
    base_url=BASE_URL,
    authorize_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode",
    token_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/token",
    redirect_path="/oauth/callback",
    required_scopes=["read", "write"],
    token_endpoint_auth_method="client_secret_basic",
    forward_pkce=False,
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
