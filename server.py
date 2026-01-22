"""
Blackboard MCP Server - Entry Point
FastMCP Cloud runs this file. It imports and registers all tools from submodules.

With OAuthProxy, users authenticate automatically when they add this server
in Claude - no more copying/pasting tokens!
"""
from fastmcp import FastMCP
from auth import auth, SERVER_URL  # Import the OAuthProxy instance
from tools.common import register_common_tools
from tools.student import register_student_tools
from tools.instructor import register_instructor_tools

# ============================================================================
# MCP SERVER WITH OAUTH
# ============================================================================
# Pass the auth (OAuthProxy) to FastMCP - this enables automatic OAuth!
mcp = FastMCP(
    name="Blackboard",
    auth=auth,
    # Optional: These appear on the consent screen
    # description="Access your Blackboard courses, grades, and assignments",
)

# ============================================================================
# REGISTER ALL TOOLS
# ============================================================================
register_common_tools(mcp)
register_student_tools(mcp)
register_instructor_tools(mcp)


# ============================================================================
# NOTES ON THE CHANGE
# ============================================================================
# 
# What changed:
# 1. No more custom /auth/start and /auth/callback routes - OAuthProxy handles these
# 2. No more templates.py needed for success/error pages - OAuthProxy has its own
# 3. Tools no longer need access_token parameter - they call get_bb_token() from auth.py
#
# How it works now:
# 1. User adds this MCP server URL in Claude (Settings > Integrations)
# 2. Claude discovers OAuth endpoints via /.well-known/oauth-authorization-server
# 3. Claude initiates OAuth flow, user sees consent screen, authenticates with Blackboard
# 4. OAuthProxy stores the Blackboard token and issues a FastMCP JWT to Claude
# 5. When tools run, get_bb_token() retrieves the stored Blackboard token
#
# The redirect URI registered in Blackboard should be:
#   {SERVER_URL}/auth/callback
#
# For production with multiple instances, set these env vars:
# - JWT_SIGNING_KEY: Any complex string for signing FastMCP JWTs
# - Optionally configure Redis storage in auth.py for distributed deployments
