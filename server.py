"""
Blackboard MCP Server - Works in both local and cloud modes!

Local mode (Claude Desktop via stdio):
  - Automatically opens browser for Blackboard authentication on startup
  - Set: BLACKBOARD_URL, BLACKBOARD_APP_KEY, BLACKBOARD_APP_SECRET
  - Run with: uvx --from git+https://github.com/Mitchel-BT/fastmcp-blackboard blackboard-mcp

Cloud mode (FastMCP Cloud via HTTP):
  - Uses OAuthProxy for automatic authentication via Claude
  - Set: BLACKBOARD_URL, BLACKBOARD_APP_KEY, BLACKBOARD_APP_SECRET, SERVER_URL
"""
import sys
import asyncio
from fastmcp import FastMCP
from auth import auth, IS_LOCAL_MODE, BLACKBOARD_URL, ensure_local_auth
from tools.common import register_common_tools
from tools.student import register_student_tools
from tools.instructor import register_instructor_tools
from tools.testing import register_testing_tools

# ============================================================================
# MCP SERVER
# ============================================================================

mcp = FastMCP(
    name="Blackboard" + (" (Local)" if IS_LOCAL_MODE else ""),
    auth=auth,  # None in local mode, OAuthProxy in cloud mode
)

# ============================================================================
# REGISTER ALL TOOLS
# ============================================================================
register_common_tools(mcp)
register_student_tools(mcp)
register_instructor_tools(mcp)
register_testing_tools(mcp)


# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    """Entry point for running the server"""
    
    if IS_LOCAL_MODE:
        print(f"🖥️  Blackboard MCP Server (Local Mode)", file=sys.stderr)
        print(f"   Blackboard: {BLACKBOARD_URL}", file=sys.stderr)
        
        # Run OAuth flow before starting the MCP server
        # This opens the browser and gets the token
        try:
            asyncio.run(ensure_local_auth())
        except Exception as e:
            print(f"\n❌ Authentication failed: {e}", file=sys.stderr)
            sys.exit(1)
        
        print("🚀 Starting MCP server...\n", file=sys.stderr)
    else:
        print(f"☁️  Blackboard MCP Server (Cloud Mode)", file=sys.stderr)
        print(f"   Blackboard: {BLACKBOARD_URL}", file=sys.stderr)
    
    mcp.run()


if __name__ == "__main__":
    main()
