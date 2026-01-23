"""
Common MCP tools for Blackboard - used by both students and instructors.

This version avoids importing `Depends` (not exported by some fastmcp builds).
It resolves the Blackboard token in a way that works in both local and cloud modes.
"""

import blackboard_client as bb
from blackboard_client import BlackboardAPIError
from fastmcp.server.dependencies import get_access_token

from auth import IS_LOCAL_MODE, get_bb_token


async def _resolve_bb_token() -> str:
    """
    Resolve the Blackboard token in both modes:
    - Local mode: token is stored by browser OAuth and returned by get_bb_token(None)
    - Cloud mode: token comes from FastMCP via get_access_token(), then passed into get_bb_token(token)
    """
    if IS_LOCAL_MODE:
        return get_bb_token(None)  # local mode uses stored token :contentReference[oaicite:1]{index=1}

    mcp_access_token = await get_access_token()
    return get_bb_token(mcp_access_token)  # cloud mode returns injected token :contentReference[oaicite:2]{index=2}


def register_common_tools(mcp):
    """Register common tools with the MCP server."""

    @mcp.tool()
    async def check_token_status() -> dict:
        """
        Check if auth is working by calling /users/me.
        """
        try:
            bb_token = await _resolve_bb_token()
            user = await bb.get_current_user(access_token=bb_token)

            return {
                "valid": True,
                "user_id": user.get("id"),
                "username": user.get("userName"),
                "message": "✅ Connected to Blackboard successfully.",
            }

        except ValueError as e:
            return {"valid": False, "message": str(e)}
        except BlackboardAPIError as e:
            return {
                "valid": False,
                "message": f"Token may be expired or invalid: {getattr(e, 'message', str(e))}",
                "status_code": getattr(e, "status_code", None),
                "details": getattr(e, "details", None),
            }
        except Exception as e:
            return {"valid": False, "message": str(e), "exception_type": type(e).__name__}

    @mcp.tool()
    async def get_my_profile() -> dict:
        """Get your Blackboard user profile information."""
        try:
            bb_token = await _resolve_bb_token()
            user = await bb.get_current_user(access_token=bb_token)
            return {"success": True, "user": user}
        except Exception as e:
            return {"error": str(e), "exception_type": type(e).__name__}
