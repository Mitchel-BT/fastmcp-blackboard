"""
Common MCP tools for Blackboard - used by both students and instructors.

Auth strategy:
- Local mode: use stored token via get_bb_token(None)
- Cloud mode: await fastmcp get_access_token(), then pass to get_bb_token(...)
"""
import blackboard_client as bb
from blackboard_client import BlackboardAPIError

from fastmcp.server.dependencies import get_access_token
from auth import IS_LOCAL_MODE, get_bb_token


async def _resolve_bb_token() -> str:
    if IS_LOCAL_MODE:
        return get_bb_token(None)
    mcp_access_token = await get_access_token()
    return get_bb_token(mcp_access_token)


def register_common_tools(mcp):
    """Register common tools with the MCP server"""

    @mcp.tool()
    async def check_token_status() -> dict:
        """
        Check if you're connected and the token works by calling /users/me.
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
            return {"valid": False, "message": f"API error: {e.message}", "status_code": e.status_code}

    @mcp.tool()
    async def get_my_profile() -> dict:
        """Get your Blackboard user profile information."""
        try:
            bb_token = await _resolve_bb_token()
            user = await bb.get_current_user(access_token=bb_token)
            return {"success": True, "user": user}
        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e)}
