"""
Common MCP tools for Blackboard - used by both students and instructors.
With OAuthProxy, authentication is automatic - no more token parameters!
"""
import blackboard_client as bb
from blackboard_client import BlackboardAPIError


def register_common_tools(mcp):
    """Register common tools with the MCP server"""

    @mcp.tool()
    async def check_token_status() -> dict:
        """
        Check if your access token is valid and see how much time is remaining.
        """
        try:
            # Verify by making a simple API call
            user = await bb.get_current_user()
            return {
                "valid": True,
                "user_id": user.get("id"),
                "username": user.get("userName"),
                "message": "✅ Connected to Blackboard successfully."
            }
        except ValueError as e:
            return {
                "valid": False,
                "message": str(e)
            }
        except BlackboardAPIError as e:
            return {
                "valid": False,
                "message": f"Token may be expired: {e.message}"
            }

    @mcp.tool()
    async def get_my_profile(access_token: str = Depends(get_access_token)) -> dict:
        """Get your Blackboard user profile information."""
        try:
            user = await bb.get_current_user(access_token)  # Pass access_token
            return {"success": True, "user": user}
        except Exception as e:
            return {"error": str(e)}
