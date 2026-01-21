"""
Common MCP tools for Blackboard - used by both students and instructors.
"""
from auth import SERVER_URL, get_user_info
import blackboard_client as bb
from blackboard_client import AuthenticationRequired, BlackboardAPIError


def _auth_error_response():
    return {
        "error": "authentication_required",
        "message": "Please authenticate with Blackboard first.",
        "auth_url": f"{SERVER_URL}/auth/start"
    }


def register_common_tools(mcp):
    """Register common tools with the MCP server"""

    @mcp.tool()
    async def get_auth_link() -> dict:
        """
        Get the link to authenticate with Blackboard.
        Use this first if you haven't connected your Blackboard account yet.
        """
        return {
            "message": "Visit this URL to connect your Blackboard account:",
            "auth_url": f"{SERVER_URL}/auth/start",
            "next_step": "After authenticating, copy the message shown and paste it here. I'll remember your token for this conversation."
        }

    @mcp.tool()
    async def check_token_status(access_token: str) -> dict:
        """
        Check if your access token is valid and see how much time is remaining.
        
        Args:
            access_token: Your personal access token to verify.
        """
        user_info = get_user_info(access_token)

        if not user_info:
            return {
                "valid": False,
                "message": "Token not found or expired. Please re-authenticate.",
                "auth_url": f"{SERVER_URL}/auth/start"
            }

        expires_min = user_info["expires_in_seconds"] // 60

        return {
            "valid": True,
            "user_id": user_info["user_id"],
            "expires_in": f"{expires_min} minutes",
            "message": "Token is valid." if expires_min > 5 else "Token expiring soon, you may need to re-authenticate."
        }

    @mcp.tool()
    async def get_my_profile(access_token: str) -> dict:
        """
        Get your Blackboard user profile information.
        Shows your name, email, and account details.
        
        Args:
            access_token: Your personal access token (Claude will remember this).
        """
        try:
            user = await bb.get_current_user(access_token)

            name = user.get("name", {})
            contact = user.get("contact", {})

            return {
                "success": True,
                "profile": {
                    "name": f"{name.get('given', '')} {name.get('family', '')}".strip(),
                    "username": user.get("userName"),
                    "email": contact.get("email"),
                    "student_id": user.get("studentId"),
                    "institution_role": user.get("institutionRoleIds", []),
                    "last_login": user.get("lastLogin")
                }
            }

        except AuthenticationRequired:
            return _auth_error_response()
        except BlackboardAPIError as e:
            return {
                "error": "api_error",
                "message": e.message,
                "details": e.details
            }
