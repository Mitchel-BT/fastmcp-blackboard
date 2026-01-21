"""
Testing/Debug tools for Blackboard MCP Server.
Allows switching users, viewing session info, and testing without full re-auth flows.
"""
from auth import (
    SERVER_URL, 
    get_user_info, 
    get_bb_token,
    get_user_tokens,
)
import blackboard_client as bb
from blackboard_client import AuthenticationRequired, BlackboardAPIError


def _auth_error_response():
    return {
        "error": "authentication_required",
        "message": "Please authenticate with Blackboard first.",
        "auth_url": f"{SERVER_URL}/auth/start"
    }


def _api_error_response(e: BlackboardAPIError):
    return {
        "error": "api_error",
        "message": e.msg if hasattr(e, 'msg') else str(e),
        "status_code": e.status if hasattr(e, 'status') else None,
        "details": e.details if hasattr(e, 'details') else None
    }


def register_testing_tools(mcp):
    """Register testing/debug tools with the MCP server"""

    @mcp.tool()
    async def switch_user() -> dict:
        """
        [Testing] Get a new authentication link to switch to a different Blackboard user.
        Use this to test as different roles (student, instructor) in the same session.
        """
        return {
            "message": "Click the link below to authenticate as a different user:",
            "auth_url": f"{SERVER_URL}/auth/start",
            "tip": "After authenticating, you'll get a new access token. Give me that token and I'll use the new account."
        }

    @mcp.tool()
    async def list_active_sessions() -> dict:
        """
        [Testing] List all active user sessions on this server.
        Shows token previews, user IDs, and expiry status.
        """
        user_tokens = get_user_tokens()
        
        if not user_tokens:
            return {"message": "No active sessions", "count": 0, "sessions": []}
        
        import time
        sessions = []
        for token, creds in user_tokens.items():
            age = time.time() - creds["obtained_at"]
            expires_in = max(0, int(creds["bb_expires_in"] - age))
            
            sessions.append({
                "token_preview": token[:8] + "..." + token[-4:],
                "user_id": creds["bb_user_id"],
                "age_seconds": int(age),
                "expires_in_seconds": expires_in,
                "status": "valid" if expires_in > 0 else "expired"
            })
        
        return {
            "count": len(sessions),
            "sessions": sessions,
            "tip": "Use the full token (not preview) when calling other tools"
        }

    @mcp.tool()
    async def whoami(access_token: str) -> dict:
        """
        [Testing] Check which user is associated with a token and their role in each course.
        Useful for verifying you're testing as the right user.
        
        Args:
            access_token: The token to check
        """
        try:
            # Get user profile
            user = await bb.get_current_user(access_token)
            name = user.get("name", {})
            
            # Get courses with roles
            memberships = await bb.get_user_courses(access_token)
            
            courses = []
            for m in memberships:
                course_id = m.get("courseId")
                role = m.get("courseRoleId")
                try:
                    course = await bb.get_course_details(access_token, course_id)
                    course_name = course.get("name", course_id)
                except:
                    course_name = course_id
                
                courses.append({
                    "course": course_name,
                    "role": role,
                    "course_id": course_id
                })
            
            # Summarize roles
            roles = set(c["role"] for c in courses)
            
            return {
                "success": True,
                "user": {
                    "name": f"{name.get('given', '')} {name.get('family', '')}".strip(),
                    "username": user.get("userName"),
                    "email": user.get("contact", {}).get("email"),
                    "user_id": user.get("id")
                },
                "roles_summary": list(roles),
                "is_instructor": "Instructor" in roles,
                "is_student": "Student" in roles,
                "course_count": len(courses),
                "courses": courses
            }
            
        except AuthenticationRequired:
            return _auth_error_response()
        except BlackboardAPIError as e:
            return _api_error_response(e)

    @mcp.tool()
    async def compare_users(token_a: str, token_b: str) -> dict:
        """
        [Testing] Compare two user sessions side-by-side.
        Useful for verifying different test accounts have the expected roles.
        
        Args:
            token_a: First user's access token
            token_b: Second user's access token
        """
        async def get_user_summary(token, label):
            try:
                user = await bb.get_current_user(token)
                name = user.get("name", {})
                memberships = await bb.get_user_courses(token)
                roles = set(m.get("courseRoleId") for m in memberships)
                
                return {
                    "label": label,
                    "name": f"{name.get('given', '')} {name.get('family', '')}".strip(),
                    "username": user.get("userName"),
                    "roles": list(roles),
                    "course_count": len(memberships),
                    "is_instructor": "Instructor" in roles,
                    "is_student": "Student" in roles
                }
            except:
                return {"label": label, "error": "Failed to fetch user info"}
        
        user_a = await get_user_summary(token_a, "User A")
        user_b = await get_user_summary(token_b, "User B")
        
        return {
            "success": True,
            "user_a": user_a,
            "user_b": user_b,
            "comparison": {
                "same_user": user_a.get("username") == user_b.get("username"),
                "a_is_instructor": user_a.get("is_instructor", False),
                "b_is_instructor": user_b.get("is_instructor", False),
                "a_is_student": user_a.get("is_student", False),
                "b_is_student": user_b.get("is_student", False)
            }
        }

    @mcp.tool()
    async def clear_session(access_token: str) -> dict:
        """
        [Testing] Clear/invalidate a specific session token.
        The user will need to re-authenticate to get a new token.
        
        Args:
            access_token: The token to invalidate
        """
        user_tokens = get_user_tokens()
        
        if access_token in user_tokens:
            user_id = user_tokens[access_token].get("bb_user_id", "unknown")
            del user_tokens[access_token]
            return {
                "success": True,
                "message": f"Session cleared for user {user_id}",
                "auth_url": f"{SERVER_URL}/auth/start"
            }
        else:
            return {
                "success": False,
                "message": "Token not found - may already be expired or invalid"
            }

    @mcp.tool()
    async def clear_all_sessions() -> dict:
        """
        [Testing] Clear ALL active sessions. Everyone will need to re-authenticate.
        Use with caution!
        """
        user_tokens = get_user_tokens()
        count = len(user_tokens)
        user_tokens.clear()
        return {
            "success": True,
            "message": f"Cleared {count} session(s)",
            "auth_url": f"{SERVER_URL}/auth/start"
        }
