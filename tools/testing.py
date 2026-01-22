"""
Testing/Debug tools for Blackboard MCP Server.
With OAuthProxy, session management is handled automatically by FastMCP.
These tools help verify the connection and check user info.
"""
import blackboard_client as bb
from blackboard_client import BlackboardAPIError


def register_testing_tools(mcp):
    """Register testing/debug tools with the MCP server"""

    @mcp.tool()
    async def debug_auth_state() -> dict:
        """
        [Debug] Show the current authentication state.
        Helps diagnose why tools might be failing.
        """
        from auth import IS_LOCAL_MODE, BLACKBOARD_URL, SERVER_URL, get_local_token
        
        result = {
            "mode": "LOCAL" if IS_LOCAL_MODE else "CLOUD",
            "blackboard_url": BLACKBOARD_URL,
            "server_url": SERVER_URL or "(not set)",
        }
        
        # Check local token state
        if IS_LOCAL_MODE:
            local_token = get_local_token()
            result["local_token_set"] = local_token is not None
            if local_token:
                result["local_token_preview"] = f"{local_token[:8]}...{local_token[-4:]}"
            else:
                result["local_token_preview"] = None
                result["issue"] = "Token was not stored after OAuth flow!"
        
        # Try to get token via get_bb_token
        try:
            from auth import get_bb_token
            token = get_bb_token()
            result["get_bb_token_works"] = True
            result["token_preview"] = f"{token[:8]}...{token[-4:]}"
        except Exception as e:
            result["get_bb_token_works"] = False
            result["get_bb_token_error"] = str(e)
        
        return result

    @mcp.tool()
    async def debug_test_api_call() -> dict:
        """
        [Debug] Make a raw API call to test if the token works.
        """
        import httpx
        from auth import BLACKBOARD_URL, get_local_token, IS_LOCAL_MODE
        
        if IS_LOCAL_MODE:
            token = get_local_token()
        else:
            try:
                from auth import get_bb_token
                token = get_bb_token()
            except Exception as e:
                return {"error": f"Could not get token: {e}"}
        
        if not token:
            return {"error": "No token available", "local_token_is_none": True}
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10.0
                )
                
                return {
                    "status_code": response.status_code,
                    "success": response.status_code == 200,
                    "response": response.json() if response.status_code == 200 else response.text[:500]
                }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def whoami() -> dict:
        """
        [Testing] Check which user is currently authenticated and their role in each course.
        Useful for verifying you're connected as the right user.
        """
        try:
            token = get_bb_token()
            
            # Get user profile
            user = await bb.get_current_user(token)
            name = user.get("name", {})
            
            # Get courses with roles
            memberships = await bb.get_user_courses(token)
            
            courses = []
            for m in memberships:
                course_id = m.get("courseId")
                role = m.get("courseRoleId")
                try:
                    course = await bb.get_course_details(token, course_id)
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
            
        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {
                "error": "api_error",
                "message": e.message if hasattr(e, 'message') else str(e),
                "status_code": e.status_code if hasattr(e, 'status_code') else None,
                "details": e.details if hasattr(e, 'details') else None
            }

    @mcp.tool()
    async def test_connection() -> dict:
        """
        [Testing] Test that the Blackboard connection is working.
        Shows which mode (local/cloud) and verifies authentication.
        """
        from auth import IS_LOCAL_MODE, BLACKBOARD_URL, SERVER_URL
        
        mode = "LOCAL (stdio)" if IS_LOCAL_MODE else "CLOUD (HTTP)"
        
        try:
            user = await bb.get_current_user()
            
            return {
                "success": True,
                "message": "✅ Connection successful!",
                "mode": mode,
                "blackboard_url": BLACKBOARD_URL,
                "server_url": SERVER_URL or "(not set - local mode)",
                "connected_as": user.get("userName"),
                "user_id": user.get("id")
            }
            
        except ValueError as e:
            return {
                "success": False,
                "mode": mode,
                "message": f"❌ Not authenticated: {str(e)}",
                "tip": "Reconnect this server in Claude's settings to re-authenticate"
            }
        except BlackboardAPIError as e:
            return {
                "success": False,
                "mode": mode,
                "message": f"❌ API error: {e.message if hasattr(e, 'message') else str(e)}",
                "tip": "Your token may have expired. Reconnect in Claude's settings."
            }

    @mcp.tool()
    async def test_api_endpoint(endpoint: str) -> dict:
        """
        [Testing] Test a raw Blackboard API endpoint.
        Useful for debugging API responses.
        
        Args:
            endpoint: The API endpoint path (e.g., "/users/me" or "/courses")
        """
        try:
            token = get_bb_token()
            
            # Ensure endpoint starts with /
            if not endpoint.startswith("/"):
                endpoint = "/" + endpoint
            
            # Make the request using the blackboard_client's base functionality
            import httpx
            from auth import BLACKBOARD_URL
            
            url = f"{BLACKBOARD_URL}/learn/api/public/v1{endpoint}"
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=30.0
                )
                
                return {
                    "success": response.status_code < 400,
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "response": response.json() if response.content else None
                }
                
        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except Exception as e:
            return {"error": "request_failed", "message": str(e)}


# =============================================================================
# NOTE: The following tools from the old version are no longer applicable
# with OAuthProxy, since session management is handled by FastMCP:
#
# - switch_user: Users switch by disconnecting/reconnecting in Claude settings
# - list_active_sessions: OAuthProxy manages sessions internally
# - compare_users: Not possible with single-user OAuth flow
# - clear_session: Sessions are managed by Claude/OAuthProxy
# - clear_all_sessions: Not accessible with OAuthProxy
#
# If you need multi-user testing, you would:
# 1. Disconnect the server in Claude settings
# 2. Reconnect and authenticate as a different user
# =============================================================================
