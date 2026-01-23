import blackboard_client as bb
from blackboard_client import BlackboardAPIError
from fastmcp.server.dependencies import get_access_token
from fastmcp import Depends
from auth import IS_LOCAL_MODE, BLACKBOARD_URL, SERVER_URL, get_local_token, get_bb_token

def register_testing_tools(mcp):
    """Register testing/debug tools with the MCP server"""

    @mcp.tool()
    async def debug_auth_state(access_token: str = Depends(get_access_token)) -> dict:
        result = {
            "mode": "LOCAL" if IS_LOCAL_MODE else "CLOUD",
            "blackboard_url": BLACKBOARD_URL,
            "server_url": SERVER_URL or "(not set)",
        }

        if IS_LOCAL_MODE:
            local_token = get_local_token()
            result["local_token_set"] = local_token is not None
            result["local_token_preview"] = (
                f"{local_token[:8]}...{local_token[-4:]}" if local_token else None
            )

        try:
            token = get_bb_token(access_token)
            result["get_bb_token_works"] = True
            result["token_preview"] = f"{token[:8]}...{token[-4:]}"
        except Exception as e:
            result["get_bb_token_works"] = False
            result["get_bb_token_error"] = str(e)

        return result

    @mcp.tool()
    async def debug_test_api_call(access_token: str = Depends(get_access_token)) -> dict:
        import httpx

        try:
            token = get_bb_token(access_token)
        except Exception as e:
            return {"error": f"Could not get token: {e}"}

        if not token:
            return {"error": "No token available", "token_is_none": True}

        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10.0
            )
            return {
                "status_code": r.status_code,
                "success": r.status_code == 200,
                "response": r.json() if r.status_code == 200 else r.text[:500],
            }

    @mcp.tool()
    async def whoami(access_token: str = Depends(get_access_token)) -> dict:
        try:
            bb_token = get_bb_token(access_token)
            if not bb_token:
                return {"error": "not_authenticated", "message": "No Blackboard token available"}

            # Debug info *after* bb_token exists
            debug = {
                "mcp_access_token_prefix": (access_token[:12] + "...") if access_token else None,
                "bb_token_prefix": (bb_token[:12] + "...") if bb_token else None,
            }

            user = await bb.get_current_user(access_token=bb_token)
            name = user.get("name", {})

            memberships = await bb.get_user_courses(access_token=bb_token)

            courses = []
            for m in memberships:
                course_id = m.get("courseId")
                role = m.get("courseRoleId")

                try:
                    course = await bb.get_course_details(course_id, access_token=bb_token)
                    course_name = course.get("name", course_id)
                except Exception:
                    course_name = course_id

                courses.append({"course": course_name, "role": role, "course_id": course_id})

            roles = sorted({c["role"] for c in courses if c.get("role")})

            return {
                "success": True,
                "debug": debug,
                "user": {
                    "name": f"{name.get('given', '')} {name.get('family', '')}".strip(),
                    "username": user.get("userName"),
                    "email": user.get("contact", {}).get("email"),
                    "user_id": user.get("id"),
                },
                "roles_summary": roles,
                "is_instructor": "Instructor" in roles,
                "is_student": "Student" in roles,
                "course_count": len(courses),
                "courses": courses,
            }

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {
                "error": "api_error",
                "message": getattr(e, "message", str(e)),
                "status_code": getattr(e, "status_code", None),
                "details": getattr(e, "details", None),
            }
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e), "exception_type": type(e).__name__}
