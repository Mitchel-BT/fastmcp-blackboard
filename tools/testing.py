import blackboard_client as bb
from blackboard_client import BlackboardAPIError
from fastmcp.server.dependencies import get_access_token
from fastmcp import Depends
from auth import IS_LOCAL_MODE, BLACKBOARD_URL, SERVER_URL, get_local_token, get_bb_token

def register_testing_tools(mcp):
    """Register testing/debug tools with the MCP server"""
    @mcp.tool()
    async def which_server() -> dict:
        import sys
        return {
            "server_file": __file__,
            "sys_path_head": sys.path[:3],
        }

    @mcp.tool()
    async def whoami(access_token: str = Depends(get_access_token)) -> dict:
        from auth import get_bb_token  # ensures defined
        import blackboard_client as bb

        bb_token = get_bb_token(access_token)
        user = await bb.get_current_user(access_token=bb_token)
        return {
            "success": True,
            "userName": user.get("userName"),
            "id": user.get("id"),
        }

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
