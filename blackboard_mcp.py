"""
Blackboard MCP Server - Cloud-Ready Version
For FastMCP Cloud deployment
"""

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import OAuthProxy

# ============================================================================
# CONFIGURATION - Hardcoded for simplicity
# ============================================================================

BLACKBOARD_URL="https://anthropic.bt-retool.shop"
BLACKBOARD_APP_KEY="a743ef51-d7bc-4a7e-97e6-bae6f086a0d4"
BLACKBOARD_APP_SECRET="2DXuZHi9QFZgKfIAkt8JJKhVWDBRdT0q"

# FastMCP Cloud will give you this URL after first deploy
# Format: https://your-project-name.fastmcp.app
BASE_URL = "https://blackboard-mcp.fastmcp.app/mcp"          # UPDATE AFTER DEPLOY

# ============================================================================
# OAUTH PROXY FOR BLACKBOARD
# ============================================================================

auth = OAuthProxy(
    client_id=BLACKBOARD_APP_KEY,
    client_secret=BLACKBOARD_APP_SECRET,
    base_url=BASE_URL,
    
    # Blackboard OAuth endpoints
    authorize_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode",
    token_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/token",
    
    # Callback path - full URL will be {BASE_URL}/oauth/callback
    redirect_path="/oauth/callback",
    
    # Blackboard scopes
    required_scopes=["read", "write"],
    
    # Blackboard uses Basic auth for token endpoint
    token_endpoint_auth_method="client_secret_basic",
    
    # Blackboard likely doesn't support PKCE
    forward_pkce=False,
)

# ============================================================================
# MCP SERVER
# ============================================================================

mcp = FastMCP(
    name="Blackboard",
    auth=auth,
)


async def get_bb_token(ctx) -> str:
    """Extract Blackboard access token from authenticated session"""
    if hasattr(ctx, 'session') and ctx.session:
        if hasattr(ctx.session, 'access_token'):
            return ctx.session.access_token
    raise Exception("Not authenticated - please authenticate first")


@mcp.tool()
async def get_my_courses(ctx) -> str:
    """Get all courses the authenticated user has access to"""
    token = await get_bb_token(ctx)
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{BLACKBOARD_URL}/learn/api/public/v1/courses?limit=100",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code != 200:
            return f"Error: {response.status_code} - {response.text}"
        
        data = response.json()
        courses = data.get("results", [])
        
        if not courses:
            return "No courses found"
        
        result = f"Found {len(courses)} courses:\n\n"
        for course in courses:
            result += f"- {course.get('name', 'Unnamed')} (ID: {course.get('id')})\n"
        
        return result


@mcp.tool()
async def get_course_assignments(ctx, course_id: str) -> str:
    """
    Get assignments for a course with due dates.
    
    Args:
        course_id: The course ID (e.g., "_123_1")
    """
    token = await get_bb_token(ctx)
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{BLACKBOARD_URL}/learn/api/public/v1/courses/{course_id}/gradebook/columns",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code != 200:
            return f"Error: {response.status_code} - {response.text}"
        
        data = response.json()
        columns = data.get("results", [])
        
        assignments = [c for c in columns if c.get("grading", {}).get("due")]
        
        if not assignments:
            return f"No assignments with due dates found in course {course_id}"
        
        result = f"Found {len(assignments)} assignments:\n\n"
        for assignment in assignments:
            name = assignment.get("name", "Unnamed")
            points = assignment.get("score", {}).get("possible", "?")
            due = assignment.get("grading", {}).get("due", "No due date")
            result += f"- {name} ({points} points) - Due: {due}\n"
        
        return result


@mcp.tool()
async def get_course_content(ctx, course_id: str) -> str:
    """
    Get content/materials for a course.
    
    Args:
        course_id: The course ID (e.g., "_123_1")
    """
    token = await get_bb_token(ctx)
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{BLACKBOARD_URL}/learn/api/public/v1/courses/{course_id}/contents",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code != 200:
            return f"Error: {response.status_code} - {response.text}"
        
        data = response.json()
        contents = data.get("results", [])
        
        if not contents:
            return f"No content found in course {course_id}"
        
        result = f"Found {len(contents)} content items:\n\n"
        for item in contents:
            title = item.get("title", "Untitled")
            content_type = item.get("contentHandler", {}).get("id", "unknown")
            result += f"- {title} (Type: {content_type})\n"
        
        return result


@mcp.tool()
async def check_auth_status(ctx) -> str:
    """Check current authentication status"""
    try:
        token = await get_bb_token(ctx)
        return f"✓ Authenticated with Blackboard\nToken preview: {token[:20]}..."
    except Exception as e:
        return f"✗ Not authenticated: {str(e)}"
