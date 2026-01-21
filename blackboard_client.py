"""
Blackboard API Client - handles all API requests to Blackboard Learn.
"""
import httpx
from auth import BLACKBOARD_URL, SERVER_URL, get_bb_token


class BlackboardAPIError(Exception):
    """Raised when Blackboard API returns an error"""
    def __init__(self, message: str, status_code: int = None, details: str = None):
        self.message = message
        self.status_code = status_code
        self.details = details
        super().__init__(message)


class AuthenticationRequired(Exception):
    """Raised when user needs to authenticate"""
    def __init__(self):
        self.auth_url = f"{SERVER_URL}/auth/start"
        super().__init__("Authentication required")


async def make_request(user_token: str, endpoint: str, method: str = "GET", **kwargs) -> dict:
    """
    Make authenticated request to Blackboard API.
    
    Args:
        user_token: The user's MCP access token
        endpoint: API endpoint (without base URL)
        method: HTTP method
        **kwargs: Additional arguments for httpx
        
    Returns:
        JSON response from Blackboard
        
    Raises:
        AuthenticationRequired: If token is missing or invalid
        BlackboardAPIError: If API returns an error
    """
    if not user_token:
        raise AuthenticationRequired()

    bb_token = get_bb_token(user_token)
    if not bb_token:
        raise AuthenticationRequired()

    url = f"{BLACKBOARD_URL}/learn/api/public/v1/{endpoint}"
    headers = {"Authorization": f"Bearer {bb_token}", **kwargs.pop("headers", {})}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.request(method, url, headers=headers, **kwargs)

            if response.status_code == 401:
                raise AuthenticationRequired()

            if response.status_code >= 400:
                raise BlackboardAPIError(
                    f"API error: {response.status_code}",
                    status_code=response.status_code,
                    details=response.text
                )

            return response.json()

    except httpx.RequestError as e:
        raise BlackboardAPIError(f"Request failed: {str(e)}")


# ============================================================================
# COURSE OPERATIONS
# ============================================================================

async def get_user_courses(user_token: str) -> list[dict]:
    """Get all courses the user is enrolled in"""
    result = await make_request(user_token, "users/me/courses")
    return result.get("results", [])


async def get_course_details(user_token: str, course_id: str) -> dict:
    """Get detailed information about a specific course"""
    return await make_request(user_token, f"courses/{course_id}")


async def get_course_contents(user_token: str, course_id: str) -> list[dict]:
    """Get content items (folders, assignments, etc.) for a course"""
    result = await make_request(user_token, f"courses/{course_id}/contents")
    return result.get("results", [])


async def get_content_children(user_token: str, course_id: str, content_id: str) -> list[dict]:
    """Get child content items within a folder"""
    result = await make_request(user_token, f"courses/{course_id}/contents/{content_id}/children")
    return result.get("results", [])


# ============================================================================
# GRADEBOOK OPERATIONS
# ============================================================================

async def get_gradebook_columns(user_token: str, course_id: str) -> list[dict]:
    """Get all gradebook columns for a course"""
    result = await make_request(user_token, f"courses/{course_id}/gradebook/columns")
    return result.get("results", [])


async def get_my_grades(user_token: str, course_id: str) -> list[dict]:
    """Get the current user's grades for a course"""
    result = await make_request(user_token, f"courses/{course_id}/gradebook/users/me")
    return result.get("results", [])


async def get_column_grades(user_token: str, course_id: str, column_id: str) -> list[dict]:
    """Get all grades for a specific column (instructor only)"""
    result = await make_request(user_token, f"courses/{course_id}/gradebook/columns/{column_id}/users")
    return result.get("results", [])


# ============================================================================
# ANNOUNCEMENT OPERATIONS
# ============================================================================

async def get_announcements(user_token: str, course_id: str) -> list[dict]:
    """Get announcements for a course"""
    result = await make_request(user_token, f"courses/{course_id}/announcements")
    return result.get("results", [])


# ============================================================================
# USER OPERATIONS
# ============================================================================

async def get_current_user(user_token: str) -> dict:
    """Get the current user's profile"""
    return await make_request(user_token, "users/me")


async def get_course_users(user_token: str, course_id: str) -> list[dict]:
    """Get all users enrolled in a course (instructor only)"""
    result = await make_request(user_token, f"courses/{course_id}/users")
    return result.get("results", [])


# ============================================================================
# ASSIGNMENT/ATTEMPT OPERATIONS
# ============================================================================

async def get_assignment_attempts(user_token: str, course_id: str, column_id: str) -> list[dict]:
    """Get attempts for an assignment column"""
    result = await make_request(
        user_token, 
        f"courses/{course_id}/gradebook/columns/{column_id}/attempts"
    )
    return result.get("results", [])


async def get_my_attempts(user_token: str, course_id: str, column_id: str) -> list[dict]:
    """Get current user's attempts for an assignment"""
    result = await make_request(
        user_token,
        f"courses/{course_id}/gradebook/columns/{column_id}/users/me"
    )
    return result.get("results", []) if "results" in result else [result]
