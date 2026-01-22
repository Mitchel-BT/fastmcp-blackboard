"""
Blackboard API Client - handles all API requests to Blackboard Learn.
Token is automatically retrieved from auth module - no need to pass it.
"""
import httpx
from auth import BLACKBOARD_URL, get_bb_token


class BlackboardAPIError(Exception):
    """Raised when Blackboard API returns an error"""
    def __init__(self, message: str, status_code: int = None, details: str = None):
        self.message = message
        self.status_code = status_code
        self.details = details
        super().__init__(message)


async def make_request(endpoint: str, method: str = "GET", **kwargs) -> dict:
    """
    Make authenticated request to Blackboard API.
    Token is automatically retrieved from auth module.
    
    Args:
        endpoint: API endpoint (without base URL)
        method: HTTP method
        **kwargs: Additional arguments for httpx
        
    Returns:
        JSON response from Blackboard
        
    Raises:
        ValueError: If not authenticated
        BlackboardAPIError: If API returns an error
    """
    token = get_bb_token()  # Get token from auth module

    url = f"{BLACKBOARD_URL}/learn/api/public/v1/{endpoint}"
    headers = {"Authorization": f"Bearer {token}", **kwargs.pop("headers", {})}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.request(method, url, headers=headers, timeout=30.0, **kwargs)

            if response.status_code == 401:
                raise ValueError("Token expired or invalid. Please re-authenticate.")

            if response.status_code >= 400:
                raise BlackboardAPIError(
                    f"API error: {response.status_code}",
                    status_code=response.status_code,
                    details=response.text
                )

            return response.json() if response.content else {}

    except httpx.RequestError as e:
        raise BlackboardAPIError(f"Request failed: {str(e)}")


# ============================================================================
# COURSE OPERATIONS
# ============================================================================

async def get_user_courses() -> list[dict]:
    """Get all courses the user is enrolled in"""
    result = await make_request("users/me/courses")
    return result.get("results", [])


async def get_course_details(course_id: str) -> dict:
    """Get detailed information about a specific course"""
    return await make_request(f"courses/{course_id}")


async def get_course_contents(course_id: str) -> list[dict]:
    """Get content items (folders, assignments, etc.) for a course"""
    result = await make_request(f"courses/{course_id}/contents")
    return result.get("results", [])


async def get_content_children(course_id: str, content_id: str) -> list[dict]:
    """Get child content items within a folder"""
    result = await make_request(f"courses/{course_id}/contents/{content_id}/children")
    return result.get("results", [])


# ============================================================================
# GRADEBOOK OPERATIONS
# ============================================================================

async def get_gradebook_columns(course_id: str) -> list[dict]:
    """Get all gradebook columns for a course"""
    result = await make_request(f"courses/{course_id}/gradebook/columns")
    return result.get("results", [])


async def get_my_grades(course_id: str) -> list[dict]:
    """Get the current user's grades for a course"""
    result = await make_request(f"courses/{course_id}/gradebook/users/me")
    return result.get("results", [])


async def get_column_grades(course_id: str, column_id: str) -> list[dict]:
    """Get all grades for a specific column (instructor only)"""
    result = await make_request(f"courses/{course_id}/gradebook/columns/{column_id}/users")
    return result.get("results", [])


# ============================================================================
# ANNOUNCEMENT OPERATIONS
# ============================================================================

async def get_announcements(course_id: str) -> list[dict]:
    """Get announcements for a course"""
    result = await make_request(f"courses/{course_id}/announcements")
    return result.get("results", [])


# ============================================================================
# USER OPERATIONS
# ============================================================================

async def get_current_user() -> dict:
    """Get the current user's profile"""
    return await make_request("users/me")


async def get_course_users(course_id: str) -> list[dict]:
    """Get all users enrolled in a course (instructor only)"""
    result = await make_request(f"courses/{course_id}/users")
    return result.get("results", [])


# ============================================================================
# ASSIGNMENT/ATTEMPT OPERATIONS
# ============================================================================

async def get_assignment_attempts(course_id: str, column_id: str) -> list[dict]:
    """Get attempts for an assignment column"""
    result = await make_request(f"courses/{course_id}/gradebook/columns/{column_id}/attempts")
    return result.get("results", [])


async def get_my_attempts(course_id: str, column_id: str) -> list[dict]:
    """Get current user's attempts for an assignment"""
    result = await make_request(f"courses/{course_id}/gradebook/columns/{column_id}/users/me")
    return result.get("results", []) if "results" in result else [result]
