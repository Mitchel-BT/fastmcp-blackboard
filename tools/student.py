"""
Student-focused MCP tools for Blackboard.
These tools are designed for students to view their courses, grades, and assignments.
"""
import blackboard_client as bb
from blackboard_client import AuthenticationRequired, BlackboardAPIError
from auth import SERVER_URL, get_user_info


def _auth_error_response():
    return {
        "error": "authentication_required",
        "message": "Please authenticate with Blackboard first.",
        "auth_url": f"{SERVER_URL}/auth/start"
    }


def _api_error_response(e: BlackboardAPIError):
    return {
        "error": "api_error",
        "message": e.message,
        "status_code": e.status_code,
        "details": e.details
    }


def register_student_tools(mcp):
    """Register all student tools with the MCP server"""

    @mcp.tool()
    async def get_my_courses(access_token: str) -> dict:
        """
        Get all courses you are enrolled in.
        Returns course names, IDs, and your role in each course.
        
        Args:
            access_token: Your personal access token. Once provided, Claude will remember it for subsequent requests.
        """
        try:
            memberships = await bb.get_user_courses(access_token)
            
            courses = []
            for m in memberships:
                course_id = m.get("courseId")
                # Fetch course details to get the name
                try:
                    course = await bb.get_course_details(access_token, course_id)
                    course_name = course.get("name", "Unknown Course")
                    course_code = course.get("courseId", "")
                except:
                    course_name = "Unknown Course"
                    course_code = ""
                
                courses.append({
                    "id": course_id,
                    "name": course_name,
                    "code": course_code,
                    "role": _friendly_role(m.get("courseRoleId")),
                    "available": m.get("availability", {}).get("available") == "Yes"
                })
            
            return {
                "success": True,
                "count": len(courses),
                "courses": courses
            }
            
        except AuthenticationRequired:
            return _auth_error_response()
        except BlackboardAPIError as e:
            return _api_error_response(e)

    @mcp.tool()
    async def get_my_grades(access_token: str, course_id: str) -> dict:
        """
        Get your grades for a specific course.
        Shows all graded items with your scores and feedback.
        
        Args:
            access_token: Your personal access token (Claude will remember this).
            course_id: The course ID from get_my_courses.
        """
        try:
            # Get gradebook columns first for context
            columns = await bb.get_gradebook_columns(access_token, course_id)
            column_map = {c["id"]: c for c in columns}
            
            # Get user's grades
            grades = await bb.get_my_grades(access_token, course_id)
            
            grade_items = []
            for g in grades:
                col_id = g.get("columnId")
                column = column_map.get(col_id, {})
                
                score = g.get("score")
                possible = column.get("score", {}).get("possible")
                
                grade_items.append({
                    "assignment": column.get("name", "Unknown"),
                    "score": score,
                    "possible": possible,
                    "percentage": f"{(score/possible*100):.1f}%" if score and possible else None,
                    "feedback": g.get("feedback"),
                    "graded_date": g.get("modified")
                })
            
            return {
                "success": True,
                "course_id": course_id,
                "count": len(grade_items),
                "grades": grade_items
            }
            
        except AuthenticationRequired:
            return _auth_error_response()
        except BlackboardAPIError as e:
            return _api_error_response(e)

    @mcp.tool()
    async def get_course_announcements(access_token: str, course_id: str) -> dict:
        """
        Get announcements for a specific course.
        Shows recent announcements from instructors.
        
        Args:
            access_token: Your personal access token (Claude will remember this).
            course_id: The course ID from get_my_courses.
        """
        try:
            announcements = await bb.get_announcements(access_token, course_id)
            
            items = []
            for a in announcements:
                items.append({
                    "title": a.get("title"),
                    "body": _clean_html(a.get("body", "")),
                    "posted": a.get("created"),
                    "modified": a.get("modified")
                })
            
            return {
                "success": True,
                "course_id": course_id,
                "count": len(items),
                "announcements": items
            }
            
        except AuthenticationRequired:
            return _auth_error_response()
        except BlackboardAPIError as e:
            return _api_error_response(e)

    @mcp.tool()
    async def get_course_content(access_token: str, course_id: str, folder_id: str = None) -> dict:
        """
        Get course materials and content.
        Can browse folders to find assignments, documents, and links.
        
        Args:
            access_token: Your personal access token (Claude will remember this).
            course_id: The course ID from get_my_courses.
            folder_id: Optional - ID of a folder to browse into. Leave empty for root content.
        """
        try:
            if folder_id:
                contents = await bb.get_content_children(access_token, course_id, folder_id)
            else:
                contents = await bb.get_course_contents(access_token, course_id)
            
            items = []
            for c in contents:
                handler = c.get("contentHandler", {}).get("id", "")
                
                items.append({
                    "id": c.get("id"),
                    "title": c.get("title"),
                    "type": _content_type(handler),
                    "description": _clean_html(c.get("body", "")),
                    "has_children": c.get("hasChildren", False),
                    "due_date": c.get("availability", {}).get("adaptiveRelease", {}).get("end"),
                    "available": c.get("availability", {}).get("available") == "Yes"
                })
            
            return {
                "success": True,
                "course_id": course_id,
                "folder_id": folder_id,
                "count": len(items),
                "items": items,
                "tip": "Use the 'id' of items with has_children=True to browse into folders"
            }
            
        except AuthenticationRequired:
            return _auth_error_response()
        except BlackboardAPIError as e:
            return _api_error_response(e)

    @mcp.tool()
    async def get_upcoming_assignments(access_token: str, course_id: str = None) -> dict:
        """
        Get upcoming assignments and due dates.
        Can check a specific course or all courses.
        
        Args:
            access_token: Your personal access token (Claude will remember this).
            course_id: Optional - specific course ID. If omitted, checks all courses.
        """
        try:
            assignments = []
            
            if course_id:
                course_ids = [course_id]
            else:
                memberships = await bb.get_user_courses(access_token)
                course_ids = [m["courseId"] for m in memberships 
                             if m.get("availability", {}).get("available") == "Yes"]
            
            for cid in course_ids[:10]:  # Limit to avoid too many API calls
                try:
                    columns = await bb.get_gradebook_columns(access_token, cid)
                    course = await bb.get_course_details(access_token, cid)
                    course_name = course.get("name", cid)
                    
                    for col in columns:
                        due = col.get("grading", {}).get("due")
                        if due:
                            assignments.append({
                                "course": course_name,
                                "course_id": cid,
                                "assignment": col.get("name"),
                                "due_date": due,
                                "points_possible": col.get("score", {}).get("possible")
                            })
                except:
                    continue
            
            # Sort by due date
            assignments.sort(key=lambda x: x.get("due_date") or "9999")
            
            return {
                "success": True,
                "count": len(assignments),
                "assignments": assignments
            }
            
        except AuthenticationRequired:
            return _auth_error_response()
        except BlackboardAPIError as e:
            return _api_error_response(e)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _friendly_role(role_id: str) -> str:
    """Convert Blackboard role ID to friendly name"""
    roles = {
        "Student": "Student",
        "Instructor": "Instructor",
        "TeachingAssistant": "Teaching Assistant",
        "CourseBuilder": "Course Builder",
        "Grader": "Grader",
        "Guest": "Guest"
    }
    return roles.get(role_id, role_id)


def _content_type(handler_id: str) -> str:
    """Convert content handler ID to friendly type"""
    types = {
        "resource/x-bb-folder": "Folder",
        "resource/x-bb-document": "Document",
        "resource/x-bb-assignment": "Assignment",
        "resource/x-bb-externallink": "External Link",
        "resource/x-bb-file": "File",
        "resource/x-bb-video": "Video",
        "resource/x-bb-audio": "Audio",
        "resource/x-bb-image": "Image"
    }
    return types.get(handler_id, "Content")


def _clean_html(html: str) -> str:
    """Basic HTML tag removal for cleaner output"""
    import re
    if not html:
        return ""
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', html)
    # Clean up whitespace
    text = ' '.join(text.split())
    return text[:500] + "..." if len(text) > 500 else text
