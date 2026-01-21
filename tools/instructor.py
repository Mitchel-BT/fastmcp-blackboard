"""
Instructor/Faculty-focused MCP tools for Blackboard.
These tools are designed for instructors to view rosters, grades, and manage courses.
"""
import blackboard_client as bb
from blackboard_client import AuthenticationRequired, BlackboardAPIError
from auth import SERVER_URL


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


def register_instructor_tools(mcp):
    """Register all instructor tools with the MCP server"""

    @mcp.tool()
    async def get_course_roster(access_token: str, course_id: str) -> dict:
        """
        [Instructor] Get the full roster of students enrolled in a course.
        Shows student names, emails, and enrollment status.
        
        Args:
            access_token: Your personal access token (Claude will remember this).
            course_id: The course ID to get the roster for.
        """
        try:
            enrollments = await bb.get_course_users(access_token, course_id)
            
            students = []
            instructors = []
            
            for e in enrollments:
                user = e.get("user", {})
                role = e.get("courseRoleId", "")
                
                person = {
                    "id": e.get("userId"),
                    "name": f"{user.get('name', {}).get('given', '')} {user.get('name', {}).get('family', '')}".strip(),
                    "email": user.get("contact", {}).get("email"),
                    "username": user.get("userName"),
                    "available": e.get("availability", {}).get("available") == "Yes",
                    "last_accessed": e.get("lastAccessed")
                }
                
                if role == "Student":
                    students.append(person)
                else:
                    person["role"] = _friendly_role(role)
                    instructors.append(person)
            
            return {
                "success": True,
                "course_id": course_id,
                "student_count": len(students),
                "instructor_count": len(instructors),
                "students": students,
                "instructors": instructors
            }
            
        except AuthenticationRequired:
            return _auth_error_response()
        except BlackboardAPIError as e:
            return _api_error_response(e)

    @mcp.tool()
    async def get_gradebook_overview(access_token: str, course_id: str) -> dict:
        """
        [Instructor] Get an overview of the gradebook for a course.
        Shows all grade columns with submission counts and averages.
        
        Args:
            access_token: Your personal access token (Claude will remember this).
            course_id: The course ID to get gradebook overview for.
        """
        try:
            columns = await bb.get_gradebook_columns(access_token, course_id)
            
            grade_items = []
            for col in columns:
                # Only include actual gradable columns
                if col.get("score", {}).get("possible"):
                    grade_items.append({
                        "id": col.get("id"),
                        "name": col.get("name"),
                        "points_possible": col.get("score", {}).get("possible"),
                        "due_date": col.get("grading", {}).get("due"),
                        "type": col.get("grading", {}).get("type"),
                        "visible_to_students": col.get("availability", {}).get("available") == "Yes"
                    })
            
            return {
                "success": True,
                "course_id": course_id,
                "column_count": len(grade_items),
                "columns": grade_items,
                "tip": "Use get_column_grades with a column ID to see individual student grades"
            }
            
        except AuthenticationRequired:
            return _auth_error_response()
        except BlackboardAPIError as e:
            return _api_error_response(e)

    @mcp.tool()
    async def get_column_grades(access_token: str, course_id: str, column_id: str) -> dict:
        """
        [Instructor] Get all student grades for a specific assignment/column.
        Shows each student's score, submission status, and feedback.
        
        Args:
            access_token: Your personal access token (Claude will remember this).
            course_id: The course ID.
            column_id: The gradebook column ID from get_gradebook_overview.
        """
        try:
            grades = await bb.get_column_grades(access_token, course_id, column_id)
            
            # Get roster for names
            enrollments = await bb.get_course_users(access_token, course_id)
            user_map = {}
            for e in enrollments:
                user = e.get("user", {})
                user_map[e.get("userId")] = {
                    "name": f"{user.get('name', {}).get('given', '')} {user.get('name', {}).get('family', '')}".strip(),
                    "username": user.get("userName")
                }
            
            student_grades = []
            total_score = 0
            graded_count = 0
            
            for g in grades:
                user_id = g.get("userId")
                user_info = user_map.get(user_id, {})
                score = g.get("score")
                
                student_grades.append({
                    "student_name": user_info.get("name", "Unknown"),
                    "username": user_info.get("username"),
                    "score": score,
                    "status": g.get("status"),
                    "feedback": g.get("feedback"),
                    "submitted": g.get("created"),
                    "graded": g.get("modified")
                })
                
                if score is not None:
                    total_score += score
                    graded_count += 1
            
            avg = total_score / graded_count if graded_count > 0 else None
            
            return {
                "success": True,
                "course_id": course_id,
                "column_id": column_id,
                "total_students": len(student_grades),
                "graded_count": graded_count,
                "average_score": round(avg, 2) if avg else None,
                "grades": student_grades
            }
            
        except AuthenticationRequired:
            return _auth_error_response()
        except BlackboardAPIError as e:
            return _api_error_response(e)

    @mcp.tool()
    async def get_submission_status(access_token: str, course_id: str, column_id: str) -> dict:
        """
        [Instructor] Get a quick summary of submission status for an assignment.
        Shows how many students have submitted, not submitted, and need grading.
        
        Args:
            access_token: Your personal access token (Claude will remember this).
            course_id: The course ID.
            column_id: The gradebook column ID from get_gradebook_overview.
        """
        try:
            grades = await bb.get_column_grades(access_token, course_id, column_id)
            enrollments = await bb.get_course_users(access_token, course_id)
            
            # Count students only
            student_count = sum(1 for e in enrollments if e.get("courseRoleId") == "Student")
            
            submitted = 0
            graded = 0
            needs_grading = 0
            
            for g in grades:
                status = g.get("status")
                if status == "Graded":
                    graded += 1
                    submitted += 1
                elif status == "NeedsGrading":
                    needs_grading += 1
                    submitted += 1
                elif g.get("score") is not None:
                    submitted += 1
            
            not_submitted = student_count - submitted
            
            return {
                "success": True,
                "course_id": course_id,
                "column_id": column_id,
                "total_students": student_count,
                "submitted": submitted,
                "not_submitted": not_submitted,
                "graded": graded,
                "needs_grading": needs_grading,
                "completion_rate": f"{(submitted/student_count*100):.1f}%" if student_count > 0 else "0%"
            }
            
        except AuthenticationRequired:
            return _auth_error_response()
        except BlackboardAPIError as e:
            return _api_error_response(e)

    @mcp.tool()
    async def find_inactive_students(access_token: str, course_id: str, days: int = 7) -> dict:
        """
        [Instructor] Find students who haven't accessed the course recently.
        Useful for identifying students who may need outreach.
        
        Args:
            access_token: Your personal access token (Claude will remember this).
            course_id: The course ID to check.
            days: Number of days of inactivity (default 7).
        """
        try:
            from datetime import datetime, timedelta
            
            enrollments = await bb.get_course_users(access_token, course_id)
            cutoff = datetime.utcnow() - timedelta(days=days)
            
            inactive = []
            never_accessed = []
            
            for e in enrollments:
                if e.get("courseRoleId") != "Student":
                    continue
                    
                user = e.get("user", {})
                name = f"{user.get('name', {}).get('given', '')} {user.get('name', {}).get('family', '')}".strip()
                
                last_accessed = e.get("lastAccessed")
                
                if not last_accessed:
                    never_accessed.append({
                        "name": name,
                        "email": user.get("contact", {}).get("email"),
                        "username": user.get("userName")
                    })
                else:
                    try:
                        access_date = datetime.fromisoformat(last_accessed.replace("Z", "+00:00"))
                        if access_date.replace(tzinfo=None) < cutoff:
                            inactive.append({
                                "name": name,
                                "email": user.get("contact", {}).get("email"),
                                "username": user.get("userName"),
                                "last_accessed": last_accessed
                            })
                    except:
                        pass
            
            return {
                "success": True,
                "course_id": course_id,
                "days_threshold": days,
                "never_accessed_count": len(never_accessed),
                "inactive_count": len(inactive),
                "never_accessed": never_accessed,
                "inactive_students": inactive
            }
            
        except AuthenticationRequired:
            return _auth_error_response()
        except BlackboardAPIError as e:
            return _api_error_response(e)


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
