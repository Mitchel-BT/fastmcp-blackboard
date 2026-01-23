"""
Student-focused MCP tools for Blackboard.

No Depends usage (avoids ImportError in some fastmcp builds).
Works in both local + cloud mode by resolving the Blackboard token at runtime.
"""
import re

import blackboard_client as bb
from blackboard_client import BlackboardAPIError

from fastmcp.server.dependencies import get_access_token
from auth import IS_LOCAL_MODE, get_bb_token


async def _resolve_bb_token() -> str:
    if IS_LOCAL_MODE:
        return get_bb_token(None)  # local mode uses stored token :contentReference[oaicite:1]{index=1}
    mcp_access_token = await get_access_token()
    return get_bb_token(mcp_access_token)  # cloud mode uses injected token :contentReference[oaicite:2]{index=2}


def register_student_tools(mcp):
    """Register all student tools with the MCP server"""

    @mcp.tool()
    async def get_my_courses() -> dict:
        """Get all courses you are enrolled in."""
        try:
            bb_token = await _resolve_bb_token()
            courses = await bb.get_user_courses(access_token=bb_token)
            return {"success": True, "courses": courses, "count": len(courses)}
        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e), "exception_type": type(e).__name__}

    @mcp.tool()
    async def get_my_grades(course_id: str) -> dict:
        """
        Get your grades for a specific course.
        Shows all graded items with your scores and feedback.
        """
        try:
            bb_token = await _resolve_bb_token()

            # Gradebook columns for context
            columns = await bb.get_gradebook_columns(course_id, access_token=bb_token)
            column_map = {c.get("id"): c for c in columns if c.get("id")}

            # Your grades
            grades = await bb.get_my_grades(course_id, access_token=bb_token)

            grade_items = []
            for g in grades:
                col_id = g.get("columnId")
                column = column_map.get(col_id, {})

                score = g.get("score")
                possible = column.get("score", {}).get("possible")

                pct = None
                if score is not None and possible:
                    try:
                        pct = f"{(score / possible * 100):.1f}%"
                    except Exception:
                        pct = None

                grade_items.append({
                    "assignment": column.get("name", "Unknown"),
                    "score": score,
                    "possible": possible,
                    "percentage": pct,
                    "feedback": g.get("feedback"),
                    "graded_date": g.get("modified"),
                    "status": g.get("status"),
                })

            return {"success": True, "course_id": course_id, "count": len(grade_items), "grades": grade_items}

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e), "exception_type": type(e).__name__}

    @mcp.tool()
    async def get_course_announcements(course_id: str) -> dict:
        """
        Get announcements for a specific course.
        Shows recent announcements from instructors.
        """
        try:
            bb_token = await _resolve_bb_token()
            announcements = await bb.get_announcements(course_id, access_token=bb_token)

            items = []
            for a in announcements:
                items.append({
                    "title": a.get("title"),
                    "body": _clean_html(a.get("body", "")),
                    "posted": a.get("created"),
                    "modified": a.get("modified"),
                })

            return {"success": True, "course_id": course_id, "count": len(items), "announcements": items}

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e), "exception_type": type(e).__name__}

    @mcp.tool()
    async def get_course_content(course_id: str, folder_id: str = None) -> dict:
        """
        Get course materials and content.
        Can browse folders to find assignments, documents, and links.
        """
        try:
            bb_token = await _resolve_bb_token()

            if folder_id:
                contents = await bb.get_content_children(course_id, folder_id, access_token=bb_token)
            else:
                contents = await bb.get_course_contents(course_id, access_token=bb_token)

            items = []
            for c in contents:
                handler_id = c.get("contentHandler", {}).get("id", "")
                items.append({
                    "id": c.get("id"),
                    "title": c.get("title"),
                    "type": _content_type(handler_id),
                    "description": _clean_html(c.get("body", "")),
                    "has_children": c.get("hasChildren", False),
                    "available": c.get("availability", {}).get("available") == "Yes",
                })

            return {
                "success": True,
                "course_id": course_id,
                "folder_id": folder_id,
                "count": len(items),
                "items": items,
                "tip": "Use the 'id' of items with has_children=True to browse into folders",
            }

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e), "exception_type": type(e).__name__}

    @mcp.tool()
    async def get_upcoming_assignments(course_id: str = None) -> dict:
        """
        Get upcoming assignments and due dates.
        Can check a specific course or all courses (limited).
        """
        try:
            bb_token = await _resolve_bb_token()
            assignments = []

            if course_id:
                course_ids = [course_id]
            else:
                memberships = await bb.get_user_courses(access_token=bb_token)
                course_ids = [
                    m.get("courseId") for m in memberships
                    if m.get("availability", {}).get("available") == "Yes" and m.get("courseId")
                ]

            for cid in course_ids[:10]:  # limit calls
                try:
                    columns = await bb.get_gradebook_columns(cid, access_token=bb_token)
                    course = await bb.get_course_details(cid, access_token=bb_token)
                    course_name = course.get("name", cid)

                    for col in columns:
                        due = col.get("grading", {}).get("due")
                        if due:
                            assignments.append({
                                "course": course_name,
                                "course_id": cid,
                                "assignment": col.get("name"),
                                "due_date": due,
                                "points_possible": col.get("score", {}).get("possible"),
                            })
                except Exception:
                    continue

            assignments.sort(key=lambda x: x.get("due_date") or "9999")

            return {"success": True, "count": len(assignments), "assignments": assignments}

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e), "exception_type": type(e).__name__}


# =============================================================================
# Helper functions
# =============================================================================

def _content_type(handler_id: str) -> str:
    types = {
        "resource/x-bb-folder": "Folder",
        "resource/x-bb-document": "Document",
        "resource/x-bb-assignment": "Assignment",
        "resource/x-bb-externallink": "External Link",
        "resource/x-bb-file": "File",
        "resource/x-bb-video": "Video",
        "resource/x-bb-audio": "Audio",
        "resource/x-bb-image": "Image",
    }
    return types.get(handler_id, "Content")


def _clean_html(html: str) -> str:
    if not html:
        return ""
    text = re.sub(r"<[^>]+>", "", html)
    text = " ".join(text.split())
    return text[:500] + "..." if len(text) > 500 else text
