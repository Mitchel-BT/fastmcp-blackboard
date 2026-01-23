"""
Student-focused MCP tools for Blackboard.

Auth strategy:
- Local mode: use stored token via get_bb_token(None)
- Cloud mode: await fastmcp get_access_token(), then pass to get_bb_token(...)
"""
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import blackboard_client as bb
from blackboard_client import BlackboardAPIError

from fastmcp.server.dependencies import get_access_token
from auth import IS_LOCAL_MODE, get_bb_token


async def _resolve_bb_token() -> str:
    if IS_LOCAL_MODE:
        return get_bb_token(None)
    mcp_access_token = await get_access_token()
    return get_bb_token(mcp_access_token)


def _parse_bb_datetime(dt: Optional[str]) -> Optional[datetime]:
    """
    Blackboard timestamps often look like '2023-09-08T15:35:05.817Z'
    """
    if not dt:
        return None
    try:
        # handle trailing Z
        if dt.endswith("Z"):
            return datetime.fromisoformat(dt.replace("Z", "+00:00"))
        return datetime.fromisoformat(dt)
    except Exception:
        return None


def _clean_html(html: str) -> str:
    """Basic HTML tag removal for cleaner output."""
    if not html:
        return ""
    text = re.sub(r"<[^>]+>", "", html)
    text = " ".join(text.split())
    return text[:500] + "..." if len(text) > 500 else text


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


def register_student_tools(mcp):
    """Register all student tools with the MCP server"""
    @mcp.tool()
    async def get_assignment_description(
        course_id: str,
        content_id: str,
        include_raw_html: bool = False
    ) -> dict:
        """
        Get an assignment's description/instructions by content item id.

        Args:
            course_id: Blackboard course id (e.g., "_123_1")
            content_id: Blackboard content id for the assignment (e.g., "_17196_1")
            include_raw_html: include raw body/instructions HTML in the response
        """
        try:
            bb_token = await _resolve_bb_token()

            item = await bb.get_content_item(course_id, content_id, access_token=bb_token)

            # Different items may store description/instructions differently.
            body_html = item.get("body") or item.get("instructions") or ""
            description_text = _clean_html(body_html)

            resp = {
                "success": True,
                "course_id": course_id,
                "content_id": content_id,
                "title": item.get("title"),
                "description": description_text,
                "note": (
                    "Some Ultra assignments created/edited in the Learn UI may not expose "
                    "instructions via REST (platform limitation)."
                ),
            }

            if include_raw_html:
                resp["raw_html"] = body_html

            return resp

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e), "exception_type": type(e).__name__}


    @mcp.tool()
    async def get_my_courses(include_course_names: bool = False, limit: int = 50) -> dict:
        """
        Get all courses you are enrolled in.

        Args:
            include_course_names: If true, fetch course details to include course name (more API calls).
            limit: Max memberships to return.
        """
        try:
            bb_token = await _resolve_bb_token()
            memberships = await bb.get_user_courses(access_token=bb_token)
            memberships = memberships[: max(1, min(limit, 200))]

            if not include_course_names:
                return {"success": True, "courses": memberships, "count": len(memberships)}

            # Enrich with course names (bounded)
            enriched = []
            for m in memberships:
                cid = m.get("courseId")
                course_name = None
                if cid:
                    try:
                        course = await bb.get_course_details(cid, access_token=bb_token)
                        course_name = course.get("name")
                    except Exception:
                        course_name = None
                enriched.append({**m, "courseName": course_name})

            return {"success": True, "courses": enriched, "count": len(enriched)}

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e)}

    @mcp.tool()
    async def get_my_grades(course_id: str) -> dict:
        """
        Get your grades for a specific course.
        Includes assignment name + points possible by joining gradebook columns.
        """
        try:
            bb_token = await _resolve_bb_token()

            columns = await bb.get_gradebook_columns(course_id, access_token=bb_token)
            column_map = {c.get("id"): c for c in columns if c.get("id")}

            grades = await bb.get_my_grades(course_id, access_token=bb_token)

            grade_items = []
            for g in grades:
                col_id = g.get("columnId")
                col = column_map.get(col_id, {})
                score = g.get("score")
                possible = col.get("score", {}).get("possible")

                pct = None
                if score is not None and possible:
                    try:
                        pct = round((score / possible) * 100, 1)
                    except Exception:
                        pct = None

                grade_items.append(
                    {
                        "assignment": col.get("name") or col.get("displayName") or "Unknown",
                        "column_id": col_id,
                        "score": score,
                        "possible": possible,
                        "percentage": f"{pct}%" if pct is not None else None,
                        "status": g.get("status"),
                        "feedback": g.get("feedback"),
                        "graded_date": g.get("modified"),
                    }
                )

            return {"success": True, "course_id": course_id, "count": len(grade_items), "grades": grade_items}

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e)}

    @mcp.tool()
    async def get_course_announcements(course_id: str, limit: int = 20) -> dict:
        """
        Get announcements for a specific course.
        """
        try:
            bb_token = await _resolve_bb_token()
            announcements = await bb.get_announcements(course_id, access_token=bb_token)

            items = []
            for a in announcements[: max(1, min(limit, 50))]:
                items.append(
                    {
                        "title": a.get("title"),
                        "body": _clean_html(a.get("body", "")),
                        "posted": a.get("created"),
                        "modified": a.get("modified"),
                    }
                )

            return {"success": True, "course_id": course_id, "count": len(items), "announcements": items}

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e)}

    @mcp.tool()
    async def get_course_content(course_id: str, folder_id: str = None, limit: int = 100) -> dict:
        """
        Browse course materials and content (folders, items, etc.).

        Args:
            course_id: Course ID
            folder_id: If provided, browse children of this folder; otherwise browse root
            limit: Max items to return
        """
        try:
            bb_token = await _resolve_bb_token()

            if folder_id:
                contents = await bb.get_content_children(course_id, folder_id, access_token=bb_token)
            else:
                contents = await bb.get_course_contents(course_id, access_token=bb_token)

            items = []
            for c in contents[: max(1, min(limit, 200))]:
                handler_id = (c.get("contentHandler") or {}).get("id", "")
                items.append(
                    {
                        "id": c.get("id"),
                        "title": c.get("title"),
                        "type": _content_type(handler_id),
                        "description": _clean_html(c.get("body", "")),
                        "has_children": c.get("hasChildren", False),
                        "available": (c.get("availability") or {}).get("available") == "Yes",
                    }
                )

            return {
                "success": True,
                "course_id": course_id,
                "folder_id": folder_id,
                "count": len(items),
                "items": items,
                "tip": "Use the 'id' of items with has_children=True as folder_id to browse deeper.",
            }

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e)}

    @mcp.tool()
    async def get_upcoming_assignments(
        days_ahead: int = 14,
        course_id: str = None,
        include_course_names: bool = True,
        limit: int = 50,
    ) -> dict:
        """
        Get upcoming assignments (based on gradebook column due dates).

        Args:
            days_ahead: Look ahead window (default 14 days)
            course_id: If provided, only check this course
            include_course_names: If true, include course name (more API calls)
            limit: Max assignments returned
        """
        try:
            bb_token = await _resolve_bb_token()

            now = datetime.now(timezone.utc)
            end = now + timedelta(days=max(1, min(days_ahead, 120)))

            # Determine which courses to scan
            course_ids = []
            course_name_map = {}

            if course_id:
                course_ids = [course_id]
            else:
                memberships = await bb.get_user_courses(access_token=bb_token)
                course_ids = [
                    m.get("courseId")
                    for m in memberships
                    if m.get("courseId") and (m.get("availability") or {}).get("available") == "Yes"
                ][:25]  # safety cap

            if include_course_names:
                for cid in course_ids:
                    try:
                        c = await bb.get_course_details(cid, access_token=bb_token)
                        course_name_map[cid] = c.get("name", cid)
                    except Exception:
                        course_name_map[cid] = cid

            assignments = []

            for cid in course_ids:
                try:
                    columns = await bb.get_gradebook_columns(cid, access_token=bb_token)
                except Exception:
                    continue

                for col in columns:
                    due = (col.get("grading") or {}).get("due")
                    due_dt = _parse_bb_datetime(due)
                    if not due_dt:
                        continue

                    if now <= due_dt <= end:
                        assignments.append(
                            {
                                "course_id": cid,
                                "course": course_name_map.get(cid, cid) if include_course_names else None,
                                "assignment": col.get("name") or col.get("displayName"),
                                "column_id": col.get("id"),
                                "due_date": due,
                                "points_possible": (col.get("score") or {}).get("possible"),
                                "visible_to_students": (col.get("availability") or {}).get("available") == "Yes",
                            }
                        )

            assignments.sort(key=lambda x: _parse_bb_datetime(x.get("due_date")) or datetime.max.replace(tzinfo=timezone.utc))
            assignments = assignments[: max(1, min(limit, 200))]

            return {"success": True, "count": len(assignments), "assignments": assignments, "window": {"from": now.isoformat(), "to": end.isoformat()}}

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e)}
