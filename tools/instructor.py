"""
Instructor/Faculty-focused MCP tools for Blackboard.
These tools are designed for instructors to view rosters, grades, and manage courses.
Includes background tasks for long-running analytics.
With OAuthProxy, authentication is automatic.
"""
import re
from datetime import datetime, timedelta
import httpx

import blackboard_client as bb
from blackboard_client import BlackboardAPIError

from fastmcp.server.dependencies import get_access_token, Progress
from auth import IS_LOCAL_MODE, get_bb_token


async def _resolve_bb_token() -> str:
    if IS_LOCAL_MODE:
        return get_bb_token(None)  # local mode uses stored token :contentReference[oaicite:3]{index=3}
    mcp_access_token = await get_access_token()
    return get_bb_token(mcp_access_token)  # cloud mode uses injected token :contentReference[oaicite:4]{index=4}


def register_instructor_tools(mcp):
    """Register all instructor tools with the MCP server"""

    @mcp.tool()
    async def get_course_roster(course_id: str) -> dict:
        try:
            bb_token = await _resolve_bb_token()
            enrollments = await bb.get_course_users(course_id, access_token=bb_token)

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
                    "last_accessed": e.get("lastAccessed"),
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
                "instructors": instructors,
            }

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}

    @mcp.tool()
    async def get_gradebook_overview(course_id: str) -> dict:
        try:
            bb_token = await _resolve_bb_token()
            columns = await bb.get_gradebook_columns(course_id, access_token=bb_token)

            grade_items = []
            for col in columns:
                if col.get("score", {}).get("possible"):
                    grade_items.append({
                        "id": col.get("id"),
                        "name": col.get("name"),
                        "points_possible": col.get("score", {}).get("possible"),
                        "due_date": col.get("grading", {}).get("due"),
                        "type": col.get("grading", {}).get("type"),
                        "visible_to_students": col.get("availability", {}).get("available") == "Yes",
                    })

            return {
                "success": True,
                "course_id": course_id,
                "column_count": len(grade_items),
                "columns": grade_items,
                "tip": "Use get_column_grades with a column ID to see individual student grades",
            }

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}

    @mcp.tool()
    async def get_column_grades(course_id: str, column_id: str) -> dict:
        try:
            bb_token = await _resolve_bb_token()
            grades = await bb.get_column_grades(course_id, column_id, access_token=bb_token)

            enrollments = await bb.get_course_users(course_id, access_token=bb_token)
            user_map = {}
            for e in enrollments:
                user = e.get("user", {})
                user_map[e.get("userId")] = {
                    "name": f"{user.get('name', {}).get('given', '')} {user.get('name', {}).get('family', '')}".strip(),
                    "username": user.get("userName"),
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
                    "graded": g.get("modified"),
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
                "average_score": round(avg, 2) if avg is not None else None,
                "grades": student_grades,
            }

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}

    @mcp.tool()
    async def get_submission_status(course_id: str, column_id: str) -> dict:
        try:
            bb_token = await _resolve_bb_token()
            grades = await bb.get_column_grades(course_id, column_id, access_token=bb_token)
            enrollments = await bb.get_course_users(course_id, access_token=bb_token)

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
                "completion_rate": f"{(submitted/student_count*100):.1f}%" if student_count > 0 else "0%",
            }

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}

    @mcp.tool()
    async def find_inactive_students(course_id: str, days: int = 7) -> dict:
        try:
            bb_token = await _resolve_bb_token()
            enrollments = await bb.get_course_users(course_id, access_token=bb_token)
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
                        "username": user.get("userName"),
                    })
                else:
                    try:
                        access_date = datetime.fromisoformat(last_accessed.replace("Z", "+00:00"))
                        if access_date.replace(tzinfo=None) < cutoff:
                            inactive.append({
                                "name": name,
                                "email": user.get("contact", {}).get("email"),
                                "username": user.get("userName"),
                                "last_accessed": last_accessed,
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
                "inactive_students": inactive,
            }

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}

    # Background task tools follow same pattern: resolve bb_token once and pass it

    @mcp.tool(task=True)
    async def find_struggling_students(course_id: str, grade_threshold: float = 70.0, progress: Progress = Progress()) -> dict:
        try:
            bb_token = await _resolve_bb_token()
            await progress.set_message("Fetching course data...")

            enrollments = await bb.get_course_users(course_id, access_token=bb_token)
            students = {e.get("userId"): e for e in enrollments if e.get("courseRoleId") == "Student"}

            columns = await bb.get_gradebook_columns(course_id, access_token=bb_token)
            graded_columns = [c for c in columns if c.get("score", {}).get("possible")]

            await progress.set_total(len(graded_columns) + 1)

            student_grades = {uid: [] for uid in students.keys()}

            for col in graded_columns:
                await progress.set_message(f"Analyzing: {col.get('name', 'Unknown')[:30]}...")
                try:
                    grades = await bb.get_column_grades(course_id, col["id"], access_token=bb_token)
                    possible = col.get("score", {}).get("possible", 100)

                    for g in grades:
                        uid = g.get("userId")
                        score = g.get("score")
                        if uid in student_grades and score is not None:
                            pct = (score / possible) * 100 if possible > 0 else 0
                            student_grades[uid].append({
                                "assignment": col.get("name"),
                                "percentage": pct,
                                "score": score,
                                "possible": possible,
                            })
                except:
                    pass
                await progress.increment()

            await progress.set_message("Analyzing student performance...")

            struggling = []
            at_risk = []

            for uid, grades in student_grades.items():
                if not grades:
                    continue

                student_info = students[uid]
                user = student_info.get("user", {})
                name = f"{user.get('name', {}).get('given', '')} {user.get('name', {}).get('family', '')}".strip()

                avg = sum(g["percentage"] for g in grades) / len(grades)

                recent = grades[-3:] if len(grades) >= 3 else grades
                declining = False
                if len(recent) >= 2:
                    declining = all(recent[i]["percentage"] > recent[i+1]["percentage"] for i in range(len(recent)-1))

                last_accessed = student_info.get("lastAccessed")
                days_inactive = None
                if last_accessed:
                    try:
                        access_date = datetime.fromisoformat(last_accessed.replace("Z", "+00:00"))
                        days_inactive = (datetime.utcnow() - access_date.replace(tzinfo=None)).days
                    except:
                        pass

                signals = []
                if avg < grade_threshold:
                    signals.append(f"Low average: {avg:.1f}%")
                if declining:
                    signals.append("Declining trend")
                if days_inactive and days_inactive > 7:
                    signals.append(f"Inactive {days_inactive} days")
                if not last_accessed:
                    signals.append("Never accessed course")

                if len(signals) >= 2:
                    struggling.append({
                        "name": name,
                        "email": user.get("contact", {}).get("email"),
                        "average": round(avg, 1),
                        "assignments_graded": len(grades),
                        "signals": signals,
                        "last_accessed": last_accessed,
                    })
                elif len(signals) == 1:
                    at_risk.append({
                        "name": name,
                        "email": user.get("contact", {}).get("email"),
                        "average": round(avg, 1),
                        "signal": signals[0],
                    })

            await progress.increment()

            struggling.sort(key=lambda x: x["average"])
            at_risk.sort(key=lambda x: x["average"])

            return {
                "success": True,
                "course_id": course_id,
                "threshold": grade_threshold,
                "struggling_count": len(struggling),
                "at_risk_count": len(at_risk),
                "struggling_students": struggling,
                "at_risk_students": at_risk,
                "recommendation": f"Consider reaching out to the {len(struggling)} struggling students first.",
            }

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
