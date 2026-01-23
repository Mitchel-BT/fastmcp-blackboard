"""
Instructor/Faculty-focused MCP tools for Blackboard.

- Works in LOCAL mode (token stored by browser OAuth in auth.py)
- Works in CLOUD mode (OAuthProxy -> MCP access token -> auth.get_bb_token(access_token))

IMPORTANT:
- Avoids Depends() entirely to prevent import/version issues with fastmcp.
- Passes bb_token explicitly into blackboard_client calls.

Includes:
- Existing roster/gradebook tools
- Goals endpoint tools + assignment->goal recommendation
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, Optional

import httpx

import blackboard_client as bb
from blackboard_client import BlackboardAPIError
from auth import IS_LOCAL_MODE, BLACKBOARD_URL, get_bb_token

# NOTE: we import get_access_token but DO NOT use Depends
from fastmcp.server.dependencies import Progress, get_access_token


# =============================================================================
# TOKEN HELPERS (NO Depends)
# =============================================================================

async def _maybe_await(x):
    """Await x if it's awaitable, otherwise return it."""
    try:
        import inspect
        if inspect.isawaitable(x):
            return await x
    except Exception:
        pass
    return x


async def _get_mcp_access_token() -> Optional[str]:
    """
    In cloud mode, FastMCP provides an access token accessor.
    Depending on fastmcp version, get_access_token might be sync or async.
    """
    try:
        token = get_access_token()
        token = await _maybe_await(token)
        if isinstance(token, str) and token:
            return token
    except Exception:
        return None
    return None


async def _resolve_bb_token() -> str:
    """
    Resolve a usable Blackboard bearer token in both modes.
    - LOCAL: auth.get_bb_token() returns the locally stored token
    - CLOUD: fetch MCP access token then auth.get_bb_token(mcp_token)
    """
    if IS_LOCAL_MODE:
        return get_bb_token()

    mcp_token = await _get_mcp_access_token()
    return get_bb_token(mcp_token)


# =============================================================================
# SMALL TEXT HELPERS
# =============================================================================

def _safe_text(x) -> str:
    return x if isinstance(x, str) else ""


def _strip_html(text: str) -> str:
    if not text:
        return ""
    return re.sub(r"<[^>]+>", " ", text).replace("\n", " ").strip()


def _tokenize(text: str) -> set[str]:
    text = (text or "").lower()
    # words + basic stemming-ish
    words = re.findall(r"[a-z0-9]+", text)
    out = set()
    for w in words:
        if len(w) <= 2:
            continue
        if w.endswith("ing") and len(w) > 5:
            out.add(w[:-3])
        if w.endswith("ed") and len(w) > 4:
            out.add(w[:-2])
        if w.endswith("s") and len(w) > 4:
            out.add(w[:-1])
        out.add(w)
    return out


def _goal_text(goal: dict) -> str:
    # Defensive: goal payload fields can vary by version
    title = _safe_text(goal.get("title"))
    stmt = _safe_text(goal.get("statement")) or _safe_text(goal.get("text")) or _safe_text(goal.get("description"))
    return _strip_html(f"{title}\n{stmt}")


def _score_goal_match(assignment_text: str, goal: dict) -> tuple[float, list[str]]:
    """
    Very lightweight lexical match.
    score = overlap / assignment_tokens (biased toward matches that explain assignment text)
    """
    a_tokens = _tokenize(assignment_text)
    if not a_tokens:
        return 0.0, []

    g_tokens = _tokenize(_goal_text(goal))
    if not g_tokens:
        return 0.0, []

    overlap = a_tokens.intersection(g_tokens)
    if not overlap:
        return 0.0, []

    score = len(overlap) / max(12, len(a_tokens))
    anchors = sorted(list(overlap))[:12]
    return score, anchors


# =============================================================================
# RAW PUBLIC API GET (FOR GOALS ENDPOINT)
# =============================================================================

async def _bb_public_get(bb_token: str, path: str, params: dict | None = None, timeout: float = 30.0) -> dict:
    """
    GET against Blackboard public v1 endpoints (path should start with '/learn/api/public/v1/...').
    """
    url = f"{BLACKBOARD_URL.rstrip('/')}{path}"
    headers = {"Authorization": f"Bearer {bb_token}"}

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.get(url, headers=headers, params=params or {})
        if r.status_code == 401:
            raise ValueError("Not authenticated or token expired (401).")
        if r.status_code >= 400:
            raise BlackboardAPIError(
                message=f"API error: {r.status_code}",
                status_code=r.status_code,
                details=r.text[:2000],
            )
        return r.json() if r.content else {}


async def fetch_goal_sets(bb_token: str, max_items: int = 200) -> list[dict]:
    """
    There is a Goal Sets endpoint in some versions. If your instance doesn't support it,
    you can just use list_goals and group by goalSetId.
    """
    # If your API supports it, uncomment and adjust path:
    # data = await _bb_public_get(bb_token, "/learn/api/public/v1/goalSets", params={"limit": max_items})
    # return data.get("results", []) if isinstance(data, dict) else []
    return []


async def fetch_goals(
    bb_token: str,
    goal_set_id: str | None = None,
    category_id: str | None = None,
    goal_type: str | None = None,
    max_items: int = 800,
) -> list[dict]:
    params: dict[str, Any] = {"offset": 0, "limit": 200, "includePermissions": "true"}
    if goal_set_id:
        params["goalSetId"] = goal_set_id
    if category_id:
        params["categoryId"] = category_id
    if goal_type:
        params["type"] = goal_type

    out: list[dict] = []
    offset = 0

    while len(out) < max_items:
        params["offset"] = offset
        data = await _bb_public_get(bb_token, "/learn/api/public/v1/goals", params=params)

        results = data.get("results", []) if isinstance(data, dict) else []
        if not results:
            break

        out.extend(results)
        if len(results) < params["limit"]:
            break

        offset += params["limit"]

    return out[:max_items]


# =============================================================================
# ASSIGNMENT CANDIDATES (CONTENT + GRADEBOOK)
# =============================================================================

async def _collect_gradebook_assignments(course_id: str, bb_token: str, max_items: int = 50) -> list[dict]:
    cols = await bb.get_gradebook_columns(course_id, access_token=bb_token)
    results: list[dict] = []

    for col in cols or []:
        if len(results) >= max_items:
            break

        possible = (col.get("score") or {}).get("possible")
        if possible is None:
            continue

        name = col.get("name") or ""
        desc = _safe_text(col.get("description")) or _safe_text((col.get("grading") or {}).get("instructions"))
        due = (col.get("grading") or {}).get("due")

        text = _strip_html(f"{name}\n{desc}")
        results.append({
            "source": "gradebook",
            "column_id": col.get("id"),
            "title": name,
            "due_date": due,
            "text": text,
            "raw": col,
        })

    return results


async def _collect_content_assignments(course_id: str, bb_token: str, max_items: int = 50) -> list[dict]:
    results: list[dict] = []

    async def walk(folder_id: str | None = None):
        nonlocal results
        if len(results) >= max_items:
            return

        if folder_id:
            items = await bb.get_content_children(course_id, folder_id, access_token=bb_token)
        else:
            items = await bb.get_course_contents(course_id, access_token=bb_token)

        for item in items or []:
            if len(results) >= max_items:
                return

            handler_id = (item.get("contentHandler") or {}).get("id", "") or ""
            title = item.get("title") or item.get("name") or ""
            body = _safe_text(item.get("body")) or _safe_text(item.get("description"))
            text = _strip_html(f"{title}\n{body}")

            hid = handler_id.lower()
            is_assignmentish = (
                "assignment" in hid
                or "assessment" in hid
                or "test" in hid
                or "quiz" in hid
            )

            if is_assignmentish:
                due_date = (item.get("grading") or {}).get("due") \
                           or (item.get("availability") or {}).get("adaptiveRelease", {}).get("end")

                results.append({
                    "source": "content",
                    "content_id": item.get("id"),
                    "title": title,
                    "content_handler": handler_id,
                    "due_date": due_date,
                    "text": text,
                    "raw": item,
                })

            if item.get("hasChildren"):
                await walk(item.get("id"))

    await walk(None)
    return results


# =============================================================================
# EXISTING INSTRUCTOR TOOLS + NEW GOALS TOOLS
# =============================================================================

def register_instructor_tools(mcp):
    """Register all instructor tools with the MCP server"""

    # -------------------------------------------------------------------------
    # Goals tools
    # -------------------------------------------------------------------------

    @mcp.tool()
    async def list_goal_sets() -> dict:
        """
        [Instructor] List goal sets (if supported) or return empty.
        """
        try:
            bb_token = await _resolve_bb_token()
            sets = await fetch_goal_sets(bb_token)
            return {"success": True, "count": len(sets), "goal_sets": sets}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    async def list_goals(goal_set_id: str | None = None, category_id: str | None = None, goal_type: str | None = None, max_items: int = 200) -> dict:
        """
        [Instructor] List goals from GET /learn/api/public/v1/goals.
        """
        try:
            bb_token = await _resolve_bb_token()
            goals = await fetch_goals(bb_token, goal_set_id=goal_set_id, category_id=category_id, goal_type=goal_type, max_items=max_items)
            return {"success": True, "count": len(goals), "goals": goals}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    async def debug_assignment_candidates(course_id: str, max_items: int = 50) -> dict:
        """
        [Instructor] Debug what the server considers "assignment candidates"
        from BOTH course content and gradebook.
        """
        try:
            bb_token = await _resolve_bb_token()
            content_items = await _collect_content_assignments(course_id, bb_token, max_items=max_items)
            gradebook_items = await _collect_gradebook_assignments(course_id, bb_token, max_items=max_items)

            return {
                "success": True,
                "course_id": course_id,
                "content_assignment_count": len(content_items),
                "gradebook_assignment_count": len(gradebook_items),
                "content_sample_titles": [x.get("title") for x in content_items[:10]],
                "gradebook_sample_titles": [x.get("title") for x in gradebook_items[:10]],
                "note": "If gradebook count is 0, items may not be gradable columns. If content count is 0, your contentHandler IDs may differ."
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    async def recommend_goals_for_course_assignments(
        course_id: str,
        goal_set_id: str | None = None,
        top_k: int = 5,
        max_assignments: int = 25,
        max_goals: int = 800,
        min_score: float = 0.02,
    ) -> dict:
        """
        [Instructor] Scan a course (content + gradebook) and recommend goals for each assignment candidate.

        Note:
        - Does NOT require due dates.
        - Pulls goals live via GET /learn/api/public/v1/goals.
        """
        try:
            bb_token = await _resolve_bb_token()

            content_items = await _collect_content_assignments(course_id, bb_token, max_items=max_assignments)
            gradebook_items = await _collect_gradebook_assignments(course_id, bb_token, max_items=max_assignments)

            # Merge + naive dedupe
            seen = set()
            assignments: list[dict] = []
            for a in (gradebook_items + content_items):
                key = (a.get("source"), (a.get("title") or "").strip().lower())
                if key in seen:
                    continue
                seen.add(key)
                assignments.append(a)

            if not assignments:
                return {
                    "success": False,
                    "course_id": course_id,
                    "message": "No assignment candidates found in content or gradebook.",
                    "tip": "Run debug_assignment_candidates(course_id) to see what Blackboard is returning."
                }

            goals = await fetch_goals(bb_token, goal_set_id=goal_set_id, max_items=max_goals)
            if not goals:
                return {
                    "success": False,
                    "course_id": course_id,
                    "assignments_scanned": len(assignments),
                    "goals_fetched": 0,
                    "message": "No goals returned from /goals. Check entitlement system.learningstandards.VIEW and/or goal_set_id filter."
                }

            recommendations = []
            for a in assignments:
                a_text = a.get("text", "")
                scored = []
                for g in goals:
                    score, anchors = _score_goal_match(a_text, g)
                    if score >= min_score:
                        scored.append((score, anchors, g))
                scored.sort(key=lambda x: x[0], reverse=True)

                top = scored[:top_k]
                recs = [{
                    "id": g.get("id"),
                    "uid": g.get("uid"),
                    "goalSetId": g.get("goalSetId"),
                    "categoryId": g.get("categoryId"),
                    "type": g.get("type"),
                    "title": g.get("title"),
                    "statement": g.get("statement") or g.get("text") or g.get("description"),
                    "score": round(score, 4),
                    "matched_tokens": anchors,
                } for score, anchors, g in top]

                recommendations.append({
                    "assignment": {
                        "source": a.get("source"),
                        "title": a.get("title"),
                        "due_date": a.get("due_date"),
                        "content_id": a.get("content_id"),
                        "column_id": a.get("column_id"),
                        "content_handler": a.get("content_handler"),
                    },
                    "recommended_goals": recs,
                })

            return {
                "success": True,
                "course_id": course_id,
                "goal_set_id": goal_set_id,
                "assignments_scanned": len(assignments),
                "goals_fetched": len(goals),
                "top_k": top_k,
                "min_score": min_score,
                "recommendations": recommendations,
                "tip": "If recommendations are empty, lower min_score (e.g., 0.005) or ensure assignment text shares vocabulary with goal statements."
            }

        except ValueError as e:
            return {"success": False, "error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"success": False, "error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"success": False, "error": "unexpected_error", "message": str(e)}

    # -------------------------------------------------------------------------
    # Your existing instructor tools (updated to pass bb_token correctly)
    # -------------------------------------------------------------------------

    @mcp.tool()
    async def get_course_roster(course_id: str) -> dict:
        """
        [Instructor] Get the full roster of students enrolled in a course.
        """
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
        """
        [Instructor] Get an overview of the gradebook for a course.
        """
        try:
            bb_token = await _resolve_bb_token()
            columns = await bb.get_gradebook_columns(course_id, access_token=bb_token)

            grade_items = []
            for col in columns:
                if (col.get("score") or {}).get("possible") is not None:
                    grade_items.append({
                        "id": col.get("id"),
                        "name": col.get("name"),
                        "points_possible": (col.get("score") or {}).get("possible"),
                        "due_date": (col.get("grading") or {}).get("due"),
                        "type": (col.get("grading") or {}).get("type"),
                        "visible_to_students": (col.get("availability") or {}).get("available") == "Yes",
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
        """
        [Instructor] Get all student grades for a specific assignment/column.
        """
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
        """
        [Instructor] Get a quick summary of submission status for an assignment.
        """
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
        """
        [Instructor] Find students who haven't accessed the course recently.
        """
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
                        access_date = datetime.fromisoformat(last_accessed.replace("Z", "+00:00")).replace(tzinfo=None)
                        if access_date < cutoff:
                            inactive.append({
                                "name": name,
                                "email": user.get("contact", {}).get("email"),
                                "username": user.get("userName"),
                                "last_accessed": last_accessed,
                            })
                    except Exception:
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

    # -------------------------------------------------------------------------
    # Background tasks (kept, but token usage corrected)
    # -------------------------------------------------------------------------

    @mcp.tool(task=True)
    async def find_struggling_students(course_id: str, grade_threshold: float = 70.0, progress: Progress = Progress()) -> dict:
        """
        [Instructor] Identify students who may be struggling based on grades and activity.
        """
        try:
            bb_token = await _resolve_bb_token()
            await progress.set_message("Fetching course data...")

            enrollments = await bb.get_course_users(course_id, access_token=bb_token)
            students = {e.get("userId"): e for e in enrollments if e.get("courseRoleId") == "Student"}

            columns = await bb.get_gradebook_columns(course_id, access_token=bb_token)
            graded_columns = [c for c in columns if (c.get("score") or {}).get("possible") is not None]

            await progress.set_total(len(graded_columns) + 1)

            student_grades = {uid: [] for uid in students.keys()}

            for col in graded_columns:
                await progress.set_message(f"Analyzing: {(_safe_text(col.get('name'))[:30] or 'Unknown')}...")
                try:
                    grades = await bb.get_column_grades(course_id, col["id"], access_token=bb_token)
                    possible = (col.get("score") or {}).get("possible", 100)

                    for g in grades:
                        uid = g.get("userId")
                        score = g.get("score")
                        if uid in student_grades and score is not None:
                            pct = (score / possible) * 100 if possible else 0
                            student_grades[uid].append({
                                "assignment": col.get("name"),
                                "percentage": pct,
                                "score": score,
                                "possible": possible,
                            })
                except Exception:
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
                    declining = all(recent[i]["percentage"] > recent[i + 1]["percentage"] for i in range(len(recent) - 1))

                last_accessed = student_info.get("lastAccessed")
                days_inactive = None
                if last_accessed:
                    try:
                        access_date = datetime.fromisoformat(last_accessed.replace("Z", "+00:00")).replace(tzinfo=None)
                        days_inactive = (datetime.utcnow() - access_date).days
                    except Exception:
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
                "recommendation": f"Consider reaching out to the {len(struggling)} struggling students first." if struggling else "No major issues detected.",
            }

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}


# =============================================================================
# Friendly helpers (kept from your original)
# =============================================================================

def _friendly_role(role_id: str) -> str:
    roles = {
        "Student": "Student",
        "Instructor": "Instructor",
        "TeachingAssistant": "Teaching Assistant",
        "CourseBuilder": "Course Builder",
        "Grader": "Grader",
        "Guest": "Guest",
    }
    return roles.get(role_id, role_id)
