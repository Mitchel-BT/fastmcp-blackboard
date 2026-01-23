"""
Instructor/Faculty-focused MCP tools for Blackboard.
These tools are designed for instructors to view rosters, grades, and manage courses.
Includes background tasks for long-running analytics.
With OAuthProxy, authentication is automatic.
"""
import re
from datetime import datetime, timedelta
import httpx
import math

import blackboard_client as bb
from blackboard_client import BlackboardAPIError

from fastmcp.server.dependencies import get_access_token, Progress
from auth import IS_LOCAL_MODE, get_bb_token


async def _resolve_bb_token() -> str:
    if IS_LOCAL_MODE:
        return get_bb_token(None)  # local mode uses stored token :contentReference[oaicite:3]{index=3}
    mcp_access_token = await get_access_token()
    return get_bb_token(mcp_access_token)  # cloud mode uses injected token :contentReference[oaicite:4]{index=4}


# -----------------------------
# Goals API helpers
# -----------------------------

async def _bb_public_get(bb_token: str, path: str, params: dict | None = None, timeout: float = 15.0) -> dict:
    """
    Low-level helper to call Blackboard Public v1 endpoints with bearer token.
    path example: "/goals"
    """
    url = f"{bb.BLACKBOARD_URL}/learn/api/public/v1{path}" if hasattr(bb, "BLACKBOARD_URL") else None
    # Fallback to auth.BLACKBOARD_URL if your client doesn't expose it:
    if not url:
        from auth import BLACKBOARD_URL
        url = f"{BLACKBOARD_URL}/learn/api/public/v1{path}"

    headers = {"Authorization": f"Bearer {bb_token}"}

    async with httpx.AsyncClient() as client:
        r = await client.get(url, headers=headers, params=params or {}, timeout=timeout)

    # Let your existing error handling patterns work:
    if r.status_code == 401:
        raise ValueError("Token expired or invalid. Please re-authenticate.")
    if r.status_code >= 400:
        raise BlackboardAPIError(
            message=f"API error calling {path}: {r.status_code}",
            status_code=r.status_code,
            details=r.text[:2000],
        )

    return r.json() if r.content else {}


async def fetch_goals(
    bb_token: str,
    goal_set_id: str | None = None,
    category_id: str | None = None,
    goal_type: str | None = None,
    max_items: int = 1000,
) -> list[dict]:
    """
    Fetch goals from /goals (optionally filtered).
    Uses offset-based pagination until max_items or no more results.
    """
    goals: list[dict] = []
    offset = 0

    while len(goals) < max_items:
        params = {"offset": offset}
        if goal_set_id:
            params["goalSetId"] = goal_set_id
        if category_id:
            params["categoryId"] = category_id
        if goal_type:
            params["type"] = goal_type

        data = await _bb_public_get(bb_token, "/goals", params=params)

        # Typical Blackboard pattern is {"results":[...]} but be defensive:
        batch = data.get("results")
        if batch is None and isinstance(data, list):
            batch = data
        if not batch:
            break

        goals.extend(batch)

        # If the API returns paging, use it; otherwise increment offset by batch length
        paging = data.get("paging") or {}
        next_offset = paging.get("nextOffset")
        if next_offset is not None:
            offset = next_offset
        else:
            offset += len(batch)

        # Stop if fewer returned than a page-size hint
        if len(batch) < 1:
            break

    return goals[:max_items]


async def fetch_goal_sets(bb_token: str, max_items: int = 200) -> list[dict]:
    """
    Optional helper if your instance supports goal sets listing.
    Endpoint name varies by version; try /goalSets first.
    """
    data = await _bb_public_get(bb_token, "/goalSets", params={"offset": 0})
    results = data.get("results") or []
    return results[:max_items]


# -----------------------------
# Assignment crawl + text normalization
# -----------------------------

def _strip_html(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    return " ".join(text.split())


async def _collect_course_assignments(course_id: str, bb_token: str, max_items: int = 50) -> list[dict]:
    """
    Crawl course contents and return assignment-like items.
    Heuristic: contentHandler id contains "assignment"
    """
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
            body = item.get("body") or item.get("description") or ""
            text = _strip_html(f"{title}\n{body}")

            is_assignment = "assignment" in handler_id.lower()

            if is_assignment:
                results.append({
                    "content_id": item.get("id"),
                    "title": title,
                    "content_handler": handler_id,
                    "text": text,
                    "due_date": (
                        (item.get("grading") or {}).get("due")
                        or (item.get("availability") or {}).get("adaptiveRelease", {}).get("end")
                    ),
                    "raw": item,
                })

            if item.get("hasChildren"):
                await walk(item.get("id"))

    await walk(None)
    return results


# -----------------------------
# Goal recommendation scoring
# -----------------------------

def _tokenize(text: str) -> set[str]:
    if not text:
        return set()
    text = text.lower()
    # keep simple word tokens
    tokens = re.findall(r"[a-z0-9']{3,}", text)
    return set(tokens)


def _goal_text(goal: dict) -> str:
    # Be defensive across payload variants
    parts = [
        str(goal.get("title") or ""),
        str(goal.get("statement") or ""),
        str(goal.get("description") or ""),
        str(goal.get("text") or ""),
    ]
    return _strip_html(" ".join(p for p in parts if p))


def _score_goal_match(assignment_text: str, goal: dict) -> tuple[float, list[str]]:
    """
    Jaccard-ish overlap on token sets, with a small boost for exact phrase hits.
    Returns (score, rationale_tokens)
    """
    a_tokens = _tokenize(assignment_text)
    g_text = _goal_text(goal)
    g_tokens = _tokenize(g_text)

    if not a_tokens or not g_tokens:
        return 0.0, []

    overlap = a_tokens.intersection(g_tokens)
    jacc = len(overlap) / max(1, len(a_tokens.union(g_tokens)))

    # Phrase boost: if a meaningful substring from goal appears in assignment text
    a_low = assignment_text.lower()
    boost = 0.0
    # pick a few “anchor” words from the overlap
    anchors = sorted(list(overlap))[:8]
    for w in anchors:
        if w in a_low:
            boost += 0.01

    score = jacc + boost
    return score, anchors


def register_instructor_tools(mcp):
    """Register all instructor tools with the MCP server"""
    @mcp.tool()
    async def list_goal_sets() -> dict:
        """
        [Instructor/Admin] List available goal sets (if supported by your instance).
        """
        try:
            bb_token = await _resolve_bb_token()
            sets = await fetch_goal_sets(bb_token)
            return {"success": True, "count": len(sets), "goal_sets": sets}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e), "exception_type": type(e).__name__}


    @mcp.tool()
    async def list_goals(goal_set_id: str | None = None, category_id: str | None = None, goal_type: str | None = None, max_items: int = 200) -> dict:
        """
        [Instructor/Admin] List goals from Blackboard Goals API.

        Args:
            goal_set_id: Optional filter
            category_id: Optional filter
            goal_type: Optional filter
            max_items: Max goals to return
        """
        try:
            bb_token = await _resolve_bb_token()
            goals = await fetch_goals(bb_token, goal_set_id=goal_set_id, category_id=category_id, goal_type=goal_type, max_items=max_items)

            # Normalize a tiny preview shape
            normalized = []
            for g in goals:
                normalized.append({
                    "id": g.get("id"),
                    "uid": g.get("uid"),
                    "goalSetId": g.get("goalSetId"),
                    "categoryId": g.get("categoryId"),
                    "type": g.get("type"),
                    "title": g.get("title"),
                    "statement": g.get("statement") or g.get("text") or g.get("description"),
                })

            return {"success": True, "count": len(normalized), "goals": normalized}

        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e), "exception_type": type(e).__name__}


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
        [Instructor] Crawl assignments in a course and recommend Blackboard goals for each.

        Args:
            course_id: Blackboard course id
            goal_set_id: Optional filter to a specific goal set (recommended if you have many goals)
            top_k: How many goals to return per assignment
            max_assignments: Limit assignments scanned
            max_goals: Limit goals fetched
            min_score: Drop weak matches
        """
        try:
            bb_token = await _resolve_bb_token()

            # 1) Fetch assignments
            assignments = await _collect_course_assignments(course_id, bb_token, max_items=max_assignments)

            # 2) Fetch goals live from Blackboard
            goals = await fetch_goals(bb_token, goal_set_id=goal_set_id, max_items=max_goals)

            if not goals:
                return {
                    "success": False,
                    "course_id": course_id,
                    "assignments_scanned": len(assignments),
                    "goals_fetched": 0,
                    "message": "No goals returned from /goals. Check goal_set_id filter or entitlements.",
                }

            # 3) Score + rank
            recommendations = []
            for a in assignments:
                scored = []
                for g in goals:
                    score, anchors = _score_goal_match(a.get("text", ""), g)
                    if score >= min_score:
                        scored.append((score, anchors, g))

                scored.sort(key=lambda x: x[0], reverse=True)
                top = scored[:top_k]

                recs = []
                for score, anchors, g in top:
                    recs.append({
                        "id": g.get("id"),
                        "uid": g.get("uid"),
                        "goalSetId": g.get("goalSetId"),
                        "categoryId": g.get("categoryId"),
                        "type": g.get("type"),
                        "title": g.get("title"),
                        "statement": g.get("statement") or g.get("text") or g.get("description"),
                        "score": round(score, 4),
                        "matched_tokens": anchors,
                    })

                recommendations.append({
                    "assignment": {
                        "content_id": a.get("content_id"),
                        "title": a.get("title"),
                        "due_date": a.get("due_date"),
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
                "tip": "If results look noisy, pass goal_set_id and/or raise min_score (e.g., 0.04).",
            }

        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {"error": "api_error", "message": e.message, "status_code": e.status_code, "details": e.details}
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e), "exception_type": type(e).__name__}


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
