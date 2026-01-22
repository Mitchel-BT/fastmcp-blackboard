"""
Instructor/Faculty-focused MCP tools for Blackboard.
These tools are designed for instructors to view rosters, grades, and manage courses.
Includes background tasks for long-running analytics.
"""
import asyncio
import httpx
import re
from datetime import datetime, timedelta

import blackboard_client as bb
from blackboard_client import AuthenticationRequired, BlackboardAPIError
from auth import SERVER_URL
from fastmcp.server.dependencies import Progress


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

    # ==========================================================================
    # BASIC INSTRUCTOR TOOLS (synchronous)
    # ==========================================================================

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

    # ==========================================================================
    # ANALYTICS TOOLS (background tasks)
    # ==========================================================================

    @mcp.tool(task=True)
    async def find_struggling_students(
        access_token: str, 
        course_id: str,
        grade_threshold: float = 70.0,
        progress: Progress = Progress()
    ) -> dict:
        """
        [Instructor] Identify students who may be struggling based on grades and activity.
        Combines low grades + declining trend + low activity signals.
        This runs as a background task with progress updates.
        
        Args:
            access_token: Your personal access token.
            course_id: The course ID to analyze.
            grade_threshold: Score percentage below which a student is flagged (default 70).
        """
        try:
            await progress.set_message("Fetching course data...")
            
            # Get enrollments
            enrollments = await bb.get_course_users(access_token, course_id)
            students = {e.get("userId"): e for e in enrollments if e.get("courseRoleId") == "Student"}
            
            # Get gradebook columns
            columns = await bb.get_gradebook_columns(access_token, course_id)
            graded_columns = [c for c in columns if c.get("score", {}).get("possible")]
            
            await progress.set_total(len(graded_columns) + 1)
            
            # Collect grades for each student
            student_grades = {uid: [] for uid in students.keys()}
            
            for col in graded_columns:
                await progress.set_message(f"Analyzing: {col.get('name', 'Unknown')[:30]}...")
                try:
                    grades = await bb.get_column_grades(access_token, course_id, col["id"])
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
                                "possible": possible
                            })
                except:
                    pass
                await progress.increment()
            
            await progress.set_message("Analyzing student performance...")
            
            # Analyze each student
            struggling = []
            at_risk = []
            
            for uid, grades in student_grades.items():
                if not grades:
                    continue
                    
                student_info = students[uid]
                user = student_info.get("user", {})
                name = f"{user.get('name', {}).get('given', '')} {user.get('name', {}).get('family', '')}".strip()
                
                # Calculate average
                avg = sum(g["percentage"] for g in grades) / len(grades)
                
                # Check for declining trend (last 3 assignments)
                recent = grades[-3:] if len(grades) >= 3 else grades
                declining = False
                if len(recent) >= 2:
                    declining = all(recent[i]["percentage"] > recent[i+1]["percentage"] for i in range(len(recent)-1))
                
                # Check activity
                last_accessed = student_info.get("lastAccessed")
                days_inactive = None
                if last_accessed:
                    try:
                        access_date = datetime.fromisoformat(last_accessed.replace("Z", "+00:00"))
                        days_inactive = (datetime.utcnow() - access_date.replace(tzinfo=None)).days
                    except:
                        pass
                
                # Categorize
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
                        "last_accessed": last_accessed
                    })
                elif len(signals) == 1:
                    at_risk.append({
                        "name": name,
                        "email": user.get("contact", {}).get("email"),
                        "average": round(avg, 1),
                        "signal": signals[0]
                    })
            
            await progress.increment()
            
            # Sort by average grade (lowest first)
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
                "recommendation": f"Consider reaching out to the {len(struggling)} struggling students first."
            }
            
        except AuthenticationRequired:
            return _auth_error_response()
        except BlackboardAPIError as e:
            return _api_error_response(e)

    @mcp.tool(task=True)
    async def find_problem_assignments(
        access_token: str,
        course_id: str,
        threshold: float = 70.0,
        progress: Progress = Progress()
    ) -> dict:
        """
        [Instructor] Find assignments where students performed unusually poorly.
        Flags assignments with low class averages or high failure rates.
        This runs as a background task with progress updates.
        
        Args:
            access_token: Your personal access token.
            course_id: The course ID to analyze.
            threshold: Average percentage below which an assignment is flagged (default 70).
        """
        try:
            await progress.set_message("Fetching gradebook...")
            
            columns = await bb.get_gradebook_columns(access_token, course_id)
            graded_columns = [c for c in columns if c.get("score", {}).get("possible")]
            
            await progress.set_total(len(graded_columns))
            
            assignment_stats = []
            
            for col in graded_columns:
                await progress.set_message(f"Analyzing: {col.get('name', 'Unknown')[:30]}...")
                
                try:
                    grades = await bb.get_column_grades(access_token, course_id, col["id"])
                    possible = col.get("score", {}).get("possible", 100)
                    
                    scores = []
                    below_threshold = 0
                    
                    for g in grades:
                        score = g.get("score")
                        if score is not None:
                            pct = (score / possible) * 100 if possible > 0 else 0
                            scores.append(pct)
                            if pct < threshold:
                                below_threshold += 1
                    
                    if scores:
                        avg = sum(scores) / len(scores)
                        sorted_scores = sorted(scores)
                        median = sorted_scores[len(sorted_scores) // 2]
                        
                        assignment_stats.append({
                            "id": col.get("id"),
                            "name": col.get("name"),
                            "average": round(avg, 1),
                            "median": round(median, 1),
                            "min": round(min(scores), 1),
                            "max": round(max(scores), 1),
                            "graded_count": len(scores),
                            "below_threshold": below_threshold,
                            "failure_rate": round((below_threshold / len(scores)) * 100, 1)
                        })
                except:
                    pass
                
                await progress.increment()
            
            # Identify problem assignments
            problems = []
            watch_list = []
            
            for a in assignment_stats:
                issues = []
                if a["average"] < threshold:
                    issues.append(f"Low average: {a['average']}%")
                if a["failure_rate"] > 40:
                    issues.append(f"High failure rate: {a['failure_rate']}%")
                if a["median"] < threshold:
                    issues.append(f"Low median: {a['median']}%")
                
                if len(issues) >= 2:
                    a["issues"] = issues
                    problems.append(a)
                elif len(issues) == 1:
                    a["issue"] = issues[0]
                    watch_list.append(a)
            
            # Sort by average (lowest first)
            problems.sort(key=lambda x: x["average"])
            watch_list.sort(key=lambda x: x["average"])
            
            # Calculate overall stats
            all_avgs = [a["average"] for a in assignment_stats]
            course_avg = sum(all_avgs) / len(all_avgs) if all_avgs else 0
            
            return {
                "success": True,
                "course_id": course_id,
                "threshold": threshold,
                "course_average": round(course_avg, 1),
                "total_assignments": len(assignment_stats),
                "problem_count": len(problems),
                "watch_list_count": len(watch_list),
                "problem_assignments": problems,
                "watch_list": watch_list,
                "all_assignments": sorted(assignment_stats, key=lambda x: x["average"])
            }
            
        except AuthenticationRequired:
            return _auth_error_response()
        except BlackboardAPIError as e:
            return _api_error_response(e)

    @mcp.tool(task=True)
    async def check_course_links(
        access_token: str,
        course_id: str,
        timeout_seconds: int = 10,
        progress: Progress = Progress()
    ) -> dict:
        """
        [Instructor] Check all external links in a course for broken URLs.
        Crawls course content and validates each link.
        This runs as a background task with progress updates.
        
        Args:
            access_token: Your personal access token.
            course_id: The course ID to check.
            timeout_seconds: Timeout for each link check (default 10).
        """
        try:
            await progress.set_message("Scanning course content for links...")
            
            # Get all content recursively
            all_links = []
            
            async def scan_content(folder_id=None):
                try:
                    if folder_id:
                        contents = await bb.get_content_children(access_token, course_id, folder_id)
                    else:
                        contents = await bb.get_course_contents(access_token, course_id)
                    
                    for item in contents:
                        # Check for external link content type
                        handler = item.get("contentHandler", {})
                        if handler.get("id") == "resource/x-bb-externallink":
                            url = handler.get("url")
                            if url:
                                all_links.append({
                                    "title": item.get("title"),
                                    "url": url,
                                    "location": item.get("id")
                                })
                        
                        # Extract links from body HTML
                        body = item.get("body", "")
                        if body:
                            urls = re.findall(r'href=[\'"]?(https?://[^\'" >]+)', body)
                            for url in urls:
                                all_links.append({
                                    "title": f"Link in: {item.get('title', 'Unknown')}",
                                    "url": url,
                                    "location": item.get("id")
                                })
                        
                        # Recurse into folders
                        if item.get("hasChildren"):
                            await scan_content(item.get("id"))
                except:
                    pass
            
            await scan_content()
            
            if not all_links:
                return {
                    "success": True,
                    "course_id": course_id,
                    "message": "No external links found in course content",
                    "total_links": 0
                }
            
            # Deduplicate by URL
            unique_links = {}
            for link in all_links:
                if link["url"] not in unique_links:
                    unique_links[link["url"]] = link
            
            links_to_check = list(unique_links.values())
            await progress.set_total(len(links_to_check))
            await progress.set_message(f"Checking {len(links_to_check)} unique links...")
            
            # Check each link
            broken = []
            valid = []
            skipped = []
            
            # Domains that require auth (skip these)
            auth_domains = ["doi.org", "jstor.org", "springer.com", "wiley.com", 
                          "sciencedirect.com", "tandfonline.com", "library.", "proxy."]
            
            async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=True) as client:
                for link in links_to_check:
                    url = link["url"]
                    await progress.set_message(f"Checking: {url[:50]}...")
                    
                    # Skip known auth-required domains
                    if any(domain in url.lower() for domain in auth_domains):
                        skipped.append({**link, "reason": "Requires authentication"})
                        await progress.increment()
                        continue
                    
                    try:
                        response = await client.head(url)
                        if response.status_code < 400:
                            valid.append({**link, "status": response.status_code})
                        else:
                            # Try GET as some servers don't support HEAD
                            response = await client.get(url)
                            if response.status_code < 400:
                                valid.append({**link, "status": response.status_code})
                            else:
                                broken.append({**link, "status": response.status_code, "error": f"HTTP {response.status_code}"})
                    except httpx.TimeoutException:
                        broken.append({**link, "status": None, "error": "Timeout"})
                    except Exception as e:
                        broken.append({**link, "status": None, "error": str(e)[:50]})
                    
                    await progress.increment()
            
            return {
                "success": True,
                "course_id": course_id,
                "total_links": len(links_to_check),
                "valid_count": len(valid),
                "broken_count": len(broken),
                "skipped_count": len(skipped),
                "broken_links": broken,
                "skipped_links": skipped,
                "recommendation": f"Found {len(broken)} broken links that need attention." if broken else "All links are working!"
            }
            
        except AuthenticationRequired:
            return _auth_error_response()
        except BlackboardAPIError as e:
            return _api_error_response(e)

    @mcp.tool(task=True)
    async def get_course_health_summary(
        access_token: str,
        course_id: str,
        progress: Progress = Progress()
    ) -> dict:
        """
        [Instructor] Get a comprehensive health summary of a course.
        One-call overview: engagement, grades, at-risk students, problem areas.
        This runs as a background task with progress updates.
        
        Args:
            access_token: Your personal access token.
            course_id: The course ID to analyze.
        """
        try:
            await progress.set_total(5)
            
            # 1. Get course info
            await progress.set_message("Fetching course info...")
            course = await bb.get_course_details(access_token, course_id)
            await progress.increment()
            
            # 2. Get enrollments
            await progress.set_message("Analyzing enrollment...")
            enrollments = await bb.get_course_users(access_token, course_id)
            students = [e for e in enrollments if e.get("courseRoleId") == "Student"]
            
            # Activity analysis
            now = datetime.utcnow()
            active_7d = 0
            active_30d = 0
            never_accessed = 0
            
            for s in students:
                last = s.get("lastAccessed")
                if not last:
                    never_accessed += 1
                else:
                    try:
                        access_date = datetime.fromisoformat(last.replace("Z", "+00:00")).replace(tzinfo=None)
                        days_ago = (now - access_date).days
                        if days_ago <= 7:
                            active_7d += 1
                        if days_ago <= 30:
                            active_30d += 1
                    except:
                        pass
            
            await progress.increment()
            
            # 3. Grade analysis
            await progress.set_message("Analyzing grades...")
            columns = await bb.get_gradebook_columns(access_token, course_id)
            graded_columns = [c for c in columns if c.get("score", {}).get("possible")]
            
            assignment_avgs = []
            student_avgs = {}
            
            for col in graded_columns[:10]:  # Limit to avoid too many API calls
                try:
                    grades = await bb.get_column_grades(access_token, course_id, col["id"])
                    possible = col.get("score", {}).get("possible", 100)
                    
                    scores = []
                    for g in grades:
                        score = g.get("score")
                        if score is not None:
                            pct = (score / possible) * 100
                            scores.append(pct)
                            uid = g.get("userId")
                            if uid not in student_avgs:
                                student_avgs[uid] = []
                            student_avgs[uid].append(pct)
                    
                    if scores:
                        assignment_avgs.append({
                            "name": col.get("name"),
                            "average": sum(scores) / len(scores)
                        })
                except:
                    pass
            
            await progress.increment()
            
            # 4. Calculate student performance tiers
            await progress.set_message("Categorizing students...")
            
            a_tier = 0  # 90+
            b_tier = 0  # 80-89
            c_tier = 0  # 70-79
            d_tier = 0  # 60-69
            f_tier = 0  # <60
            
            for uid, grades in student_avgs.items():
                if grades:
                    avg = sum(grades) / len(grades)
                    if avg >= 90:
                        a_tier += 1
                    elif avg >= 80:
                        b_tier += 1
                    elif avg >= 70:
                        c_tier += 1
                    elif avg >= 60:
                        d_tier += 1
                    else:
                        f_tier += 1
            
            await progress.increment()
            
            # 5. Identify problem areas
            await progress.set_message("Identifying issues...")
            
            issues = []
            if never_accessed > 0:
                issues.append(f"{never_accessed} student(s) have never accessed the course")
            if len(students) > 0 and (active_7d / len(students)) < 0.5:
                issues.append(f"Low engagement: only {active_7d}/{len(students)} active in past 7 days")
            if f_tier > len(students) * 0.2:
                issues.append(f"High failure rate: {f_tier} students below 60%")
            
            low_avg_assignments = [a for a in assignment_avgs if a["average"] < 70]
            if low_avg_assignments:
                issues.append(f"{len(low_avg_assignments)} assignment(s) with average below 70%")
            
            await progress.increment()
            
            # Calculate overall course average
            all_avgs = [a["average"] for a in assignment_avgs]
            course_avg = sum(all_avgs) / len(all_avgs) if all_avgs else None
            
            return {
                "success": True,
                "course": {
                    "id": course_id,
                    "name": course.get("name"),
                },
                "enrollment": {
                    "total_students": len(students),
                    "active_7_days": active_7d,
                    "active_30_days": active_30d,
                    "never_accessed": never_accessed,
                    "engagement_rate": f"{(active_7d/len(students)*100):.0f}%" if students else "N/A"
                },
                "grades": {
                    "course_average": round(course_avg, 1) if course_avg else None,
                    "assignments_analyzed": len(assignment_avgs),
                    "grade_distribution": {
                        "A (90+)": a_tier,
                        "B (80-89)": b_tier,
                        "C (70-79)": c_tier,
                        "D (60-69)": d_tier,
                        "F (<60)": f_tier
                    }
                },
                "health_score": _calculate_health_score(active_7d, len(students), course_avg, f_tier, never_accessed),
                "issues": issues if issues else ["No major issues detected"],
                "recommendation": issues[0] if issues else "Course appears healthy!"
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


def _calculate_health_score(active_7d, total_students, course_avg, failing_count, never_accessed):
    """Calculate a simple health score 0-100"""
    if total_students == 0:
        return None
    
    score = 100
    
    # Engagement penalty (up to 30 points)
    engagement_rate = active_7d / total_students
    if engagement_rate < 0.8:
        score -= (0.8 - engagement_rate) * 37.5  # Max 30 point penalty
    
    # Grade penalty (up to 30 points)
    if course_avg:
        if course_avg < 80:
            score -= (80 - course_avg) * 1.5  # Max 30 point penalty
    
    # Failing students penalty (up to 20 points)
    failing_rate = failing_count / total_students
    if failing_rate > 0.1:
        score -= (failing_rate - 0.1) * 50  # Max ~20 point penalty
    
    # Never accessed penalty (up to 20 points)
    never_rate = never_accessed / total_students
    if never_rate > 0:
        score -= never_rate * 40  # Max 20 point penalty
    
    return max(0, min(100, round(score)))
