"""
Blackboard MCP Tools

Tools are organized by user role:
- common.py: Shared tools (auth, profile)
- student.py: Student-focused tools (grades, content, announcements)
- instructor.py: Instructor-focused tools (roster, grading, analytics)
"""
from .common import register_common_tools
from .student import register_student_tools
from .instructor import register_instructor_tools

__all__ = [
    "register_common_tools",
    "register_student_tools",
    "register_instructor_tools"
]
