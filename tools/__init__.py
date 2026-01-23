"""
Blackboard MCP Tools

Tools are organized by user role:
- common.py: Shared tools (profile, connection check)
- student.py: Student-focused tools (grades, content, announcements)
- instructor.py: Instructor-focused tools (roster, grading, analytics)
- testing.py: Debug/testing tools (whoami, test connection)

With OAuthProxy, authentication is automatic when users connect through Claude.
No more access_token parameters needed!
"""
from .common import register_common_tools
from .student import register_student_tools
from .instructor import register_instructor_tools
from .testing import register_testing_tools

__all__ = [
    "register_testing_tools",
]
