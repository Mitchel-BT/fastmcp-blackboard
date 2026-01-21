# Blackboard MCP Server

A Model Context Protocol (MCP) server that connects Claude to Blackboard Learn, enabling students and instructors to interact with their courses, grades, and content through natural conversation.

![MCP](https://img.shields.io/badge/MCP-Compatible-blue)
![FastMCP](https://img.shields.io/badge/FastMCP-Cloud-purple)
![License](https://img.shields.io/badge/License-All%20Rights%20Reserved-red)

## Features

### For Students
- 📚 **View Courses** - See all enrolled courses with names and roles
- 📊 **Check Grades** - View grades with scores, percentages, and feedback
- 📢 **Read Announcements** - Stay up to date with course announcements
- 📁 **Browse Content** - Navigate course materials, folders, and files

### For Instructors
- 👥 **Course Roster** - View enrolled students with contact info
- 📝 **Gradebook Overview** - See all assignments and due dates
- ✅ **Submission Status** - Quick view of who's submitted, who needs grading
- 📈 **Grade Analysis** - View individual grades with class averages

## Quick Start

### 1. Add the MCP Server to Claude

Add the Blackboard connector in Claude's settings, or configure it in Claude Desktop.

### 2. Authenticate

Ask Claude to connect to Blackboard:

> "Connect me to Blackboard"

Claude will provide an authentication link. Click it, log in with your Blackboard credentials, then copy the message shown and paste it back to Claude.

### 3. Start Using It

Once authenticated, just ask naturally:

> "What courses am I enrolled in?"

> "Show me my grades for Biology 101"

> "What assignments are due this week?"

> "Show me the roster for my CS 201 class"

## Available Tools

| Tool | Who | Description |
|------|-----|-------------|
| `get_auth_link` | Everyone | Get authentication URL |
| `check_token_status` | Everyone | Verify your session is active |
| `get_my_profile` | Everyone | View your Blackboard profile |
| `get_my_courses` | Everyone | List enrolled courses |
| `get_my_grades` | Student | View grades for a course |
| `get_course_announcements` | Everyone | Read course announcements |
| `get_course_content` | Everyone | Browse course materials |
| `get_course_roster` | Instructor | View student roster |
| `get_gradebook_overview` | Instructor | See all grade columns |
| `get_column_grades` | Instructor | View grades for an assignment |
| `get_submission_status` | Instructor | Submission/grading summary |

## Project Structure

```
blackboard-mcp/
├── server.py              # MCP server entry point
├── auth.py                # OAuth & token management
├── blackboard_client.py   # Blackboard API client
├── templates.py           # HTML templates for auth pages
└── tools/
    ├── __init__.py
    ├── common.py          # Shared tools
    ├── student.py         # Student-focused tools
    └── instructor.py      # Instructor-focused tools
```

## Self-Hosting

### Prerequisites

- Python 3.10+
- A Blackboard Learn instance with REST API enabled
- A registered application on [Anthology Developer Portal](https://developer.anthology.com)

### Environment Variables

```bash
BLACKBOARD_URL=https://your-institution.blackboard.com
BLACKBOARD_APP_KEY=your-application-key
BLACKBOARD_APP_SECRET=your-application-secret
SERVER_URL=https://your-server-url.com
```

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/blackboard-mcp.git
cd blackboard-mcp

# Install dependencies
pip install fastmcp httpx

# Run locally
fastmcp run server.py
```

### Deploy to FastMCP Cloud

1. Push your repo to GitHub
2. Connect your repo to [FastMCP Cloud](https://fastmcp.cloud)
3. Set environment variables in the dashboard
4. Deploy

## Security

This server implements several security measures:

- **Opaque Tokens**: Users never see their actual Blackboard access token. They receive a random lookup key that only works with this MCP server.
- **Server-Side Storage**: Real Blackboard credentials are stored server-side, mapped to the user's opaque token.
- **Read-Only by Default**: All tools are read-only, limiting potential damage if a token is compromised.
- **Session Expiry**: Tokens expire based on Blackboard's token lifetime (typically 1 hour).

## API Reference

This server uses the [Blackboard Learn REST API](https://docs.anthology.com/docs/blackboard/rest-apis/learn-intro). Key endpoints used:

- `GET /users/me` - Current user profile
- `GET /users/me/courses` - User's course enrollments
- `GET /courses/{id}` - Course details
- `GET /courses/{id}/contents` - Course content
- `GET /courses/{id}/gradebook/columns` - Gradebook columns
- `GET /courses/{id}/gradebook/users/me` - User's grades
- `GET /courses/{id}/announcements` - Course announcements
- `GET /courses/{id}/users` - Course roster (instructor)


## License

Copyright © 2026. All rights reserved.

## Acknowledgments

- Built with [FastMCP](https://github.com/jlowin/fastmcp)
- Uses the [Blackboard Learn REST API](https://docs.anthology.com)

---

**Note**: This is an unofficial integration and is not affiliated with Anthology or Blackboard Inc.
