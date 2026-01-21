"""
HTML templates for Blackboard MCP auth pages.
"""


def success_page(token: str, user_id: str) -> str:
    """Generate the authentication success page"""
    masked_token = "•" * 28 + token[-4:]
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Authentication Successful</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .card {{
                background: white;
                border-radius: 16px;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
                padding: 40px;
                max-width: 560px;
                width: 100%;
                text-align: center;
            }}
            .icon {{
                width: 80px; height: 80px;
                background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                border-radius: 50%;
                display: flex; align-items: center; justify-content: center;
                margin: 0 auto 24px;
            }}
            .icon svg {{ width: 40px; height: 40px; color: white; }}
            h1 {{ color: #1f2937; font-size: 24px; font-weight: 700; margin-bottom: 8px; }}
            .subtitle {{ color: #6b7280; font-size: 14px; margin-bottom: 24px; }}
            .step-section {{
                background: #f0fdf4; border: 2px solid #86efac; border-radius: 12px;
                padding: 20px; margin-bottom: 20px; text-align: left;
            }}
            .step-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }}
            .step-number {{
                background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                color: white; width: 28px; height: 28px; border-radius: 50%;
                display: flex; align-items: center; justify-content: center;
                font-size: 14px; font-weight: 700;
            }}
            .step-title {{ color: #166534; font-size: 14px; font-weight: 600; }}
            .copy-message-box {{
                background: white; border: 1px solid #d1d5db; border-radius: 8px;
                padding: 12px 16px; font-size: 14px; color: #374151;
            }}
            .copy-message-box code {{
                color: #7c3aed; font-family: 'Monaco', 'Menlo', monospace;
                background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 13px;
            }}
            .btn {{
                width: 100%; padding: 14px 20px; border-radius: 8px;
                font-size: 15px; font-weight: 600; cursor: pointer;
                transition: transform 0.2s; border: none; margin-top: 12px;
            }}
            .btn:hover {{ transform: translateY(-2px); }}
            .btn-copy {{
                background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                color: white;
            }}
            .warning-box {{
                background: #fef3c7; border: 1px solid #f59e0b; border-radius: 8px;
                padding: 12px 16px; margin-top: 20px;
                display: flex; align-items: flex-start; gap: 10px; text-align: left;
            }}
            .warning-box svg {{ width: 20px; height: 20px; color: #d97706; flex-shrink: 0; }}
            .warning-box p {{ color: #92400e; font-size: 13px; line-height: 1.4; }}
            .user-info {{ color: #9ca3af; font-size: 12px; margin-top: 16px; }}
            .copied-toast {{
                position: fixed; bottom: 30px; left: 50%;
                transform: translateX(-50%) translateY(100px);
                background: #1f2937; color: white;
                padding: 12px 24px; border-radius: 8px;
                font-size: 14px; opacity: 0;
                transition: transform 0.3s, opacity 0.3s;
            }}
            .copied-toast.show {{ transform: translateX(-50%) translateY(0); opacity: 1; }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="icon">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                </svg>
            </div>
            <h1>Authentication Successful!</h1>
            <p class="subtitle">Your Blackboard account is now connected</p>
            
            <div class="step-section">
                <div class="step-header">
                    <div class="step-number">1</div>
                    <div class="step-title">Copy this message to send to Claude</div>
                </div>
                <div class="copy-message-box">
                    Here's my Blackboard access token: <code>{masked_token}</code>
                </div>
                <button class="btn btn-copy" onclick="copyToClipboard()">📋 Copy Message to Clipboard</button>
            </div>
            
            <div class="step-section" style="background: #eff6ff; border-color: #93c5fd;">
                <div class="step-header">
                    <div class="step-number" style="background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);">2</div>
                    <div class="step-title" style="color: #1e40af;">Paste it in your Claude conversation</div>
                </div>
                <p style="color: #1e3a8a; font-size: 13px; line-height: 1.5;">
                    Go back to Claude and paste the message. Claude will remember your token for all Blackboard requests.
                </p>
            </div>
            
            <div class="warning-box">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                </svg>
                <p><strong>Keep this token private.</strong> It provides access to your Blackboard data for this session.</p>
            </div>
            
            <p class="user-info">Authenticated as: {user_id}</p>
        </div>
        
        <div class="copied-toast" id="toast">✓ Copied! Now paste it in Claude</div>
        
        <script>
            const token = "{token}";
            const message = "Here's my Blackboard access token: " + token;
            
            function copyToClipboard() {{
                navigator.clipboard.writeText(message).then(() => {{
                    const toast = document.getElementById('toast');
                    toast.classList.add('show');
                    setTimeout(() => toast.classList.remove('show'), 3000);
                }});
            }}
        </script>
    </body>
    </html>
    """


def error_page(message: str) -> str:
    """Generate the authentication error page"""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Authentication Error</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
                min-height: 100vh;
                display: flex; align-items: center; justify-content: center;
                padding: 20px;
            }}
            .card {{
                background: white; border-radius: 16px;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
                padding: 40px; max-width: 450px; width: 100%; text-align: center;
            }}
            .icon {{
                width: 80px; height: 80px;
                background: linear-gradient(135deg, #fca5a5 0%, #f87171 100%);
                border-radius: 50%;
                display: flex; align-items: center; justify-content: center;
                margin: 0 auto 24px;
            }}
            .icon svg {{ width: 40px; height: 40px; color: #dc2626; }}
            h1 {{ color: #1f2937; font-size: 24px; font-weight: 700; margin-bottom: 16px; }}
            .message {{ color: #6b7280; font-size: 14px; line-height: 1.6; margin-bottom: 24px; }}
            .retry-btn {{
                background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
                color: white; border: none; padding: 12px 24px;
                border-radius: 8px; font-size: 14px; font-weight: 600;
                cursor: pointer; text-decoration: none; display: inline-block;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="icon">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                </svg>
            </div>
            <h1>Authentication Failed</h1>
            <p class="message">{message}</p>
            <a href="/auth/start" class="retry-btn">Try Again</a>
        </div>
    </body>
    </html>
    """
