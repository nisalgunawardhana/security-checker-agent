#!/usr/bin/env python3
"""
Example MCP server with intentional security vulnerabilities for testing purposes.
This file demonstrates various MCP security issues that the scanner should detect.
"""

import json
import subprocess
import os
from mcp import MCPServer
from mcp.server import tool

# 1. Prompt Injection vulnerability - direct string concatenation
def handle_user_request(user_input):
    prompt = "You are a helpful assistant. " + user_input  # VULNERABLE: Direct concatenation
    return prompt

# 2. Tool Poisoning - dynamic tool loading without validation
def load_tool(tool_name):
    import importlib
    tool_module = importlib.import_module(tool_name)  # VULNERABLE: No validation
    return tool_module

# 3. Hardcoded secrets - cryptographic failures
API_KEY = "sk-1234567890abcdef"  # VULNERABLE: Hardcoded API key
SECRET_TOKEN = "super-secret-token-123"  # VULNERABLE: Hardcoded secret

# 4. Excessive permissions - subprocess with shell=True
@tool("execute_command")
def execute_command(command: str):
    result = subprocess.call(command, shell=True)  # VULNERABLE: Shell injection risk
    return result

# 5. Missing authentication
@tool("admin_function")
def admin_function(action: str):
    # VULNERABLE: No authentication check
    if action == "delete_all":
        return "All data deleted"
    return "Action completed"

# 6. Token passthrough without validation
def forward_request(auth_header, endpoint):
    headers = {"Authorization": auth_header}  # VULNERABLE: No token validation
    # Make request to external service
    return headers

# 7. Session hijacking - weak session management
import random
def create_session(user_id):
    session_id = str(random.randint(1000, 9999))  # VULNERABLE: Weak session ID
    return session_id

# 8. Indirect prompt injection - external data without sanitization
import requests
def process_external_data(url):
    response = requests.get(url)
    external_content = response.text  # VULNERABLE: No sanitization
    prompt = f"Process this data: {external_content}"
    return prompt

# 9. Confused deputy - privilege escalation
def execute_as_admin(user_command):
    # VULNERABLE: Escalating privileges without proper checks
    admin_command = f"sudo {user_command}"
    os.system(admin_command)

# 10. Supply chain - untrusted dependencies
# This would be in requirements.txt:
# untrusted-package==1.0.0

# Logging tokens (vulnerability)
import logging
def log_request(token, action):
    logging.info(f"User with token {token} performed {action}")  # VULNERABLE: Token in logs

# File access without restriction
def read_user_file(file_path):
    with open(file_path, 'r') as f:  # VULNERABLE: No path validation
        return f.read()

# Main server setup
if __name__ == "__main__":
    server = MCPServer("vulnerable-mcp-server")
    server.run()
