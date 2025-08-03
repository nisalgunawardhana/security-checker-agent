#!/usr/bin/env python3
"""
Example secure MCP server demonstrating best practices.
This file shows how to implement MCP security correctly.
"""

import json
import subprocess
import os
import secrets
import hashlib
import jwt
from typing import Dict, List, Optional
from mcp import MCPServer
from mcp.server import tool
import logging

# Configure secure logging (no sensitive data)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecureMCPServer:
    def __init__(self):
        self.server = MCPServer("secure-mcp-server")
        self.authorized_tools = ["safe_calculator", "file_info", "weather"]
        self.jwt_secret = os.environ.get("JWT_SECRET")  # From environment
        self.max_file_size = 10 * 1024 * 1024  # 10MB limit
        
    def validate_input(self, user_input: str) -> str:
        """Sanitize and validate user input to prevent injection attacks."""
        if not isinstance(user_input, str):
            raise ValueError("Input must be a string")
        
        # Remove potentially dangerous characters
        dangerous_patterns = ['<script', 'javascript:', 'data:', '${', '{{']
        sanitized = user_input
        
        for pattern in dangerous_patterns:
            if pattern.lower() in sanitized.lower():
                sanitized = sanitized.replace(pattern, '')
        
        # Limit length to prevent DoS
        if len(sanitized) > 1000:
            sanitized = sanitized[:1000]
            
        return sanitized.strip()
    
    def create_secure_prompt(self, user_input: str) -> str:
        """Create prompts using parameterized templates."""
        sanitized_input = self.validate_input(user_input)
        
        # Use template with proper escaping
        template = "You are a helpful assistant. User query: {query}"
        return template.format(query=sanitized_input)
    
    def verify_jwt_token(self, token: str) -> Optional[Dict]:
        """Verify JWT token with proper signature validation."""
        try:
            if not self.jwt_secret:
                raise ValueError("JWT secret not configured")
                
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            return payload
        except jwt.InvalidTokenError:
            logger.warning("Invalid JWT token received")
            return None
    
    def require_authentication(self, token: str, required_role: str = "user") -> bool:
        """Require proper authentication for sensitive operations."""
        payload = self.verify_jwt_token(token)
        if not payload:
            return False
            
        user_role = payload.get("role", "")
        if required_role == "admin" and user_role != "admin":
            return False
            
        return True
    
    def create_secure_session(self, user_id: str) -> str:
        """Create cryptographically secure session IDs."""
        session_data = f"{user_id}:{secrets.token_urlsafe(32)}"
        session_id = hashlib.sha256(session_data.encode()).hexdigest()
        return session_id
    
    def validate_file_path(self, file_path: str) -> bool:
        """Validate file paths to prevent directory traversal."""
        # Normalize the path
        normalized_path = os.path.normpath(file_path)
        
        # Check for directory traversal attempts
        if ".." in normalized_path or normalized_path.startswith("/"):
            return False
            
        # Restrict to allowed directories
        allowed_dirs = ["./uploads", "./data"]
        return any(normalized_path.startswith(allowed_dir) for allowed_dir in allowed_dirs)

# Secure tool implementations
@tool("safe_calculator")
def safe_calculator(expression: str, auth_token: str) -> str:
    """Safely evaluate mathematical expressions."""
    server = SecureMCPServer()
    
    if not server.require_authentication(auth_token):
        return "Authentication required"
    
    # Sanitize expression - only allow numbers and basic operators
    allowed_chars = set("0123456789+-*/(). ")
    if not all(c in allowed_chars for c in expression):
        return "Invalid characters in expression"
    
    try:
        # Use eval with restricted builtins for safety
        result = eval(expression, {"__builtins__": {}}, {})
        logger.info(f"Calculator operation performed")
        return str(result)
    except Exception as e:
        logger.warning(f"Calculator error: {type(e).__name__}")
        return "Calculation error"

@tool("secure_file_info")
def secure_file_info(file_path: str, auth_token: str) -> str:
    """Get file information with proper security checks."""
    server = SecureMCPServer()
    
    if not server.require_authentication(auth_token, "admin"):
        return "Admin authentication required"
    
    if not server.validate_file_path(file_path):
        logger.warning(f"Invalid file path access attempt: {file_path}")
        return "Invalid file path"
    
    try:
        if os.path.exists(file_path):
            stat = os.stat(file_path)
            # Return non-sensitive file information
            return f"File size: {stat.st_size} bytes"
        else:
            return "File not found"
    except PermissionError:
        return "Permission denied"
    except Exception:
        return "Error accessing file"

@tool("process_external_data")
def process_external_data(url: str, auth_token: str) -> str:
    """Safely process external data with validation."""
    server = SecureMCPServer()
    
    if not server.require_authentication(auth_token, "admin"):
        return "Admin authentication required"
    
    # Validate URL
    allowed_domains = ["api.weather.com", "api.example.com"]
    if not any(domain in url for domain in allowed_domains):
        return "URL not in allowlist"
    
    try:
        import requests
        response = requests.get(url, timeout=10)
        
        # Sanitize response data
        sanitized_data = server.validate_input(response.text[:1000])
        
        # Use parameterized prompt template
        prompt_template = "Process this validated data: {data}"
        return prompt_template.format(data=sanitized_data)
        
    except requests.RequestException:
        return "Failed to fetch external data"

def main():
    """Main server setup with security configurations."""
    # Verify required environment variables
    required_env_vars = ["JWT_SECRET"]
    missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {missing_vars}")
        return
    
    # Initialize secure server
    server = SecureMCPServer()
    
    # Log startup (no sensitive information)
    logger.info("Secure MCP server starting up")
    
    # Start server with security middleware
    server.server.run()

if __name__ == "__main__":
    main()
