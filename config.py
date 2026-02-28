"""
Configuration module for Sentinel V14
Loads settings from environment variables and defines constants.
"""

import os

# API Configuration
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

# System Paths (Linux/Unix)
SHADOW_FILE = "/etc/shadow"
PASSWD_FILE = "/etc/passwd"
PAM_FILE = "/etc/pam.d/common-password"
SSH_CONFIG = "/etc/ssh/sshd_config"

# FIX (CRITICAL): Whitelist of safe command prefixes for AI-suggested fixes
# AI commands are NEVER executed unless they match one of these prefixes
ALLOWED_COMMAND_PREFIXES = (
    "chage ",
    "passwd ",
    "sed -i",
    "pam-auth-update",
    "authselect ",
    "systemctl restart sshd",
    "systemctl reload sshd",
)

# Default settings
DEFAULT_PASSWORD_LENGTH = 16
DEFAULT_AUDIT_TIME = 30
PASSWORD_SYMBOLS = "!@#$%^&*()_+"

# Wordlist paths for John the Ripper
WORDLIST_PATHS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/john/password.lst",
    "rockyou.txt"
]

# Check if AI is available
try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
