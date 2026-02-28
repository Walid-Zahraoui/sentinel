"""
Utility functions for Sentinel V14
Core password analysis and security checks.
"""

import hashlib
import requests
from zxcvbn import zxcvbn
from rich.console import Console

console = Console()


def identify_hash_type(hash_str: str) -> str:
    """Identify password hashing algorithm from hash string."""
    if hash_str.startswith("$1$"):
        return "MD5 (Weak)"
    if hash_str.startswith("$2") or hash_str.startswith("$2a$"):
        return "Blowfish"
    if hash_str.startswith("$5$"):
        return "SHA-256"
    if hash_str.startswith("$6$"):
        return "SHA-512"
    if hash_str.startswith("$y$"):
        return "Yescrypt (Strong)"
    return "Unknown"


def check_leaks_api(password: str) -> int:
    """
    Query HaveIBeenPwned API for password breaches.
    Returns: breach count (0 = not found, -1 = API error)
    """
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        res = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5
        )
        if res.status_code == 200:
            for line in res.text.splitlines():
                h, count = line.split(':')
                if h == suffix:
                    return int(count)
        return 0
    except requests.exceptions.Timeout:
        console.print("[yellow]⚠ HIBP API timeout — breach check skipped.[/yellow]")
        return -1
    except Exception as e:
        console.print(f"[yellow]⚠ HIBP API error: {e}[/yellow]")
        return -1


def detect_machine_generated(password: str, entropy: float) -> tuple:
    """
    Detect if password is likely machine-generated (high quality pattern).
    Returns: (is_machine_generated, description_text)
    """
    score = 0
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    if has_upper and has_lower and has_digit and has_symbol:
        score += 1
    
    density = entropy / length if length > 0 else 0
    if density > 3.5:
        score += 2
    
    if length in [12, 16, 24, 32]:
        score += 1

    if score >= 3:
        return True, "[bold magenta]LIKELY MACHINE GENERATED[/bold magenta]"
    elif score == 2:
        return False, "[yellow]POSSIBLY MACHINE GENERATED[/yellow]"
    else:
        return False, "[blue]LIKELY HUMAN MADE[/blue]"


def get_password_score(password: str) -> int:
    """Get password strength score (0-4) using zxcvbn."""
    return zxcvbn(password)['score']


def get_password_entropy(password: str) -> float:
    """Get password entropy (bits) using zxcvbn."""
    return zxcvbn(password)['guesses_log10']
