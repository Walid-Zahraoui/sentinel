#!/usr/bin/env python3
"""
SENTINEL V14 - PAM Enforcer Edition (Hardened & Modular)
Main entry point: Routes commands to appropriate modules.

Usage:
    python3 main.py --help
    python3 main.py --analyze
    sudo python3 main.py --audit
"""

import sys
import argparse
import warnings

warnings.filterwarnings("ignore")
warnings.simplefilter("ignore")

from rich.console import Console
from rich.panel import Panel

from config import GEMINI_API_KEY, GENAI_AVAILABLE
from password_analyzer import PasswordAnalyzer
from system_audit import SystemAudit
from pam_enforcer import PAMEnforcer
from ai_chat import AIChat

console = Console()


def init_ai():
    """Initialize Gemini AI if configured."""
    if not GENAI_AVAILABLE:
        return None
    
    if not GEMINI_API_KEY:
        console.print(
            "[yellow]⚠ GEMINI_API_KEY not set. AI features disabled. "
            "Set it via: export GEMINI_API_KEY=your_key[/yellow]"
        )
        return None
    
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        available_models = [
            m.name for m in genai.list_models()
            if 'generateContent' in m.supported_generation_methods
        ]
        
        chosen_model = next((m for m in available_models if 'flash' in m), None)
        if not chosen_model:
            chosen_model = next(
                (m for m in available_models if 'pro' in m),
                available_models[0] if available_models else None
            )
        
        if chosen_model:
            model = genai.GenerativeModel(chosen_model.replace("models/", ""))
            return model.start_chat(history=[])
    
    except Exception as e:
        console.print(f"[yellow]⚠ AI init failed: {e}[/yellow]")
    
    return None


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="SENTINEL V14 - PAM Enforcer Edition",
        add_help=False
    )
    
    parser.add_argument('--audit', action='store_true',
                       help='Full system audit (shadow, SSH, cracking, AI fixes)')
    parser.add_argument('--create-user', type=str, metavar="USER",
                       help='Create user with secure password validation')
    parser.add_argument('--analyze', action='store_true',
                       help='Analyze a single password')
    parser.add_argument('--generate', action='store_true',
                       help='Generate a verified secure password')
    parser.add_argument('--setup-test', action='store_true',
                       help='Create test users (DEV ONLY)')
    parser.add_argument('--chat', action='store_true',
                       help='Interactive AI chat')
    parser.add_argument('--pam', action='store_true',
                       help='Manage PAM configuration')
    parser.add_argument('--pam-check', action='store_true',
                       help='Internal: PAM password checker')
    parser.add_argument('--time', type=int, default=30,
                       help='Cracking timeout in seconds (default: 30)')
    parser.add_argument('--help', '-h', action='store_true',
                       help='Show this help message')
    
    args = parser.parse_args()
    
    try:
        # Initialize AI
        chat_session = init_ai()
        
        # Show help if no arguments
        if args.help or len(sys.argv) == 1:
            console.print(Panel("""
[bold green]SENTINEL V14 - PAM ENFORCER (Hardened & Modular)[/bold green]

[bold cyan]COMMANDS:[/bold cyan]
  [cyan]--audit[/cyan]                Full system audit (shadow, SSH, cracking)
  [cyan]--analyze[/cyan]              Test a single password (leaks, entropy, origin)
  [cyan]--generate[/cyan]             Generate a verified secure password
  [cyan]--create-user USER[/cyan]     Create secure user (password required)
  [cyan]--setup-test[/cyan]           Create test users for security testing
  [cyan]--pam[/cyan]                  Check and manage PAM configuration
  [cyan]--chat[/cyan]                 Interactive AI chat
  [cyan]--time SECONDS[/cyan]         Cracking timeout (default: 30)

[bold cyan]ROOT REQUIRED FOR:[/bold cyan]
  --audit, --create-user, --pam, --setup-test

[bold cyan]EXAMPLES:[/bold cyan]
  python3 main.py --analyze
  python3 main.py --generate
  sudo python3 main.py --audit --time 60
  sudo python3 main.py --create-user newuser
  python3 main.py --chat

[bold cyan]AI CONFIGURATION:[/bold cyan]
  export GEMINI_API_KEY=your_key_here
            """, title="Help", expand=False))
            return
        
        # Route to appropriate handler
        if args.pam_check:
            pam = PAMEnforcer()
            pam.pam_check_internal()
        
        elif args.create_user:
            pam = PAMEnforcer(chat_session)
            pam.create_secure_user(args.create_user)
        
        elif args.analyze:
            analyzer = PasswordAnalyzer(chat_session)
            analyzer.analyze_single_password()
        
        elif args.generate:
            analyzer = PasswordAnalyzer(chat_session)
            analyzer.generate_pro_password()
        
        elif args.setup_test:
            pam = PAMEnforcer(chat_session)
            pam.setup_test_users()
        
        elif args.pam:
            pam = PAMEnforcer(chat_session)
            pam.manage_pam()
        
        elif args.audit:
            audit = SystemAudit(chat_session)
            audit.audit_system(args.time)
        
        elif args.chat:
            if chat_session:
                chat = AIChat(chat_session)
                chat.interactive_chat()
            else:
                console.print("[red]Error: AI not configured. Set GEMINI_API_KEY environment variable.[/red]")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Aborted.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
