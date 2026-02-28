"""
PAM enforcer module for Sentinel V14
PAM configuration management and secure user creation.
"""

import os
import sys
import subprocess
import time
import shutil
from zxcvbn import zxcvbn
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm, Prompt, IntPrompt
from rich.markdown import Markdown
from rich import box

from config import PAM_FILE, DEFAULT_PASSWORD_LENGTH
from utils import check_leaks_api

console = Console()


class PAMEnforcer:
    """PAM configuration and user management."""

    def __init__(self, chat_session=None):
        self.chat_session = chat_session

    def get_pam_settings(self) -> dict:
        """Parse current PAM configuration."""
        settings = {
            'minlen': 'Default',
            'ucredit': 'Default',
            'lcredit': 'Default',
            'dcredit': 'Default',
            'ocredit': 'Default',
            'retry': 'Default',
            'enforce_for_root': 'No'
        }
        try:
            with open(PAM_FILE, 'r') as f:
                for line in f:
                    if ("pam_pwquality.so" in line or "pam_cracklib.so" in line) \
                            and not line.strip().startswith('#'):
                        parts = line.split()
                        for part in parts:
                            if '=' in part:
                                k, v = part.split('=', 1)
                                if k in settings:
                                    settings[k] = v
                            if part == 'enforce_for_root':
                                settings['enforce_for_root'] = 'Yes'
        except Exception as e:
            console.print(f"[yellow]⚠ Could not read PAM file: {e}[/yellow]")
        return settings

    def manage_pam(self):
        """Main PAM management interface."""
        console.rule("[bold magenta]PAM Configuration Enforcer[/bold magenta]")

        is_installed = False
        try:
            with open(PAM_FILE, 'r') as f:
                if "sentinel" in f.read():
                    is_installed = True
        except Exception as e:
            console.print(f"[yellow]⚠ Could not read PAM file: {e}[/yellow]")

        status_text = "[green]ACTIVE[/green]" if is_installed else "[yellow]INACTIVE[/yellow]"
        console.print(f"Sentinel Hook Status: {status_text}")

        console.print("\n[cyan]➜ Analyzing PAM Configuration...[/cyan]")
        settings = self.get_pam_settings()

        table = Table(title="PAM Password Quality Settings", box=box.ROUNDED)
        table.add_column("Parameter", style="cyan")
        table.add_column("Current Value", justify="center")
        table.add_column("Recommended", justify="center", style="green")

        for key, val in settings.items():
            color = "white"
            rec = ""
            if key == 'minlen':
                rec = "12+"
                try:
                    color = "green" if val != 'Default' and int(val) >= 12 else "red"
                except ValueError:
                    color = "red"
            elif key in ['ucredit', 'lcredit', 'dcredit', 'ocredit']:
                rec = "< 0 (-1)"
                try:
                    color = "green" if val != 'Default' and int(val) < 0 else "yellow"
                except ValueError:
                    color = "yellow"
            table.add_row(key, f"[{color}]{val}[/]", rec)

        console.print(table)

        console.print("\n[bold white]Available Actions:[/bold white]")
        console.print("1. [cyan]Ask AI[/cyan] to fix this configuration")
        console.print("2. [magenta]Install/Uninstall[/magenta] Sentinel Hook")
        console.print("3. Exit")

        choice = IntPrompt.ask("Select an option", choices=["1", "2", "3"])

        if choice == 1:
            self._ai_fix_config(settings)
        elif choice == 2:
            self._manage_hook(is_installed)

    def _ai_fix_config(self, settings: dict):
        """Get AI recommendations for PAM configuration."""
        if self.chat_session:
            prompt = (
                f"Current PAM Config: {settings}. File: {PAM_FILE}. "
                "Explain what is weak and provide the EXACT line for "
                "/etc/pam.d/common-password with: minlen 12, required "
                "upper/lower/digit/symbol, enforce_for_root."
            )
            with console.status("[cyan]Consulting AI...[/cyan]"):
                try:
                    resp = self.chat_session.send_message(prompt)
                    console.print(Panel(Markdown(resp.text), title="AI PAM Recommendation"))
                except Exception as e:
                    console.print(f"[red]AI unavailable: {e}[/red]")
        else:
            console.print("[red]AI not available (API key missing).[/red]")

    def _manage_hook(self, is_installed: bool):
        """Install or uninstall Sentinel PAM hook."""
        if is_installed:
            if Confirm.ask("Uninstall Sentinel Hook?"):
                try:
                    lines = open(PAM_FILE, 'r').readlines()
                    with open(PAM_FILE, 'w') as f:
                        for line in lines:
                            if "sentinel" not in line:
                                f.write(line)
                    console.print("[green]Uninstalled.[/green]")
                except Exception as e:
                    console.print(f"[red]Error uninstalling hook: {e}[/red]")
        else:
            if Confirm.ask("Install Sentinel Hook?"):
                try:
                    shutil.copy(PAM_FILE, f"{PAM_FILE}.bak")
                    console.print(f"[dim]Backup created: {PAM_FILE}.bak[/dim]")
                    script_path = os.path.realpath(__file__)
                    hook_line = (
                        f"password requisite pam_exec.so expose_authtok "
                        f"{script_path} --pam-check\n"
                    )
                    with open(PAM_FILE, 'r') as f:
                        content = f.read()
                    with open(PAM_FILE, 'w') as f:
                        f.write(hook_line + content)
                    console.print("[green]Installed![/green]")
                except Exception as e:
                    console.print(f"[red]Error installing hook: {e}[/red]")

    def create_secure_user(self, username: str):
        """Create a user with strong password validation."""
        console.rule(f"[bold green]Creating Secure User: {username}[/bold green]")
        pwd = Prompt.ask("Set a password for the new user", password=True)
        pwd_confirm = Prompt.ask("Confirm password", password=True)

        if pwd != pwd_confirm:
            console.print("[red]Error: Passwords do not match![/red]")
            return

        with console.status("[bold yellow]Verifying Password Strength...[/bold yellow]"):
            leaks = check_leaks_api(pwd)
            score = zxcvbn(pwd)['score']
            time.sleep(0.5)

        if leaks > 0:
            console.print(
                f"[bold red]❌ BLOCKED: Password found in {leaks} public breach(es).[/bold red]"
            )
            return
        if leaks == -1:
            console.print(
                "[yellow]⚠ Could not verify against breach database. Proceeding with caution.[/yellow]"
            )
        if score < 3:
            console.print("[bold red]❌ BLOCKED: Password is too weak (Score < 3).[/bold red]")
            return

        console.print("[bold green]✅ Password is Secure. Creating user...[/bold green]")
        try:
            subprocess.run(["useradd", "-m", username], check=True)
            proc = subprocess.Popen(['chpasswd'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate(input=f"{username}:{pwd}".encode())
            if proc.returncode != 0:
                console.print(f"[red]chpasswd failed: {err.decode().strip()}[/red]")
                return
            subprocess.run(["chage", "-M", "90", "-m", "1", "-W", "7", username], check=True)
            console.print(
                f"[bold cyan]SUCCESS: User '{username}' created with a secure, expiring password.[/bold cyan]"
            )
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Error creating user: {e}[/red]")
        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/red]")

    def setup_test_users(self):
        """Create test users for security testing (DEV ONLY)."""
        console.print(
            "[bold red]⚠ WARNING: Creates users with INTENTIONALLY WEAK passwords "
            "for testing ONLY. Never run on production![/bold red]"
        )
        if not Confirm.ask("Proceed?"):
            return

        import secrets
        data = [
            ("test_weak1", "123456"),
            ("test_strong1", secrets.token_urlsafe(16)),
        ]
        for u, p in data:
            try:
                os.system(f"useradd -m {u} 2>/dev/null")
                proc = subprocess.Popen(['chpasswd'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
                proc.communicate(input=f"{u}:{p}".encode())
                os.system(f"chage -M 99999 {u}")
                console.print(f"[green]Created: {u}[/green]")
            except Exception as e:
                console.print(f"[red]Failed to create {u}: {e}[/red]")

        console.print(
            "[bold yellow]Delete after testing: userdel -r test_weak1 && userdel -r test_strong1[/bold yellow]"
        )

    def pam_check_internal(self):
        """Called by PAM via pam_exec.so. Validates password from stdin."""
        try:
            p = sys.stdin.read().strip()
            if not p:
                sys.exit(0)

            score = zxcvbn(p)['score']
            if score < 3:
                print("Password too weak (score < 3)", file=sys.stderr)
                sys.exit(1)

            leak_count = check_leaks_api(p)
            if leak_count > 0:
                print(f"Password found in {leak_count} public breach(es)", file=sys.stderr)
                sys.exit(1)
            elif leak_count == -1:
                print("Warning: breach check unavailable — proceeding", file=sys.stderr)
                sys.exit(0)

            sys.exit(0)
        except Exception as e:
            print(f"sentinel pam_check error: {e}", file=sys.stderr)
            sys.exit(0)
