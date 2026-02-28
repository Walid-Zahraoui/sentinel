"""
System audit module for Sentinel V14
System-wide auditing, SSH checks, and password cracking.
"""

import os
import sys
import subprocess
import datetime
import json
import re
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.markdown import Markdown
from rich import box

from config import SHADOW_FILE, PASSWD_FILE, PAM_FILE, SSH_CONFIG, ALLOWED_COMMAND_PREFIXES
from utils import identify_hash_type, check_leaks_api

console = Console()


def is_command_safe(cmd: str) -> bool:
    """FIX (CRITICAL): Validate AI commands against whitelist."""
    cmd = cmd.strip()
    return any(cmd.startswith(prefix) for prefix in ALLOWED_COMMAND_PREFIXES)


class SystemAudit:
    """System-wide security auditing."""

    def __init__(self, chat_session=None):
        self.chat_session = chat_session

    def analyze_shadow(self) -> list:
        """Analyze /etc/shadow for password policies."""
        if os.geteuid() != 0:
            console.print("[red]Root required.[/red]")
            sys.exit(1)
        
        users = []
        try:
            with open(SHADOW_FILE, 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) > 1 and '$' in parts[1]:
                        try:
                            last_chg_days = int(parts[2]) if parts[2] else 0
                            last_chg_date = (
                                datetime.date(1970, 1, 1) + datetime.timedelta(days=last_chg_days)
                            ).isoformat()
                            users.append({
                                'user': parts[0],
                                'algo': identify_hash_type(parts[1]),
                                'last': last_chg_date,
                                'min': parts[3],
                                'max': parts[4],
                                'warn': parts[5],
                                'inact': parts[6] if len(parts) > 6 else "",
                                'expire': parts[7] if len(parts) > 7 else ""
                            })
                        except (ValueError, IndexError) as e:
                            console.print(f"[yellow]⚠ Skipping malformed shadow entry: {e}[/yellow]")
        except Exception as e:
            console.print(f"[red]Error reading shadow file: {e}[/red]")
        
        return users

    def audit_ssh_config(self) -> list:
        """Audit SSH configuration for vulnerabilities."""
        console.rule("[bold magenta]SSH Hardening Auditor[/bold magenta]")
        
        if not Confirm.ask("Audit the SSH configuration?", default=True):
            return []

        console.print("[cyan]➜ Reading /etc/ssh/sshd_config...[/cyan]")
        if not os.path.exists(SSH_CONFIG):
            console.print("[yellow]SSH Config not found. Skipping.[/yellow]")
            return []

        issues = []
        try:
            with open(SSH_CONFIG, 'r') as f:
                config = f.read()

            if "PermitRootLogin yes" in config:
                issues.append({
                    "setting": "PermitRootLogin",
                    "status": "UNSAFE (yes)",
                    "fix": "PermitRootLogin no"
                })
            else:
                console.print("[green]✓ Root Login Disabled[/green]")

            if "PermitEmptyPasswords yes" in config:
                issues.append({
                    "setting": "PermitEmptyPasswords",
                    "status": "CRITICAL (yes)",
                    "fix": "PermitEmptyPasswords no"
                })
            else:
                console.print("[green]✓ Empty Passwords Disabled[/green]")

        except Exception as e:
            console.print(f"[red]Error reading SSH config: {e}[/red]")

        if issues:
            table = Table(title="SSH Vulnerabilities", box=box.ROUNDED)
            table.add_column("Setting", style="cyan")
            table.add_column("Current", style="white")
            table.add_column("Fix", style="magenta")
            for i in issues:
                table.add_row(i['setting'], f"[red]{i['status']}[/]", f"[cyan]{i['fix']}[/]")
            console.print(table)

        return issues

    def _execute_ai_fixes(self, fixes: list):
        """Safe execution of AI-suggested commands."""
        console.print("\n[bold yellow]⚠ AI-Suggested Commands Review[/bold yellow]")
        console.print("[dim]Each command will be reviewed. Only whitelisted commands allowed.[/dim]\n")

        for fix in fixes:
            cmd = fix.get('command', '').strip()
            desc = fix.get('description', 'No description')

            if not cmd:
                continue

            console.print(f"[bold white]Description:[/bold white] {desc}")
            console.print(f"[bold cyan]Command:[/bold cyan] [white]{cmd}[/white]")

            if not is_command_safe(cmd):
                console.print("[bold red]⛔ BLOCKED: Command not in whitelist. Skipping.[/bold red]\n")
                continue

            if Confirm.ask(f"Execute this command?", default=False):
                try:
                    result = subprocess.run(
                        cmd, shell=True,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                    )
                    if result.returncode == 0:
                        console.print("[green]✓ Command executed successfully.[/green]")
                        if result.stdout.strip():
                            console.print(f"[dim]{result.stdout.strip()}[/dim]")
                    else:
                        console.print(f"[red]✗ Command failed (exit {result.returncode}):[/red]")
                        console.print(f"[red]{result.stderr.strip()}[/red]")
                except Exception as e:
                    console.print(f"[red]Error executing command: {e}[/red]")
            else:
                console.print("[yellow]Skipped.[/yellow]")
            console.print()

    def export_report(self, users: list, cracked: list, ssh_issues: list, score: int):
        """Export audit results to HTML."""
        filename = f"sentinel_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html = (
            "<html><head><title>Sentinel Report</title>"
            "<style>body{font-family:sans-serif;background:#1a1a1a;color:#ddd;padding:20px}"
            "h1{color:#00ff00}.crit{color:#ff4444}"
            "table{border-collapse:collapse;width:100%}"
            "td,th{border:1px solid #444;padding:8px;text-align:left}"
            "th{background:#333}</style></head><body>"
            f"<h1>🛡️ Sentinel Audit</h1><h2>Score: {score}/100</h2>"
            "<h3>Users</h3>"
            "<table><tr><th>User</th><th>Algo</th><th>Max Age</th></tr>"
        )
        for u in users:
            html += f"<tr><td>{u['user']}</td><td>{u['algo']}</td><td>{u['max']}</td></tr>"
        html += "</table><h3>Cracked Users</h3><ul>"
        html += "".join([f"<li class='crit'>{c}</li>" for c in cracked])
        html += "</ul><h3>SSH Issues</h3><ul>"
        html += "".join([f"<li>{i['fix']}</li>" for i in ssh_issues])
        html += "</ul></body></html>"

        try:
            with open(filename, "w") as f:
                f.write(html)
            console.print(f"[bold green]Report exported to: {filename}[/bold green]")
        except Exception as e:
            console.print(f"[red]Failed to write report: {e}[/red]")

    def audit_system(self, time_limit: int):
        """Perform full system audit."""
        unshadow_path = "/tmp/sentinel_unshadowed.txt"
        try:
            console.print("[cyan]➜ Reading /etc/shadow for deep policy analysis...[/cyan]")
            users = self.analyze_shadow()

            table = Table(title="Deep System Password Audit", box=box.ROUNDED)
            table.add_column("User", style="cyan")
            table.add_column("Algo", style="white")
            table.add_column("Last Chg", justify="center")
            table.add_column("Min", justify="center")
            table.add_column("Max", justify="center")
            table.add_column("Warn", justify="center")
            table.add_column("Grade", justify="center", style="bold")

            score_total = 100
            for u in users:
                grade = "A"
                grade_color = "green"
                try:
                    if "MD5" in u['algo']:
                        grade = "F"; grade_color = "red"
                    elif u['max'] == "99999":
                        grade = "F"; grade_color = "red"; score_total -= 10
                    elif int(u['max']) > 180:
                        grade = "C"; grade_color = "yellow"
                    elif int(u['min']) == 0:
                        grade = "B"; grade_color = "green"
                except ValueError:
                    grade = "?"; grade_color = "yellow"

                table.add_row(
                    u['user'], u['algo'], u['last'],
                    u['min'],
                    u['max'] if u['max'] != "99999" else "[red]NEVER[/]",
                    u['warn'],
                    f"[{grade_color}]{grade}[/]"
                )
            console.print(table)

            ssh_issues = self.audit_ssh_config()
            score_total -= (len(ssh_issues) * 10)

            console.print("\n[bold cyan]➜ Cracking Phase[/bold cyan]")
            os.system(f"unshadow {PASSWD_FILE} {SHADOW_FILE} > {unshadow_path} 2>/dev/null")

            cmd = ["john", "--incremental=Alpha", f"--max-run-time={time_limit}", unshadow_path]
            if Confirm.ask("Use a custom wordlist? (No = Incremental Mode)", default=False):
                wordlist_path = Prompt.ask("Enter path to wordlist")
                if os.path.exists(wordlist_path):
                    cmd = ["john", f"--wordlist={wordlist_path}", f"--max-run-time={time_limit}", unshadow_path]

            console.print(f"[cyan]Running John ({time_limit}s)...[/cyan]")
            try:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                res = subprocess.run(["john", "--show", unshadow_path], stdout=subprocess.PIPE, text=True)
            except FileNotFoundError:
                console.print("[red]Error: 'john' not found. Install John the Ripper.[/red]")
                res = type('obj', (object,), {'stdout': ''})()

            cracked = []
            for line in res.stdout.splitlines():
                if ":" in line and "password hash" not in line:
                    cracked.append(line.split(':')[0])

            if cracked:
                console.print(f"[bold red]Cracked accounts: {cracked}[/bold red]")
                score_total -= 30
            else:
                console.print("[green]No passwords cracked.[/green]")

            if Confirm.ask("Export Report to HTML?"):
                self.export_report(users, cracked, ssh_issues, score_total)

            if self.chat_session:
                prompt = (
                    f"Audit Data:\n"
                    f"Users (with grades): {users}\n"
                    f"Cracked accounts: {cracked}\n"
                    f"SSH issues: {ssh_issues}\n\n"
                    "Return ONLY valid JSON (no markdown) with 'summary' and 'fixes' list."
                )

                with console.status("[cyan]Generating AI Report...[/cyan]"):
                    try:
                        resp = self.chat_session.send_message(prompt)
                        ai_response_text = resp.text
                    except Exception as e:
                        console.print(f"[red]AI error: {e}[/red]")
                        ai_response_text = None

                if ai_response_text:
                    try:
                        cleaned = re.sub(r'```(?:json)?', '', ai_response_text).strip().rstrip('`').strip()
                        rep = json.loads(cleaned)
                        console.print(Panel(rep.get('summary', ''), title="AI Assessment"))
                        fixes = rep.get('fixes', [])
                        if fixes:
                            self._execute_ai_fixes(fixes)
                    except json.JSONDecodeError:
                        console.print(Panel(Markdown(ai_response_text), title="AI Assessment"))
                    except Exception as e:
                        console.print(f"[red]Error processing AI response: {e}[/red]")

                if Confirm.ask("\n[bold cyan]Continue chatting with AI about this audit?[/bold cyan]"):
                    self._interactive_chat()

        except KeyboardInterrupt:
            console.print("\n[yellow]Aborted.[/yellow]")
        finally:
            if os.path.exists(unshadow_path):
                try:
                    os.remove(unshadow_path)
                except Exception as e:
                    console.print(f"[yellow]⚠ Could not remove temp file: {e}[/yellow]")

    def _interactive_chat(self):
        """Internal chat for audit follow-up."""
        if not self.chat_session:
            return
        console.rule("AI Chat")
        console.print("[dim]Type 'exit' to leave.[/dim]")
        while True:
            try:
                user_input = Prompt.ask("\n[green]You[/green]")
                if user_input.lower() in ['exit', 'quit']:
                    break
                if not user_input.strip():
                    continue
                with console.status("Thinking..."):
                    try:
                        r = self.chat_session.send_message(user_input)
                        console.print(Panel(Markdown(r.text), title="AI"))
                    except Exception as e:
                        console.print(f"[red]AI Error: {e}[/red]")
            except KeyboardInterrupt:
                break
