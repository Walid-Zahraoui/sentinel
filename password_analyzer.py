"""
Password analysis module for Sentinel V14
Analyzes individual passwords and generates secure passwords.
"""

import os
import secrets
import string
import subprocess
from zxcvbn import zxcvbn
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm, Prompt, IntPrompt
from rich.markdown import Markdown
from rich import box

from config import WORDLIST_PATHS, PASSWORD_SYMBOLS, DEFAULT_PASSWORD_LENGTH
from utils import check_leaks_api, detect_machine_generated, get_password_score, get_password_entropy

console = Console()


class PasswordAnalyzer:
    """Single password analysis and generation."""

    def __init__(self, chat_session=None):
        self.chat_session = chat_session

    def perform_real_attack(self, password: str):
        """Simulate real brute-force attack using John the Ripper."""
        console.print("\n[bold cyan]➜ Real Attack Simulation[/bold cyan]")
        wordlist = None
        
        for p in WORDLIST_PATHS:
            if os.path.exists(p):
                wordlist = p
                break

        if not wordlist:
            console.print("[yellow]Warning: Default wordlists not found.[/yellow]")
            if Confirm.ask("Do you want to provide a path to a wordlist?"):
                path = Prompt.ask("Path")
                if os.path.exists(path):
                    wordlist = path

        if not wordlist:
            console.print("[red]Attack skipped: No wordlist available.[/red]")
            return

        salt = secrets.token_hex(4)
        hashed_pwd = ""
        test_file = "/tmp/sentinel_test.hash"

        try:
            cmd_hash = ["openssl", "passwd", "-6", "-salt", salt, password]
            result = subprocess.run(
                cmd_hash, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            hashed_pwd = result.stdout.strip()
        except Exception as e:
            console.print(f"[red]Error generating hash: {e}[/red]")
            return

        if not hashed_pwd:
            console.print("[red]Error: Could not generate hash with OpenSSL.[/red]")
            return

        try:
            with open(test_file, "w") as f:
                f.write(f"target:{hashed_pwd}\n")

            console.print(f"[yellow]Running John the Ripper using {wordlist}...[/yellow]")
            cmd = ["john", f"--wordlist={wordlist}", "--format=crypt", test_file]

            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            res = subprocess.run(["john", "--show", test_file], stdout=subprocess.PIPE, text=True)

            if f"target:{password}" in res.stdout or "1 password hash cracked" in res.stdout:
                console.print("[bold red]❌ CRACKED! This password is in the wordlist.[/bold red]")
            else:
                console.print(
                    f"[bold green]✅ SURVIVED! Password not found in "
                    f"{os.path.basename(wordlist)}.[/bold green]"
                )
        except FileNotFoundError:
            console.print("[red]Error: 'john' not found. Install John the Ripper.[/red]")
        except Exception as e:
            console.print(f"[red]Error running John: {e}[/red]")
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)

    def analyze_single_password(self):
        """Analyze a single password for security issues."""
        console.rule("[bold magenta]Deep Password Analyzer[/bold magenta]")
        try:
            pwd = Prompt.ask("Enter password to test", password=True)
            checks = []

            console.print("[cyan]➜ Checking Length and Character sets...[/cyan]")
            length = len(pwd)
            if length >= 12:
                checks.append(("Length (>12)", "OK", "green", 20))
            else:
                checks.append(("Length (<12)", "FAIL", "red", 0))

            has_upper = any(c.isupper() for c in pwd)
            has_digit = any(c.isdigit() for c in pwd)
            has_symbol = any(not c.isalnum() for c in pwd)

            checks.append(("Uppercase", "YES", "green", 10) if has_upper else ("Uppercase", "NO", "red", 0))
            checks.append(("Numbers", "YES", "green", 10) if has_digit else ("Numbers", "NO", "red", 0))
            checks.append(("Symbols", "YES", "green", 10) if has_symbol else ("Symbols", "NO", "red", 0))

            console.print("[cyan]➜ Checking Have I Been Pwned API (Breach Database)...[/cyan]")
            with console.status("[bold yellow]Querying API...[/bold yellow]"):
                leaks = check_leaks_api(pwd)

            if leaks == 0:
                checks.append(("Public Leaks", "CLEAN", "green", 40))
            elif leaks == -1:
                checks.append(("Public Leaks", "API UNAVAILABLE", "yellow", 0))
            else:
                checks.append(("Public Leaks", f"FOUND ({leaks}x)", "bold red", 0))

            console.print("[cyan]➜ Analyzing Entropy & Origin...[/cyan]")
            stats = zxcvbn(pwd)
            current_points = sum(c[3] for c in checks)

            is_machine, pattern_text = detect_machine_generated(pwd, stats['guesses_log10'])
            checks.append(("Origin", "Machine" if is_machine else "Human", "magenta" if is_machine else "green", 0))

            if Confirm.ask("\n[bold yellow]Run REAL brute-force attack? (John + Wordlist)[/bold yellow]"):
                self.perform_real_attack(pwd)

            table = Table(title="Detailed Security Analysis", box=box.ROUNDED)
            table.add_column("Criterion", style="cyan")
            table.add_column("Status", justify="center", style="white")
            table.add_column("Points", justify="right", style="bold")

            for name, status, color, points in checks:
                table.add_row(name, f"[{color}]{status}[/{color}]", f"[{color}]{points}[/]")

            console.print(table)
            console.print(f"\n[bold white]Origin Analysis:[/bold white] {pattern_text}")

            color_final = "green" if current_points >= 80 else "yellow" if current_points >= 50 else "red"
            console.print(Panel(
                f"[bold {color_final}]{current_points}/100[/]",
                title="SENTINEL SCORE",
                expand=False
            ))

            if current_points < 100 and self.chat_session:
                if Confirm.ask("\n[bold cyan]Ask AI for advice on this password?[/bold cyan]"):
                    weak = [c[0] for c in checks if c[2] == 'red']
                    prompt = (
                        f"Password score: {current_points}/100. "
                        f"Missing/failing: {weak}. "
                        f"Breach count: {leaks}. "
                        f"Likely machine-generated: {is_machine}. "
                        "Give actionable advice on improving this password."
                    )
                    with console.status("[cyan]Asking AI...[/cyan]"):
                        try:
                            resp = self.chat_session.send_message(prompt)
                            console.print(Panel(Markdown(resp.text), title="AI Advice"))
                        except Exception as e:
                            console.print(f"[red]AI unavailable: {e}[/red]")

        except KeyboardInterrupt:
            console.print("\n[yellow]Aborted.[/yellow]")

    def generate_pro_password(self):
        """Generate a strong cryptographically secure password."""
        console.rule("[bold green]Pro Generator[/bold green]")
        try:
            length = IntPrompt.ask("Length", default=DEFAULT_PASSWORD_LENGTH)
            use_upper = Confirm.ask("Include Uppercase?", default=True)
            use_digits = Confirm.ask("Include Numbers?", default=True)
            use_symbols = Confirm.ask("Include Symbols?", default=True)

            chars = string.ascii_lowercase
            if use_upper:
                chars += string.ascii_uppercase
            if use_digits:
                chars += string.digits
            if use_symbols:
                chars += PASSWORD_SYMBOLS

            if len(chars) < 10:
                console.print("[red]Error: Select at least one character type![/red]")
                return

            console.print("[cyan]Generating & Verifying...[/cyan]")
            attempts = 0
            max_attempts = 100
            while attempts < max_attempts:
                attempts += 1
                pwd = ''.join(secrets.choice(chars) for _ in range(length))
                if get_password_score(pwd) < 3:
                    continue
                leak_count = check_leaks_api(pwd)
                if leak_count != 0:
                    continue
                break
            else:
                console.print("[red]Could not generate verified password after 100 attempts.[/red]")
                return

            console.print(Panel(f"[bold green]{pwd}[/bold green]", title="Generated & Verified Secure"))
            entropy = get_password_entropy(pwd)
            console.print(
                f"Entropy: [cyan]{entropy:.2f} bits[/cyan] | "
                f"Leaks: [green]0[/green] | Attempts: [dim]{attempts}[/dim]"
            )
        except KeyboardInterrupt:
            pass
