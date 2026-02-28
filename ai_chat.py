"""
AI chat module for Sentinel V14
Interactive AI conversation interface.
"""

import sys
import termios
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.markdown import Markdown

console = Console()


def flush_input():
    """Flush stdin buffer."""
    try:
        termios.tcflush(sys.stdin, termios.TCIOFLUSH)
    except Exception:
        pass


class AIChat:
    """Interactive AI chat interface."""

    def __init__(self, chat_session):
        self.chat_session = chat_session

    def interactive_chat(self):
        """Start interactive AI chat session."""
        if not self.chat_session:
            console.print("[red]AI not available.[/red]")
            return
        
        console.rule("AI Chat")
        console.print("[dim]Type 'exit' or 'quit' to leave.[/dim]")
        
        while True:
            try:
                flush_input()
                user_input = Prompt.ask("\n[green]You[/green]")
                
                if user_input.lower() in ['exit', 'quit']:
                    break
                
                if not user_input.strip():
                    continue
                
                with console.status("Thinking..."):
                    try:
                        response = self.chat_session.send_message(user_input)
                        console.print(Panel(Markdown(response.text), title="AI"))
                    except Exception as e:
                        console.print(f"[red]AI Error: {e}[/red]")
            
            except KeyboardInterrupt:
                break
