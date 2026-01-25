from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich import box
from urllib.parse import urlparse

from scanner_core import VulnerabilityScanner
from reporter import ReportGenerator

class CyberSentinel:
    def __init__(self):
        self.console = Console()
        self.target_url = None
        self.vulnerabilities = []
        self.scanner = None
        self.reporter = None

    def display_banner(self):
        banner = Text("""
   _____      _            _____               _   _ _____ _______ 
  / ____|    | |          / ____|             | \ | |_   _|__   __|
 | |    _   _| |__   ___ | (___   ___ ___ _ __|  \| | | |    | |   
 | |   | | | | '_ \ / _ \ \___ \ / __/ _ \ '__| . ` | | |    | |   
 | |___| |_| | |_) |  __/ ____) | (_|  __/ |  | |\  |_| |_   | |   
  \_____\__, |_.__/ \___|_____/ \___\___|_|  |_| \_|_____|  |_|   
         __/ |                                                    
        |___/                                                     
""", style="bold cyan")
        subtitle = Text("Automated Vulnerability Assessment Tool", style="bold green")
        self.console.print(banner)
        self.console.print(subtitle, justify="center")
        self.console.print(Panel.fit("Scanning for vulnerabilities with precision", border_style="yellow", style="dim"))

    def set_target_url(self):
        while True:
            url = Prompt.ask("[bold yellow][?][/] Enter target URL (e.g., http://example.com)", default="http://localhost")
            try:
                parsed = urlparse(url)
                if all([parsed.scheme, parsed.netloc]):
                    self.target_url = url
                    # Init or update scanner & reporter on new URL
                    if self.scanner is None:
                        self.scanner = VulnerabilityScanner(self.target_url, self.vulnerabilities)
                    else:
                        self.scanner.update_target(self.target_url)
                        self.scanner.vulnerabilities = self.vulnerabilities
                    self.reporter = ReportGenerator(self.console, self.vulnerabilities, self.target_url)
                    break
                else:
                    self.console.print("[red][!] Invalid URL. Please include scheme (http/https) and domain")
            except:
                self.console.print("[red][!] Invalid URL format. Please try again.")

    def display_main_menu(self):
        # self.console.clear()  # Still commented for Windows compatibility
        self.display_banner()
        menu = Table(title="Main Menu (STRICT SCOPE)", box=box.ROUNDED, border_style="blue")
        menu.add_column("Option", style="cyan", justify="right")
        menu.add_column("Description", style="white")
        menu.add_row("1", "Reflected Cross-Site Scripting (XSS) [GET]")
        menu.add_row("2", "SQL Injection (Error-based, GET)")
        menu.add_row("3", "Security Headers Misconfiguration")
        menu.add_row("4", "View/Save Report")
        menu.add_row("5", "Change Target URL")
        menu.add_row("0", "Exit")
        self.console.print(menu)

    def run(self):
        self.display_banner()
        self.set_target_url()
        while True:
            self.display_main_menu()
            choice = Prompt.ask("[bold yellow][>][/] Select an option", choices=["0", "1", "2", "3", "4", "5"], default="0")
            if choice == "1":
                self.scanner.check_xss_reflected()
            elif choice == "2":
                self.scanner.check_sqli_error_based_get()
            elif choice == "3":
                self.scanner.scan_security_headers()
            elif choice == "4":
                self.reporter.generate_report()
            elif choice == "5":
                self.set_target_url()
            elif choice == "0":
                if Confirm.ask("[red][?][/] Are you sure you want to exit?"):
                    self.console.print("[green][+] Thank you for using CyberSentinel!")
                    break

if __name__ == "__main__":
    app = CyberSentinel()
    try:
        app.run()
    except KeyboardInterrupt:
        app.console.print("\n[yellow][!] Scan interrupted by user")
        if app.reporter:
            app.reporter.generate_report()
    except Exception as e:
        app.console.print(f"[red][!] Fatal error: {str(e)}")
