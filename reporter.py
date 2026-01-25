from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Confirm
import time

class ReportGenerator:
    def __init__(self, console, vulnerabilities, target_url):
        self.console = console
        self.vulnerabilities = vulnerabilities
        self.target_url = target_url

    def generate_report(self):
        if not self.vulnerabilities:
            self.console.print(Panel.fit("[bold green]No vulnerabilities found!", subtitle="Good news!"))
            return
        report = Table(title="Vulnerability Assessment Report", box="ROUNDED", border_style="blue")
        report.add_column("Type", style="cyan")
        report.add_column("Severity", style="bold")
        report.add_column("Details", style="white")
        report.add_column("Location")
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_vulns = sorted(self.vulnerabilities, key=lambda x: severity_order.get(x["severity"], 5))
        for vuln in sorted_vulns:
            severity_style = "red" if vuln["severity"] in ["Critical", "High"] else "yellow" if vuln["severity"] == "Medium" else "green"
            details = vuln.get("payload", vuln.get("path", vuln.get("details", "N/A")))
            if isinstance(details, list):
                details = "\n".join(details)
            report.add_row(
                vuln["type"],
                Text(vuln["severity"], style=severity_style),
                details[:100] + "..." if len(str(details)) > 100 else str(details),
                vuln.get("url", vuln.get("target", "N/A"))
            )
        self.console.print(Panel.fit(report, title="Scan Results", border_style="green"))
        # Summary stats
        critical = sum(1 for v in self.vulnerabilities if v["severity"] == "Critical")
        high = sum(1 for v in self.vulnerabilities if v["severity"] == "High")
        medium = sum(1 for v in self.vulnerabilities if v["severity"] == "Medium")
        low = sum(1 for v in self.vulnerabilities if v["severity"] == "Low")
        info = sum(1 for v in self.vulnerabilities if v["severity"] == "Info")
        summary = Table(box="SIMPLE")
        summary.add_column("Severity", style="bold")
        summary.add_column("Count", justify="right")
        summary.add_row("Critical", str(critical), style="red")
        summary.add_row("High", str(high), style="red")
        summary.add_row("Medium", str(medium), style="yellow")
        summary.add_row("Low", str(low), style="green")
        summary.add_row("Info", str(info), style="blue")
        self.console.print(Panel.fit(summary, title="Summary", border_style="yellow"))
        if Confirm.ask("[blue][?] Save report to file?"):
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"cyber_sentinel_report_{timestamp}.txt"
            with open(filename, "w") as f:
                f.write(f"Cyber Sentinel Vulnerability Report\n")
                f.write(f"Target: {self.target_url}\n")
                f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for vuln in sorted_vulns:
                    f.write(f"Type: {vuln['type']}\n")
                    f.write(f"Severity: {vuln['severity']}\n")
                    f.write(f"Details: {vuln.get('payload', vuln.get('path', vuln.get('details', 'N/A')))}\n")
                    f.write(f"Location: {vuln.get('url', vuln.get('target', 'N/A'))}\n")
                    f.write("-"*50 + "\n")
                f.write("\nSummary:\n")
                f.write(f"Critical: {critical}\n")
                f.write(f"High: {high}\n")
                f.write(f"Medium: {medium}\n")
                f.write(f"Low: {low}\n")
                f.write(f"Info: {info}\n")
            self.console.print(f"[green][+] Report saved to {filename}")

