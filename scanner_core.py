import requests
from rich.console import Console
from rich.panel import Panel

class VulnerabilityScanner:
    def __init__(self, target_url, vulnerabilities=None):
        self.console = Console()
        self.target_url = target_url
        self.vulnerabilities = vulnerabilities if vulnerabilities is not None else []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberSentinel/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })

    def update_target(self, url):
        self.target_url = url

    def check_xss_reflected(self):
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>"
        ]
        params = ["search", "q", "query", "id", "name"]
        with self.console.status("[bold green]Testing for Reflected XSS..."):
            for param in params:
                for payload in payloads:
                    try:
                        response = self.session.get(f"{self.target_url}?{param}={payload}")
                        if payload in response.text:
                            self.vulnerabilities.append({
                                "type": "Reflected XSS",
                                "severity": "Medium",
                                "payload": payload,
                                "url": f"{self.target_url}?{param}=[input]"
                            })
                            self.console.print(f"[red][!] Reflected XSS found in parameter {param} with payload: {payload}")
                    except Exception as e:
                        self.console.print(f"[yellow][~] Error testing reflected XSS: {str(e)}")
        self.console.print("[green][+] Reflected XSS test completed")

    def check_sqli_error_based_get(self):
        payloads = ["'", '"', "' OR '1'='1", '" OR "1"="1', "' OR 1=1--", "1 AND 1=1", "1 AND 1=2"]
        params = ["id", "user", "name", "category", "product"]
        with self.console.status("[bold green]Testing for Error-based SQLi (GET)..."):
            for param in params:
                for payload in payloads:
                    try:
                        response = self.session.get(f"{self.target_url}?{param}={payload}", timeout=5)
                        if any(keyword in response.text.lower() for keyword in ["sql", "syntax", "error", "mysql", "oracle"]):
                            self.vulnerabilities.append({
                                "type": "SQL Injection (Error-based GET)",
                                "severity": "Critical",
                                "payload": payload,
                                "url": f"{self.target_url}?{param}=[input]"
                            })
                            self.console.print(f"[red][!] Possible SQLi in GET parameter {param} with payload: {payload}")
                    except Exception as e:
                        self.console.print(f"[yellow][~] Error testing SQLi (GET): {str(e)}")
        self.console.print("[green][+] Error-based SQLi (GET) test completed")

    def scan_security_headers(self):
        self.console.print(Panel.fit("[bold]Security Headers Misconfiguration Scan", style="blue"))
        try:
            response = self.session.get(self.target_url)
            headers = response.headers
            insecure_headers = []
            if 'server' in headers:
                insecure_headers.append(f"Server header exposed: {headers['server']}")
            if 'x-powered-by' in headers:
                insecure_headers.append(f"X-Powered-By exposed: {headers['x-powered-by']}")
            if 'x-aspnet-version' in headers:
                insecure_headers.append(f"ASP.NET version exposed: {headers['x-aspnet-version']}")
            required_headers = [
                ('Strict-Transport-Security', 'Strict-Transport-Security is missing'),
                ('Content-Security-Policy', 'Content-Security-Policy is missing'),
                ('X-Frame-Options', 'X-Frame-Options is missing'),
                ('X-XSS-Protection', 'X-XSS-Protection is missing'),
                ('X-Content-Type-Options', 'X-Content-Type-Options is missing')
            ]
            for header, warning in required_headers:
                if header.lower() not in [h.lower() for h in headers]:
                    insecure_headers.append(warning)
            if not insecure_headers:
                insecure_headers.append("No obviously insecure headers found")
            self.vulnerabilities.append({
                "type": "Security Headers Information",
                "severity": "Low",
                "details": insecure_headers,
                "url": self.target_url
            })
            for h in insecure_headers:
                self.console.print(f"[yellow][-] {h}")
        except Exception as e:
            self.console.print(f"[yellow][~] Error checking headers: {str(e)}")
        self.console.print("[green][+] Security headers check completed")

