# SmartVulnaScan

SmartVulnaScan is a lightweight Python vulnerability scanning tool placed in this repository. It provides simple scanning utilities and reporting to help find and document potential issues quickly.

Key files
- `SmartVulnaScan.py` — CLI entrypoint / main orchestrator
- `scanner_core.py` — core scanning logic
- `reporter.py` — reporting / output generation

Requirements
- Python 3.10+ (3.12 tested in this workspace)
- Optional: dependencies listed in `requirements.txt` (if you add one)

Quick start
1. Create and activate a virtual environment:
   - Windows PowerShell:
     ```powershell
     python -m venv venv; .\venv\Scripts\Activate.ps1
     ```
2. Install dependencies 
3. Run the scanner (adjust arguments as needed):
   ```powershell
   python SmartVulnaScan.py
   ```

Usage notes
- Inspect `scanner_core.py` to see how targets are loaded and scanned.
- `reporter.py` contains helpers to write scan results to files or the console.

Examples
- Run a simple local scan (example):
  ```powershell
  python SmartVulnaScan.py --target 127.0.0.1
  ```

Contributing
- Open issues or submit pull requests. Keep changes small and include tests or reproduction steps.

License
This project is published under the MIT License — see `LICENSE`.
