# SentinelAI v5

A local defensive cybersecurity dashboard built with FastAPI, SQLite, HTML/CSS/JS.

## New in v5

- Asset Manager and background uptime monitoring
- Notification Center for outages, recoveries, and slow responses
- Email Header Analyzer (SPF/DKIM/DMARC + routing indicators)
- File Hash / Static Analyzer (SHA-256, MD5 fingerprint, entropy, simple indicators; no execution)
- Advanced Domain Intelligence (A, AAAA, MX, NS, SPF, DMARC, CAA, DNSKEY, PTR)
- Local Remediation Assistant for scan findings
- Improved scan comparison (fixed findings and new issues)
- Existing Login/Register, profile drawer, password change, scan history, PDF reports, CSV export, phishing detector, password analyzer and security assistant

## Important behavior

Live monitoring runs **while the SentinelAI server is running**. It does not continue after you close the Python process or shut down the computer.

The file analyzer is a local static check. It does not execute uploaded files and is not a replacement for antivirus or a malware sandbox.

The email-header analyzer and phishing detector provide indicators, not proof that content is safe or malicious.

Use website scanning and monitoring only for assets you own or are authorized to assess.

## Windows PowerShell setup

From the folder containing `requirements.txt`:

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt --index-url https://pypi.org/simple
python -m uvicorn app.main:app --reload
```

Open:

- Dashboard: http://127.0.0.1:8000
- API docs: http://127.0.0.1:8000/docs

If you are one folder above the project folder, first `cd` into the folder where `requirements.txt` is located.
