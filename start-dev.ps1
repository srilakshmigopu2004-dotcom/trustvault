# Activate the virtual environment (it lives one folder above the project)
..\.venv\Scripts\Activate.ps1

# Fixed key so the audit chain stays valid between runs (dev only)
$env:TV_AUDIT_KEY = "dev-only-audit-key-change-me-0123456789"
$env:TV_INSECURE_COOKIES = "1"

python -m trustvault.seed
flask --app run run
