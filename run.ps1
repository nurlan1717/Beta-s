# RANSOMRUN backend - PowerShell
Set-Location $PSScriptRoot
& .\venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
