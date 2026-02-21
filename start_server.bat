@echo off
echo ================================================
echo   RANSOMRUN Backend Server Startup
echo ================================================
echo.

cd /d "%~dp0"

if not exist "venv\Scripts\activate.bat" (
    echo ERROR: Virtual environment not found!
    echo Please run: python -m venv venv
    echo Then: venv\Scripts\activate
    echo Then: pip install -r requirements.txt
    pause
    exit /b 1
)

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo.
echo Starting FastAPI server on 0.0.0.0:8000...
echo Access the dashboard at: http://localhost:8000
echo Network access: http://192.168.10.55:8000
echo.
echo IMPORTANT: Make sure Windows Firewall allows port 8000!
echo Press Ctrl+C to stop the server
echo.

python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

pause
