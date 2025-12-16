@echo off
echo ==============================================
echo ZTA Government System - mTLS Deployment (Windows)
echo ==============================================
echo.

REM Step 1: Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

REM Step 2: Check for OpenSSL
where openssl >nul 2>&1
if errorlevel 1 (
    echo WARNING: OpenSSL not found in PATH
    echo.
    echo Installing OpenSSL via Chocolatey...
    powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
    choco install openssl -y
    echo Please restart Command Prompt and run this script again
    pause
    exit /b 1
)

REM Step 3: Generate certificates
echo Step 1: Generating certificates...
python create_certificates.py
if %errorlevel% neq 0 (
    echo ERROR: Certificate generation failed
    pause
    exit /b 1
)

REM Step 4: Setup database
echo.
echo Step 2: Setting up database...
python -c "
from app import create_app
from app.models import db
app = create_app()
with app.app_context():
    db.create_all()
    print('Database tables created/updated')
"
if %errorlevel% neq 0 (
    echo ERROR: Database setup failed
    pause
    exit /b 1
)

REM Step 5: Start OPA server if exists
echo.
echo Step 3: Checking for OPA server...
if exist run_opa_server.py (
    echo Starting OPA policy server...
    start cmd /k "python run_opa_server.py"
    timeout /t 3 /nobreak >nul
)

REM Step 6: Start Flask application
echo.
echo Step 4: Starting Flask application with mTLS...
echo ==============================================
echo Application will be available at:
echo   HTTPS: https://localhost:5000
echo.
echo To test mTLS with curl in PowerShell:
echo   curl --cert ./certs/clients/1/client.crt ^
echo        --key ./certs/clients/1/client.key ^
echo        --cacert ./certs/ca.crt ^
echo        https://localhost:5000/api/documents
echo.
echo OR with Python requests:
echo   python test_mtls.py
echo.
echo Press Ctrl+C to stop the application
echo ==============================================
echo.

python run.py

pause