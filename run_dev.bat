@echo off
setlocal

set "CONFIGURED_PROJECT_DIR=C:\Users\ronyz\OneDrive\Desktop\phishwall_public_\phishwall_backend"
set "NGROK_EXE=C:\Program Files\WindowsApps\ngrok.ngrok_3.39.1.0_x64__1g87z0zv29zzc\ngrok.exe"
set "NGROK_DOMAIN=dispense-why-glamour.ngrok-free.dev"
set "PORT=8000"
set "DELAY_SECONDS=3"

set "PROJECT_DIR=%CONFIGURED_PROJECT_DIR%"
if not exist "%PROJECT_DIR%" (
    echo Project directory not found: %CONFIGURED_PROJECT_DIR%
    exit /b 1
)

if not exist "%NGROK_EXE%" (
    echo ngrok executable not found at: %NGROK_EXE%
    exit /b 1
)

echo Starting backend in a new terminal...
start "PhishWall Backend" cmd /k "cd /d \"%PROJECT_DIR%\" && python -m uvicorn main:app --host 0.0.0.0 --port %PORT%"

echo Waiting %DELAY_SECONDS% second(s) before starting ngrok...
timeout /t %DELAY_SECONDS% /nobreak >nul

echo Starting ngrok in a new terminal...
start "PhishWall ngrok" cmd /k "\"%NGROK_EXE%\" http --domain=%NGROK_DOMAIN% %PORT%"

echo.
echo Health endpoints:
echo http://localhost:%PORT%/health
echo https://%NGROK_DOMAIN%/health

endlocal
