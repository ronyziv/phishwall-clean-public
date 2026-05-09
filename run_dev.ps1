$ErrorActionPreference = "Stop"

$ConfiguredProjectDir = "C:\Users\ronyz\OneDrive\Desktop\phishwall_public_\phishwall_backend"
$NgrokExe = "C:\Program Files\WindowsApps\ngrok.ngrok_3.39.1.0_x64__1g87z0zv29zzc\ngrok.exe"
$NgrokDomain = "dispense-why-glamour.ngrok-free.dev"
$Port = 8000
$DelaySeconds = 3

if (Test-Path -LiteralPath $ConfiguredProjectDir) {
    $ProjectDir = $ConfiguredProjectDir
} else {
    Write-Error "Project directory not found: $ConfiguredProjectDir"
    exit 1
}

if (-not (Test-Path -LiteralPath $NgrokExe)) {
    Write-Error "ngrok executable not found at: $NgrokExe"
    exit 1
}

Write-Host "Starting backend in a new terminal..."
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "Set-Location -LiteralPath '$ProjectDir'; python -m uvicorn main:app --host 0.0.0.0 --port $Port"
)

Write-Host "Waiting $DelaySeconds second(s) before starting ngrok..."
Start-Sleep -Seconds $DelaySeconds

Write-Host "Starting ngrok in a new terminal..."
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "& '$NgrokExe' http --domain=$NgrokDomain $Port"
)

Write-Host ""
Write-Host "Health endpoints:"
Write-Host "http://localhost:$Port/health"
Write-Host "https://$NgrokDomain/health"
