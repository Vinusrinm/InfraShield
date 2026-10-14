# InfraShield - Run Script for Windows PowerShell
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  InfraShield — The Living Security Blueprint             " -ForegroundColor Cyan
Write-Host "  Dev Sprint '26 Hackathon Command Center                 " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$PythonExe = "python"
if (Test-Path "$env:LOCALAPPDATA\Python\bin\python.exe") {
    $PythonExe = "$env:LOCALAPPDATA\Python\bin\python.exe"
}

Write-Host "`n[1/3] Checking Python environment ($PythonExe)..." -ForegroundColor Yellow
& $PythonExe --version

Write-Host "`n[2/3] Running Automated Security Verification Tests..." -ForegroundColor Yellow
& $PythonExe -m pytest infrashield/tests -v

Write-Host "`n[3/3] Starting InfraShield Web Server on http://127.0.0.1:8000..." -ForegroundColor Green
Write-Host "Open http://127.0.0.1:8000 in your web browser.`n" -ForegroundColor Cyan

& $PythonExe -m uvicorn infrashield.backend.main:app --host 127.0.0.1 --port 8000 --reload
