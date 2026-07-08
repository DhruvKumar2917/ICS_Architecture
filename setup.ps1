# Setup script for ICS AASG Threat Modeler
Write-Host "==========================================" -ForegroundColor Green
Write-Host "   Setting up ICS AASG Threat Modeler     " -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

# 1. Setup Backend
Write-Host "`n[1/2] Setting up Python virtual environment and backend dependencies..." -ForegroundColor Cyan
cd backend
if (-not (Test-Path .venv)) {
    python -m venv .venv
}
.venv\Scripts\pip.exe install -r requirements.txt
cd ..

# 2. Setup Frontend
Write-Host "`n[2/2] Installing frontend npm packages..." -ForegroundColor Cyan
cd frontend
npm install
cd ..

Write-Host "`n==========================================" -ForegroundColor Green
Write-Host " Setup Complete! Run './start.ps1' to start the application." -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
