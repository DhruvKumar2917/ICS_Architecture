# Start script for ICS AASG Threat Modeler
Write-Host "==========================================" -ForegroundColor Green
Write-Host "   Starting ICS AASG Threat Modeler       " -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

# 1. Start Backend in a new window
Write-Host "`nStarting Backend FastAPI Server in a separate window..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd backend; .venv\Scripts\activate; python main.py"

# 2. Start Frontend Dev Server
Write-Host "Starting Frontend Vite Dev Server..." -ForegroundColor Cyan
cd frontend
npm run dev
