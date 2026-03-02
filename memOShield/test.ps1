# memOShield Quick Test Script (Windows PowerShell)
# Bu script memOShield projesini otomatik test eder
# Kullanim: powershell -ExecutionPolicy Bypass -File test.ps1

$ErrorActionPreference = "Stop"

function Write-Green($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Red($msg)   { Write-Host "[FAIL] $msg" -ForegroundColor Red }
function Write-Yellow($msg){ Write-Host "[*] $msg" -ForegroundColor Yellow }
function Write-Blue($msg)  { Write-Host $msg -ForegroundColor Cyan }

Write-Blue "========================================"
Write-Blue "  memOShield Automatic Test Script"
Write-Blue "========================================"
Write-Host ""

# 1. Python kontrolu
Write-Yellow "1/6 - Checking Python..."
try {
    $pyVer = & python --version 2>&1
    Write-Green "Python found: $pyVer"
} catch {
    Write-Red "Python not found"
    Exit 1
}

# 2. venv olustur
Write-Yellow "2/6 - Setting up virtual environment..."
if (!(Test-Path ".venv")) {
    & python -m venv .venv | Out-Null
    Write-Green "Virtual environment created"
} else {
    Write-Green "Virtual environment already exists"
}
if (!(Test-Path ".\.venv\Scripts\Activate.ps1")) {
    Write-Red "Virtual environment setup failed"
    Exit 1
}

# 3. Aktivasyon ve bagimliliklar
Write-Yellow "3/6 - Installing dependencies..."
& ".\.venv\Scripts\Activate.ps1"
$ErrorActionPreference = "Continue"
& pip install -q -r requirements.txt 2>&1 | Out-Null
$ErrorActionPreference = "Stop"
Write-Green "Dependencies installed"

# 4. Database test
Write-Yellow "4/6 - Testing database..."
$ErrorActionPreference = "Continue"
& python tools/test_db.py 2>&1 | Out-Null
$dbExit = $LASTEXITCODE
$ErrorActionPreference = "Stop"
if ($dbExit -eq 0) {
    Write-Green "Database initialized"
} else {
    Write-Red "Database test failed"
    Exit 1
}

# 5. Moduller
Write-Yellow "5/6 - Testing Python modules..."
$ErrorActionPreference = "Continue"
$modResult = & python tools/test_modules.py 2>$null
$modExit = $LASTEXITCODE
$ErrorActionPreference = "Stop"
Write-Host ($modResult | Out-String)
if ($modExit -eq 0) {
    Write-Green "All modules OK"
} else {
    Write-Red "Module test failed"
    Exit 1
}

# 6. Flask app test
Write-Yellow "6/6 - Testing Flask app..."
$ErrorActionPreference = "Continue"
& python tools/test_app.py 2>&1 | Out-Null
$appExit = $LASTEXITCODE
$ErrorActionPreference = "Stop"
if ($appExit -eq 0) {
    Write-Green "Flask app loaded successfully"
} else {
    Write-Red "Flask app test failed"
    Exit 1
}

Write-Host ""
Write-Blue "========================================"
Write-Green "All tests passed!"
Write-Blue "========================================"
Write-Host ""

Write-Yellow "Next steps:"
Write-Host "  1. Start the server:" -ForegroundColor White
Write-Host "     python app.py" -ForegroundColor Cyan
Write-Host ""
Write-Host "  2. Open in browser:" -ForegroundColor White
Write-Host "     http://127.0.0.1:5000" -ForegroundColor Cyan
Write-Host ""
Write-Host "  3. Demo mode (no login needed):" -ForegroundColor White
Write-Host "     http://127.0.0.1:5000/demo" -ForegroundColor Cyan
Write-Host ""
