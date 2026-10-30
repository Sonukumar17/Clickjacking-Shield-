Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Starting ClickjackShield Web Platform" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Set PYTHONPATH to include installed packages
$env:PYTHONPATH = "C:\Users\Abhisek\AppData\Local\Programs\Python\Python314\Lib\site-packages"

$pyCandidates = @(
    "C:\Users\Abhisek\AppData\Roaming\uv\python\cpython-3.14-windows-x86_64-none\python.exe",
    "C:\Users\Abhisek\.local\bin\python3.14.exe",
    "C:\Users\Abhisek\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe",
    "python"
)

$selectedPy = $null
foreach ($cand in $pyCandidates) {
    if ($cand -eq "python" -or (Test-Path $cand)) {
        $selectedPy = $cand
        break
    }
}

Write-Host "[+] Using Python runtime at: $selectedPy" -ForegroundColor Green
& $selectedPy run.py
