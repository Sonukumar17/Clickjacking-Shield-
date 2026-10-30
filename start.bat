@echo off
title ClickjackShield Web Platform
echo ============================================================
echo   Starting ClickjackShield Detection and Prevention Platform
echo ============================================================

set PYTHONPATH=C:\Users\Abhisek\AppData\Local\Programs\Python\Python314\Lib\site-packages

if exist "C:\Users\Abhisek\AppData\Roaming\uv\python\cpython-3.14-windows-x86_64-none\python.exe" (
    echo Using Python: C:\Users\Abhisek\AppData\Roaming\uv\python\cpython-3.14-windows-x86_64-none\python.exe
    "C:\Users\Abhisek\AppData\Roaming\uv\python\cpython-3.14-windows-x86_64-none\python.exe" run.py
) else if exist "C:\Users\Abhisek\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" (
    echo Using Python: C:\Users\Abhisek\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
    "C:\Users\Abhisek\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" run.py
) else (
    echo Using system Python
    python run.py
)
pause
