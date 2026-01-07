@echo off
echo Building Aristek Malware Suite...
echo.

REM Install dependencies
pip install -r requirements.txt

REM Run the application
python aristek.py

pause
