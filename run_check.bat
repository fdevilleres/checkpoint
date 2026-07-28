@echo off
cd /d "%~dp0"
python main.py check >> check.log 2>&1
