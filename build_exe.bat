@echo off
rem Activate the virtual environment
call venv\Scripts\activate

rem Run PyInstaller to create the executable
pyinstaller --onefile --noconsole --name=InfoEncryptor main.py

rem Deactivate the virtual environment
deactivate

@echo Build completed.
pause