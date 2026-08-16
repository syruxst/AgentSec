@echo off
REM ============================================================
REM AgentSec - Escaneo rapido desde terminal
REM Uso:  doble-clic o arrastrar la carpeta a escanear
REM ============================================================
cd /d C:\xampp\htdocs\proyecto_de_titulo

set TARGET=%1
if "%TARGET%"=="" set TARGET=C:\Users\danie\.config\opencode

.\.venv\Scripts\python -m agentsec scan "%TARGET%" --format text
echo.
pause