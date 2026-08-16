# AgentSec - Escaneo rapido desde PowerShell
# Uso:  .\scripts\escanear.ps1 [ruta]
param([string]$Target = "C:\Users\danie\.config\opencode")

cd C:\xampp\htdocs\proyecto_de_titulo
.\\.venv\Scripts\python -m agentsec scan $Target --format text