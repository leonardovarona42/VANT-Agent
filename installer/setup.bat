@echo off
setlocal enabledelayedexpansion

set VERSION=1.1.0

:: Detect Python
set "PYTHON="
for %%p in (python python3 py) do (
    for /f "delims=" %%v in ('where %%p 2^>nul') do (
        set "PYTHON=%%v"
        goto :found_python
    )
)
:found_python
if not defined PYTHON (
    echo [x] Python no encontrado. Instale Python 3.9+ desde https://python.org
    echo     Asegurese de marcar "Add Python to PATH" durante la instalacion.
    pause
    exit /b 1
)
for /f "delims=" %%v in ('"%PYTHON%" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2^>nul') do set PYVER=%%v
echo [+] Python !PYVER! encontrado: !PYTHON!

:: Determine installation mode
:: If we're in the source repo (installer\setup.bat), parent has agent.py
:: If we're in installed location (C:\Program Files\VANT-Agent\setup.bat), files are alongside

set "SCRIPT_DIR=%~dp0"
set "PARENT_DIR=!SCRIPT_DIR!.."
set "INSTALL_MODE=standalone"

:: Try to detect if agent files exist alongside or in parent
if exist "!SCRIPT_DIR!agent.py" (
    set "AGENT_SRC=!SCRIPT_DIR!"
    set "INSTALL_MODE=installed"
) else if exist "!PARENT_DIR!\agent.py" (
    set "AGENT_SRC=!PARENT_DIR!"
    set "INSTALL_MODE=standalone"
) else (
    echo [x] No se encontraron los archivos del agente.
    echo     Ejecute este instalador desde el directorio del proyecto VANT-Agent.
    pause
    exit /b 1
)

set "AGENT_DIR=%ProgramFiles%\VANT-Agent"

:: --- Check admin rights ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [x] Este instalador requiere privilegios de administrador.
    echo     Ejecute como Administrador (clic derecho ^> Ejecutar como administrador).
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   VANT-SIEM Agent v%VERSION% - Instalacion en Windows
echo ============================================================
echo.
echo   Modo: %INSTALL_MODE%
echo   Origen: !AGENT_SRC!
echo   Destino: %AGENT_DIR%
echo.

if /i "!INSTALL_MODE!"=="standalone" (
    :: --- Step 1: Create directories ---
    echo [1/6] Creando directorios...
    if not exist "%AGENT_DIR%" mkdir "%AGENT_DIR%"
    if not exist "%AGENT_DIR%\collectors" mkdir "%AGENT_DIR%\collectors"
    if not exist "%AGENT_DIR%\services" mkdir "%AGENT_DIR%\services"
    if not exist "%AGENT_DIR%\logs" mkdir "%AGENT_DIR%\logs"
    if not exist "%AGENT_DIR%\.vant_state" mkdir "%AGENT_DIR%\.vant_state"
    echo   OK

    :: --- Step 2: Copy agent files ---
    echo [2/6] Copiando archivos del agente...
    copy /Y "!AGENT_SRC!\agent.py" "%AGENT_DIR%\" >nul
    copy /Y "!AGENT_SRC!\output.py" "%AGENT_DIR%\" >nul
    copy /Y "!AGENT_SRC!\agent_tray.py" "%AGENT_DIR%\" >nul
    if exist "!AGENT_SRC!\collectors\*.py" (
        copy /Y "!AGENT_SRC!\collectors\*.py" "%AGENT_DIR%\collectors\" >nul
    )
    if exist "!AGENT_SRC!\services\*.py" (
        copy /Y "!AGENT_SRC!\services\*.py" "%AGENT_DIR%\services\" >nul
    )
    if exist "!AGENT_SRC!\linux\common\agent_installer_cli.py" (
        copy /Y "!AGENT_SRC!\linux\common\agent_installer_cli.py" "%AGENT_DIR%\" >nul
    )
    if exist "!AGENT_SRC!\linux\common\agent_tools.py" (
        copy /Y "!AGENT_SRC!\linux\common\agent_tools.py" "%AGENT_DIR%\" >nul
    )
    if exist "!AGENT_SRC!\config.template.yaml" (
        copy /Y "!AGENT_SRC!\config.template.yaml" "%AGENT_DIR%\" >nul
    ) else if exist "!AGENT_SRC!\config.example.yaml" (
        copy /Y "!AGENT_SRC!\config.example.yaml" "%AGENT_DIR%\config.template.yaml" >nul
    )
    if exist "!AGENT_SRC!\requirements.txt" (
        copy /Y "!AGENT_SRC!\requirements.txt" "%AGENT_DIR%\" >nul
    )
    if exist "!AGENT_SRC!\wheels" (
        robocopy "!AGENT_SRC!\wheels" "%AGENT_DIR%\wheels" /E /NP >nul 2>&1
    )
    echo   OK
) else (
    echo [1/6] Archivos ya instalados (modo instalador)
    echo   OK
    set /a STEP_OFFSET=2
)

:: --- Install Python dependencies ---
echo [3/6] Instalando dependencias Python...
if exist "%AGENT_DIR%\wheels\*.whl" (
    "%PYTHON%" -m pip install --no-index --find-links "%AGENT_DIR%\wheels" "%AGENT_DIR%\wheels"\*.whl -q
)
if %errorlevel% neq 0 (
    "%PYTHON%" -m pip install -r "%AGENT_DIR%\requirements.txt" -q
)
if %errorlevel% neq 0 (
    echo   Advertencia: No se pudieron instalar todas las dependencias.
    echo   Ejecute manualmente: "%PYTHON%" -m pip install -r "%AGENT_DIR%\requirements.txt"
) else (
    echo   OK
)

:: --- Create scheduled task ---
echo [4/6] Creando tarea programada...
schtasks /Delete /TN "VANT-SIEM-Agent" /F >nul 2>&1
schtasks /Create /TN "VANT-SIEM-Agent" /TR "\"!PYTHON!\" \"%AGENT_DIR%\agent.py\" --config \"%AGENT_DIR%\config.yaml\"" /SC ONLOGON /RL HIGHEST /F >nul 2>&1
if %errorlevel% equ 0 (
    echo   OK - La tarea se ejecutara al iniciar sesion
) else (
    echo   Advertencia: No se pudo crear la tarea programada
    echo   Cree la tarea manualmente o ejecute el agente desde el acceso directo
)

:: --- Create desktop shortcut ---
echo [5/6] Creando acceso directo...
set "DESKTOP=%USERPROFILE%\Desktop"
if exist "!DESKTOP!" (
    powershell -Command "$W=New-Object -ComObject WScript.Shell; $S=$W.CreateShortcut('!DESKTOP!\VANT-Agent.lnk'); $S.TargetPath='!PYTHON!'; $S.Arguments='\"%AGENT_DIR%\agent_tray.py\" --config \"%AGENT_DIR%\config.yaml\"'; $S.WorkingDirectory='%AGENT_DIR%'; $S.Description='VANT-SIEM Agent v%VERSION%'; $S.Save()" >nul 2>&1
    echo   OK
) else (
    echo   Escritorio no encontrado, omitiendo acceso directo
)

:: --- Run configuration wizard ---
echo [6/6] Asistente de configuracion...
echo.
if not exist "%AGENT_DIR%\config.yaml" (
    echo   Iniciando asistente de configuracion...
    "%PYTHON%" "%AGENT_DIR%\agent_installer_cli.py" --config "%AGENT_DIR%\config.yaml" --template "%AGENT_DIR%\config.template.yaml"
    if !errorlevel! equ 0 (
        echo   Configuracion completada.
    ) else (
        echo.
        echo   Para configurar manualmente, edite: %AGENT_DIR%\config.yaml
    )
) else (
    echo   Configuracion existente detectada en %AGENT_DIR%\config.yaml
    echo   Para reconfigurar, ejecute:
    echo     "%PYTHON%" "%AGENT_DIR%\agent_installer_cli.py" --config "%AGENT_DIR%\config.yaml"
)
echo.

:: --- Start agent ---
echo Iniciando agente...
schtasks /Run /TN "VANT-SIEM-Agent" >nul 2>&1
if %errorlevel% equ 0 (
    echo   Agente iniciado correctamente.
) else (
    echo   Ejecucion automatica fallida. Inicie manualmente desde el acceso directo.
)

echo.
echo ============================================================
echo   Instalacion completada!
echo ============================================================
echo.
echo   Directorio: %AGENT_DIR%
echo   Ejecutable: !PYTHON!
echo.
echo   Para ejecutar manualmente:
echo     !PYTHON! "%AGENT_DIR%\agent.py" --config "%AGENT_DIR%\config.yaml"
echo.
echo   Para cambiar configuracion:
echo     !PYTHON! "%AGENT_DIR%\agent_installer_cli.py" --config "%AGENT_DIR%\config.yaml"
echo.
pause
exit /b 0
