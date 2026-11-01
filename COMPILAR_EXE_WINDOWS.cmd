@echo off
setlocal
cd /d "%~dp0"
echo Compilacion Windows de Sentinel OneGuard con logo, GUI y UAC.
echo IMPORTANTE: mitigacion EXPERIMENTAL. Ejecutar primero en VM.
echo No sustituye a Microsoft Defender ni certifica que Windows este limpio.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_windows.ps1"
if errorlevel 1 (
  echo.
  echo ERROR: no se genero un ejecutable verificado.
  pause
  exit /b 1
)
echo.
echo Resultado: dist\SentinelOneGuard.exe
pause
