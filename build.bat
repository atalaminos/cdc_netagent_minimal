@echo off
REM Compila Netagent en Windows (release) y ejecuta los tests de forma nativa.
REM
REM Uso:
REM   build.bat            release + tests
REM   build.bat --debug    build de debug
REM   build.bat --no-test  omite los tests
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "PROFILE=--release"
set "RUN_TESTS=1"

:parse
if "%~1"=="" goto after
if /I "%~1"=="--debug"   set "PROFILE="
if /I "%~1"=="--no-test" set "RUN_TESTS=0"
shift
goto parse
:after

echo ==^> Compilando workspace (Windows) %PROFILE%
cargo build --workspace %PROFILE%
if errorlevel 1 exit /b 1

if "%RUN_TESTS%"=="1" (
  echo ==^> Ejecutando tests
  cargo test --workspace
  if errorlevel 1 exit /b 1
)

if "%PROFILE%"=="" (set "OUT=debug") else (set "OUT=release")
echo ==^> Listo. Binario: target\%OUT%\netagent.exe
endlocal
