@echo off
setlocal

rem === Edit these two paths as needed ===
set "SOURCE=C:\Temp\comp"
set "TARGET=C:\Temp\comp.crypted"
rem =======================================

set "MODE=%~1"
if /I "%MODE%"=="decrypt" (
    set "MODE=decrypt"
) else (
    set "MODE=encrypt"
)

echo Mode:   %MODE%
echo Source: %SOURCE%
echo Target: %TARGET%
echo.

dotnet run "%~dp0CryptFolder.cs" -- %MODE% "%SOURCE%" "%TARGET%"
set "EXITCODE=%ERRORLEVEL%"

echo.
pause
endlocal & exit /b %EXITCODE%
