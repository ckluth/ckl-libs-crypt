@echo off
setlocal

rem === Edit these two paths as needed ===
set "TARGET=C:\Temp\comp-plain"
set "SOURCE=C:\Temp\comp.crypted"
rem =======================================

rem set "MODE=%~1"
rem if /I "%MODE%"=="decrypt" (
rem     set "MODE=decrypt"
rem ) else (
rem     set "MODE=encrypt"
rem )

set "MODE=decrypt"


echo Mode:   %MODE%
echo Source: %SOURCE%
echo Target: %TARGET%
echo.

dotnet run "%~dp0CryptFolder.cs" -- %MODE% "%SOURCE%" "%TARGET%"
set "EXITCODE=%ERRORLEVEL%"

echo.
pause
endlocal & exit /b %EXITCODE%
