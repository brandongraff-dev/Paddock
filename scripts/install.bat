@echo off
rem Paddock installer launcher: double-click this file.
rem It runs install.ps1 (next to it) with the script execution policy bypassed
rem for this one run only; nothing about your PC's settings is changed.
title Paddock installer
echo.
echo Starting the Paddock installer.
echo Leave this window open until it says "Paddock is running".
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
set RC=%ERRORLEVEL%
echo.
if not "%RC%"=="0" echo The installer stopped with an error (code %RC%). The message above says what to fix. You can double-click this file again after fixing it.
pause
exit /b %RC%
