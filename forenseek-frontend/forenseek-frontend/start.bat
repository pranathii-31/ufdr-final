@echo off
cd /d %~dp0
call npm install
IF %ERRORLEVEL% NEQ 0 (
    echo npm install failed with error %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)
call npm start