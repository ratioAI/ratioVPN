@echo off
chcp 65001 >nul
cd /d "%~dp0"

where dotnet >nul 2>nul || goto nosdk
dotnet --list-sdks | findstr /r "^8\. ^9\. ^10\." >nul || goto nosdk

echo Baue Ratio VPN ...
dotnet publish src\RatioVPN.App\RatioVPN.App.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o publish
if errorlevel 1 (
  echo.
  echo Build fehlgeschlagen. Bitte die Fehlermeldung oben kopieren.
  pause
  exit /b 1
)

echo.
echo Fertig: publish\RatioVPN.exe  (WinDivert.dll und WinDivert64.sys muessen daneben liegen)
explorer publish
pause
exit /b 0

:nosdk
echo Das .NET SDK (Version 8 oder neuer) fehlt.
echo Download: https://dotnet.microsoft.com/download/dotnet/8.0
start https://dotnet.microsoft.com/download/dotnet/8.0
pause
exit /b 1
