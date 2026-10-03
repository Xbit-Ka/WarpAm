@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.

setlocal
cd /d %~dp0 || exit /b 1
echo [+] Building WarpAm.exe
call .\build.bat || exit /b 1
echo [+] Building installer
call .\installer\build.bat || exit /b 1
rem WarpAm pack 94: nothing is uninstalled first. The MSI upgrades the old
rem version in place and carries its tunnels over, while an uninstall would
rem delete them. The old line also removed AmneziaWG itself.
echo [+] Installing new version
for /f "tokens=3" %%a in ('findstr /r "Number.*=.*[0-9.]*" .\version\version.go') do set WIREGUARD_VERSION=%%a
set WIREGUARD_VERSION=%WIREGUARD_VERSION:"=%
msiexec /qb /i installer\dist\warpam-%PROCESSOR_ARCHITECTURE%-%WIREGUARD_VERSION%.msi
