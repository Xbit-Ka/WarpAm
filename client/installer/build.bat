@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.

setlocal
set PATHEXT=.exe
set BUILDDIR=%~dp0
cd /d %BUILDDIR% || exit /b 1

for /f "tokens=3" %%a in ('findstr /r "Number.*=.*[0-9.]*" ..\version\version.go') do set WIREGUARD_VERSION=%%a
set WIREGUARD_VERSION=%WIREGUARD_VERSION:"=%

set WIX_CANDLE_FLAGS=-nologo -dWIREGUARD_VERSION="%WIREGUARD_VERSION%"
set WIX_LIGHT_FLAGS=-nologo -spdb
set WIX_LIGHT_FLAGS=%WIX_LIGHT_FLAGS% -sice:ICE39
set WIX_LIGHT_FLAGS=%WIX_LIGHT_FLAGS% -sice:ICE61
set WIX_LIGHT_FLAGS=%WIX_LIGHT_FLAGS% -sice:ICE03

rem WarpAm: reuse WiX when it is already present.
:installdeps
	if not exist .deps mkdir .deps || goto :error
	cd .deps || goto :error
	if exist wix\bin\candle.exe goto :wixready
	call :download wix-binaries.zip https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip 6ac824e1642d6f7277d0ed7ea09411a508f6116ba6fae0aa5f2c7daa2ff43d31 || goto :error
	echo [+] Extracting wix-binaries.zip
	if not exist wix\bin mkdir wix\bin || goto :error
	tar -xf wix-binaries.zip -C wix\bin || goto :error
	echo [+] Cleaning up wix-binaries.zip
	del wix-binaries.zip || goto :error
:wixready
	copy /y NUL prepared > NUL || goto :error
	cd .. || goto :error
	if /I "%~1"=="deps" goto :depssuccess
	set "INSTALL_TARGET=%~1"
	if "%INSTALL_TARGET%"=="" set "INSTALL_TARGET=all"
	if /I "%INSTALL_TARGET%"=="x64" set "INSTALL_TARGET=amd64"
	if /I not "%INSTALL_TARGET%"=="x86" if /I not "%INSTALL_TARGET%"=="amd64" if /I not "%INSTALL_TARGET%"=="arm64" if /I not "%INSTALL_TARGET%"=="all" (
		echo [-] Unknown architecture: %INSTALL_TARGET%. Use x86, amd64, arm64, all or deps.
		exit /b 2
	)

:build
	if exist ..\sign.bat call ..\sign.bat
	set PATH=%BUILDDIR%..\.deps\llvm-mingw-20231128-ucrt-x86_64\bin;%PATH%
	set WIX=%BUILDDIR%.deps\wix\
	set CFLAGS=-O3 -Wall -std=gnu11 -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -municode -DUNICODE -D_UNICODE -DNDEBUG
	set LDFLAGS=-shared -s -Wl,--kill-at -Wl,--major-os-version=6 -Wl,--minor-os-version=1 -Wl,--major-subsystem-version=6 -Wl,--minor-subsystem-version=1 -Wl,--tsaware -Wl,--dynamicbase -Wl,--nxcompat -Wl,--export-all-symbols
	set LDLIBS=-lmsi -lole32 -lshlwapi -lshell32 -luuid -lntdll
	if not exist dist mkdir dist || goto :error
	if /I "%INSTALL_TARGET%"=="x86" (
		call :msi x86 i686 x86 || goto :error
	)
	if /I "%INSTALL_TARGET%"=="amd64" (
		call :msi amd64 x86_64 x64 || goto :error
	)
	if /I "%INSTALL_TARGET%"=="arm64" (
		call :msi arm64 aarch64 arm64 || goto :error
	)
	if /I "%INSTALL_TARGET%"=="all" (
		call :msi x86 i686 x86 || goto :error
		call :msi amd64 x86_64 x64 || goto :error
		call :msi arm64 aarch64 arm64 || goto :error
	)
	if "%SigningProvider%"=="" goto :success
	if "%TimestampServer%"=="" goto :success
	echo [+] Signing
	signtool sign %SigningProvider% /fd sha256 /tr "%TimestampServer%" /td sha256 /d "WarpAm Setup" "dist\warpam-*-%WIREGUARD_VERSION%.msi" || goto :error

:depssuccess
	echo [+] Installer dependencies are ready and cached.
	exit /b 0

:success
	echo [+] Success for %INSTALL_TARGET%.
	exit /b 0

:download
	echo [+] Downloading %1
	if exist %1 del /f /q %1 >NUL 2>&1
	curl --retry 5 --retry-delay 3 --retry-all-errors --connect-timeout 30 -#fLo %1 %2 || (del /f /q %1 >NUL 2>&1 & exit /b 1)
	echo [+] Verifying %1
	for /f %%a in ('CertUtil -hashfile %1 SHA256 ^| findstr /r "^[0-9a-f]*$"') do if not "%%a"=="%~3" exit /b 1
	goto :eof

:msi
	set CC=%~2-w64-mingw32-gcc
	if not exist "%~1" mkdir "%~1"
	echo [+] Compiling %1
	%CC% %CFLAGS% %LDFLAGS% -o "%~1\customactions.dll" customactions.c %LDLIBS% || exit /b 1
	if "%SigningProvider%"=="" goto :skipsign
	if "%TimestampServer%"=="" goto :skipsign
	echo [+] Signing %1
	signtool sign %SigningProvider% /fd sha256 /tr "%TimestampServer%" /td sha256 /d "WarpAm Setup Custom Actions" "%~1\customactions.dll" || exit /b 1
:skipsign
	set "WIX_GUARD_FLAG="
	if "%WARPAM_BUILD_GUARD%"=="1" set "WIX_GUARD_FLAG=-dWARPAM_GUARD=1"
	"%WIX%bin\candle" %WIX_CANDLE_FLAGS% %WIX_GUARD_FLAG% -dWIREGUARD_PLATFORM="%~1" -out "%~1\wireguard.wixobj" -arch %3 wireguard.wxs || exit /b %errorlevel%
	echo [+] Linking %1
	"%WIX%bin\light" %WIX_LIGHT_FLAGS% -out "dist\warpam-%~1-%WIREGUARD_VERSION%.msi" "%~1\wireguard.wixobj" || exit /b %errorlevel%
	goto :eof

:error
	echo [-] Failed with error #%errorlevel%.
	cmd /c exit %errorlevel%
