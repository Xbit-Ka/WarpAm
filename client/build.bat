@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.

setlocal enabledelayedexpansion
set BUILDDIR=%~dp0
set PATH=%BUILDDIR%.deps\llvm-mingw-20231128-ucrt-x86_64\bin;%BUILDDIR%.deps\go\bin;%BUILDDIR%.deps;%PATH%
set PATHEXT=.exe
cd /d %BUILDDIR% || exit /b 1

rem WarpAm: check every dependency separately. Existing verified/extracted
rem tools are reused; only a missing component is downloaded again.
:installdeps
	if not exist .deps mkdir .deps || goto :error
	cd .deps || goto :error
	if not exist go\bin\go.exe call :download go.zip https://go.dev/dl/go1.25.14.windows-amd64.zip 119044a92b3987c341cd6aebb256676dd4780d292f7b4e72a3e9976677841697 || goto :error
	if not exist llvm-mingw-20231128-ucrt-x86_64\bin\x86_64-w64-mingw32-gcc.exe call :download2 llvm-mingw-20231128-ucrt-x86_64.zip https://download.wireguard.com/windows-toolchain/distfiles/llvm-mingw-20231128-ucrt-x86_64.zip https://github.com/mstorsjo/llvm-mingw/releases/download/20231128/llvm-mingw-20231128-ucrt-x86_64.zip 7a344dafa6942de2c1f4643b3eb5c5ce5317fbab671a887e4d39f326b331798f || goto :error
	if not exist convert.exe call :download imagemagick.zip https://download.wireguard.com/windows-toolchain/distfiles/ImageMagick-7.0.8-42-portable-Q16-x64.zip 584e069f56456ce7dde40220948ff9568ac810688c892c5dfb7f6db902aa05aa "convert.exe colors.xml delegates.xml" || goto :error
	if not exist make.exe call :download make.zip https://download.wireguard.com/windows-toolchain/distfiles/make-4.2.1-without-guile-w32-bin.zip 30641be9602712be76212b99df7209f4f8f518ba764cf564262bc9d6e4047cc7 "--strip-components 1 bin" || goto :error
	if not exist src\Makefile call :download amneziawg-tools.zip https://github.com/amnezia-vpn/amneziawg-tools/archive/v3.1.20260812.zip 28c519791491d5aaa882e0c261169b8d9fbea04db8308e0937cb61758fcccfa0 "--exclude wg-quick --strip-components 1" || goto :error
	if not exist wintun\bin\amd64\wintun.dll call :download wintun.zip https://www.wintun.net/builds/wintun-0.14.1.zip 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51 || goto :error
	copy /y NUL prepared > NUL || goto :error
	cd .. || goto :error
	if /I "%~1"=="deps" (
		set "GOPATH=%BUILDDIR%.deps\gopath"
		set "GOROOT=%BUILDDIR%.deps\go"
		if not defined GOPROXY set "GOPROXY=https://proxy.golang.org,direct"
		echo [+] Downloading modules without changing go.mod or go.sum
		go mod download || goto :error
		pushd ..\core || goto :error
		go mod download || (popd & goto :error)
		popd
		goto :depssuccess
	)
	set "BUILD_TARGET=%~1"
	if "%BUILD_TARGET%"=="" set "BUILD_TARGET=all"
	if /I "%BUILD_TARGET%"=="x64" set "BUILD_TARGET=amd64"
	if /I not "%BUILD_TARGET%"=="x86" if /I not "%BUILD_TARGET%"=="amd64" if /I not "%BUILD_TARGET%"=="arm64" if /I not "%BUILD_TARGET%"=="all" (
		echo [-] Unknown architecture: %BUILD_TARGET%. Use x86, amd64, arm64, all or deps.
		exit /b 2
	)
	if not defined AWG_JOBS set "AWG_JOBS=2"

:render
	echo [+] Rendering icons
	for %%a in ("ui\icon\*.svg") do convert -background none "%%~fa" -define icon:auto-resize="256,192,128,96,64,48,40,32,24,20,16" -compress zip "%%~dpna.ico" || goto :error

:build
	for /f "tokens=3" %%a in ('findstr /r "Number.*=.*[0-9.]*" .\version\version.go') do set WIREGUARD_VERSION=%%a
	set WIREGUARD_VERSION=%WIREGUARD_VERSION:"=%
	for /f "tokens=1-4" %%a in ("%WIREGUARD_VERSION:.= % 0 0 0") do set WIREGUARD_VERSION_ARRAY=%%a,%%b,%%c,%%d
	set GOOS=windows
	set GOARM=7
	set CGO_ENABLED=0
	set GOFLAGS=
	set GOPATH=%BUILDDIR%.deps\gopath
	set GOROOT=%BUILDDIR%.deps\go
	if not defined GOPROXY set "GOPROXY=https://proxy.golang.org,direct"
	echo [+] Compatibility mode: preserving go.mod and go.sum
	if "%GoGenerate%"=="yes" (
		echo [+] Regenerating files
		go generate ./... || exit /b 1
	)
	if /I "%BUILD_TARGET%"=="x86" (
		call :build_plat x86 i686 386 || goto :error
	)
	if /I "%BUILD_TARGET%"=="amd64" (
		call :build_plat amd64 x86_64 amd64 || goto :error
	)
	if /I "%BUILD_TARGET%"=="arm64" (
		call :build_plat arm64 aarch64 arm64 || goto :error
	)
	if /I "%BUILD_TARGET%"=="all" (
		call :build_plat x86 i686 386 || goto :error
		call :build_plat amd64 x86_64 amd64 || goto :error
		call :build_plat arm64 aarch64 arm64 || goto :error
	)

:sign
	if exist .\sign.bat call .\sign.bat
	if "%SigningProvider%"=="" goto :success
	if "%TimestampServer%"=="" goto :success
	echo [+] Signing %BUILD_TARGET%
	if /I "%BUILD_TARGET%"=="x86" (
		call :sign_plat x86 || goto :error
	)
	if /I "%BUILD_TARGET%"=="amd64" (
		call :sign_plat amd64 || goto :error
	)
	if /I "%BUILD_TARGET%"=="arm64" (
		call :sign_plat arm64 || goto :error
	)
	if /I "%BUILD_TARGET%"=="all" (
		call :sign_plat x86 || goto :error
		call :sign_plat amd64 || goto :error
		call :sign_plat arm64 || goto :error
	)
	goto :success

:sign_plat
	if "%WARPAM_BUILD_GUARD%"=="1" (
		signtool sign %SigningProvider% /fd sha256 /tr "%TimestampServer%" /td sha256 /d WarpAm "%~1\WarpAm.exe" "%~1\awgchain-guard.exe" "%~1\awg.exe" || exit /b 1
	) else (
		signtool sign %SigningProvider% /fd sha256 /tr "%TimestampServer%" /td sha256 /d WarpAm "%~1\WarpAm.exe" "%~1\awg.exe" || exit /b 1
	)
	goto :eof

:depssuccess
	echo [+] Dependencies are ready and cached.
	exit /b 0

:success
	echo [+] Success for %BUILD_TARGET%. Launch WarpAm.exe.
	exit /b 0

:download2
	echo [+] Trying official toolchain mirror
	call :download %1 %2 %4
	if not errorlevel 1 goto :eof
	echo [!] Mirror unavailable, trying GitHub
	call :download %1 %3 %4
	exit /b %errorlevel%

:download
	echo [+] Downloading %1
	if exist %1 del /f /q %1 >NUL 2>&1
	curl --retry 5 --retry-delay 3 --retry-all-errors --connect-timeout 30 -#fLo %1 %2 || (del /f /q %1 >NUL 2>&1 & exit /b 1)
	echo [+] Verifying %1
	for /f %%a in ('CertUtil -hashfile %1 SHA256 ^| findstr /r "^[0-9a-f]*$"') do if not "%%a"=="%~3" exit /b 1
	echo [+] Extracting %1
	tar -xf %1 %~4 || exit /b 1
	echo [+] Cleaning up %1
	del %1 || exit /b 1
	goto :eof

:build_plat
	set GOARCH=%~3
	mkdir %1 >NUL 2>&1
	echo [+] Assembling resources %1
	%~2-w64-mingw32-windres -DWIREGUARD_VERSION_ARRAY=%WIREGUARD_VERSION_ARRAY% -DWIREGUARD_VERSION_STR=%WIREGUARD_VERSION% -i resources.rc -o "resources_%~3.syso" -O coff -c 65001 || exit /b %errorlevel%
	echo [+] Building program %1
	go build -tags load_wgnt_from_rsrc -ldflags="-H windowsgui -s -w" -trimpath -buildvcs=false -v -o "%~1\WarpAm.exe" || exit /b 1
	rem WarpAm pack 94: the program used to be amneziawg.exe.
	if exist "%~1\amneziawg.exe" del /f /q "%~1\amneziawg.exe" >NUL 2>&1
	if "%WARPAM_BUILD_GUARD%"=="1" (
		echo [+] Building WarpAm guard %1
		go build -ldflags="-s -w" -trimpath -buildvcs=false -o "%~1\awgchain-guard.exe" .\chainguard || exit /b 1
	) else (
		echo [+] The WarpAm guard is not built: the lock lives inside the service
		if exist "%~1\awgchain-guard.exe" del /f /q "%~1\awgchain-guard.exe" >NUL 2>&1
	)
	if not exist "%~1\awg.exe" (
		echo [+] Building command line tools %1
		rem Clean architecture-specific objects and dependency files. The tools
		rem source directory is shared by x86, amd64 and arm64 builds.
		del .deps\src\*.exe .deps\src\*.o .deps\src\*.d .deps\src\wincompat\*.o .deps\src\wincompat\*.d .deps\src\wincompat\*.lib 2> NUL
		rem Do not inherit compiler flags from Developer Command Prompt or IDEs.
		set "ARCH="
		set "GOARCH="
		set "TARGET_ARCH="
		set "CFLAGS="
		set "CPPFLAGS="
		set "CL="
		set "MAKEFLAGS="
		set "MFLAGS="
		set "LDFLAGS=-s"
		echo [+] Compiler: %~2-w64-mingw32-gcc
		where %~2-w64-mingw32-gcc.exe >NUL 2>&1 || (echo [-] Cross compiler not found & exit /b 1)
		rem Use the original verbose Make invocation and one job. This avoids the
		rem misleading "Waiting for unfinished jobs" state and prints the exact
		rem compiler command if the upstream tools fail.
		make --no-print-directory -C .deps\src PLATFORM=windows GOARCH= ARCH= TARGET_ARCH= CPPFLAGS= CC=%~2-w64-mingw32-gcc WINDRES=%~2-w64-mingw32-windres V=1 RUNSTATEDIR= SYSTEMDUNITDIR= -j1 || exit /b 1
		move /Y .deps\src\wg.exe "%~1\awg.exe" > NUL || exit /b 1
	)
	if not exist "%~1\wintun.dll" (
		copy /Y ".deps\wintun\bin\%~1\wintun.dll" "%~1\wintun.dll" > NUL || exit /b 1
	)
	goto :eof

:error
	echo [-] Failed with error #%errorlevel%.
	cmd /c exit %errorlevel%
