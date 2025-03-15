@echo off
echo Building MiningProxy...

:: 设置编译参数
set LDFLAGS=-ldflags="-s -w"

:: Windows builds
echo Building for Windows...
go build %LDFLAGS% -o miningproxy_windows_amd64.exe
go build %LDFLAGS% -o miningproxy_windows_arm64.exe

:: Linux builds
echo Building for Linux...
set GOOS=linux
set GOARCH=amd64
go build %LDFLAGS% -o miningproxy_linux_amd64
set GOARCH=arm64
go build %LDFLAGS% -o miningproxy_linux_arm64

:: macOS builds
echo Building for macOS...
set GOOS=darwin
set GOARCH=amd64
go build %LDFLAGS% -o miningproxy_darwin_amd64
set GOARCH=arm64
go build %LDFLAGS% -o miningproxy_darwin_arm64

echo Build complete!
pause 