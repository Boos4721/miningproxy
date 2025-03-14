@echo off
setlocal enabledelayedexpansion

REM 多平台编译脚本 - Windows版本
REM 支持Linux/Windows/macOS/ARM架构

REM 设置输出目录
set OUTPUT_DIR=build
REM 程序名称
set APP_NAME=miningproxy
REM 版本号
set VERSION=1.0.0

REM 创建输出目录
if not exist %OUTPUT_DIR% mkdir %OUTPUT_DIR%

echo === 开始编译 %APP_NAME% v%VERSION% ===

REM 编译优化标志已包含在命令中

REM 定义目标平台
set PLATFORMS=linux/amd64 linux/arm64 linux/arm/v7 windows/amd64 windows/386 darwin/amd64 darwin/arm64 freebsd/amd64

REM 编译所有平台
for %%p in (%PLATFORMS%) do (
    for /f "tokens=1,2 delims=/" %%a in ("%%p") do (
        set OS=%%a
        set ARCH=%%b
        
        REM 处理ARM版本
        set GOARM=
        if "%%b"=="arm/v7" (
            set GOARM=7
            set ARCH=arm
        )
        
        REM 设置二进制文件名
        if "!OS!"=="windows" (
            set BIN_NAME=%APP_NAME%_!OS!_!ARCH!.exe
        ) else (
            set BIN_NAME=%APP_NAME%_!OS!_!ARCH!
        )
        
        set OUTPUT_PATH=%OUTPUT_DIR%\!BIN_NAME!
        
        echo 正在编译: !OS!/!ARCH! -^> !OUTPUT_PATH!
        
        REM 设置环境变量并编译
        set GOOS=!OS!
        set GOARCH=!ARCH!
        
        if "!GOARM!" NEQ "" (
            set GOARM=!GOARM!
        )
        
        go build -ldflags="-s -w" -o !OUTPUT_PATH!
        
        if errorlevel 1 (
            echo 编译失败: !OS!/!ARCH!
        ) else (
            echo 编译成功: !BIN_NAME!
        )
    )
)

echo === 编译完成 ===
echo 编译结果保存在: %CD%\%OUTPUT_DIR%\
dir %OUTPUT_DIR% 