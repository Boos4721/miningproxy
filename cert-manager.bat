@echo off
REM ACME证书管理脚本 for Windows
REM 用于自动申请和更新SSL证书

set CONFIG_FILE=config.yaml
set DOMAIN=
set EMAIL=admin@example.com

echo ===== ACME自动证书管理工具 =====

REM 检查是否安装了acme.sh
if exist "%USERPROFILE%\.acme.sh\acme.sh" (
    echo acme.sh 已安装
) else (
    echo acme.sh 未安装，正在安装...
    powershell -Command "Invoke-WebRequest -Uri https://get.acme.sh -OutFile get-acme.sh"
    powershell -Command "bash get-acme.sh"
    if %ERRORLEVEL% neq 0 (
        echo 安装acme.sh失败，请手动安装: https://github.com/acmesh-official/acme.sh
        exit /b 1
    )
    echo acme.sh 安装成功
    del get-acme.sh
)

REM 从配置文件获取域名
if exist "%CONFIG_FILE%" (
    for /f "tokens=2 delims=: " %%a in ('findstr "domain:" %CONFIG_FILE%') do (
        set DOMAIN=%%a
    )
    if "%DOMAIN%"=="" (
        echo 未在配置文件中找到域名，请在config.yaml中添加domain字段
        exit /b 1
    )
    echo 使用配置的域名: %DOMAIN%
) else (
    echo 未找到配置文件 %CONFIG_FILE%
    exit /b 1
)

REM 申请证书
echo 正在申请证书...
bash "%USERPROFILE%\.acme.sh\acme.sh" --issue --standalone -d "%DOMAIN%" -k ec-256 --force
if %ERRORLEVEL% neq 0 (
    echo 证书申请失败，请检查域名解析和网络
    exit /b 1
)
echo 证书申请成功

REM 安装证书到当前目录
echo 正在安装证书到当前目录...
bash "%USERPROFILE%\.acme.sh\acme.sh" --install-cert -d "%DOMAIN%" --key-file "%CD%\%DOMAIN%.key" --fullchain-file "%CD%\%DOMAIN%.crt" --ecc
if %ERRORLEVEL% neq 0 (
    echo 证书安装失败
    exit /b 1
)

REM 更新配置文件
powershell -Command "(Get-Content %CONFIG_FILE%) -replace 'cert:.*', 'cert: %DOMAIN%.crt' | Set-Content %CONFIG_FILE%"
powershell -Command "(Get-Content %CONFIG_FILE%) -replace 'key:.*', 'key: %DOMAIN%.key' | Set-Content %CONFIG_FILE%"

echo 证书已安装到当前目录，并已更新配置文件
echo 证书文件: %DOMAIN%.crt
echo 密钥文件: %DOMAIN%.key
echo 证书管理操作完成
echo 您现在可以启动miningproxy了

pause 