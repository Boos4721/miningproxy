#!/bin/bash

# ACME证书管理脚本 for Linux/macOS
# 用于自动申请和更新SSL证书

CONFIG_FILE="config.yaml"
DOMAIN=""
EMAIL="admin@example.com"  # 请修改为您的邮箱

# 检查是否安装acme.sh
check_acme() {
    if [ -f "$HOME/.acme.sh/acme.sh" ]; then
        echo "acme.sh 已安装"
        return 0
    else
        echo "acme.sh 未安装，正在安装..."
        return 1
    fi
}

# 安装acme.sh
install_acme() {
    curl https://get.acme.sh | sh
    if [ $? -ne 0 ]; then
        echo "安装acme.sh失败，请手动安装: https://github.com/acmesh-official/acme.sh"
        exit 1
    fi
    echo "acme.sh 安装成功"
}

# 从配置文件获取域名
parse_config() {
    if [ -f "$CONFIG_FILE" ]; then
        DOMAIN=$(grep "domain:" "$CONFIG_FILE" | head -n 1 | awk '{print $2}' | tr -d '\r')
        if [ -z "$DOMAIN" ]; then
            echo "未在配置文件中找到域名，请在config.yaml中添加domain字段"
            exit 1
        fi
        echo "使用配置的域名: $DOMAIN"
    else
        echo "未找到配置文件 $CONFIG_FILE"
        exit 1
    fi
}

# 申请证书
issue_cert() {
    echo "正在申请证书..."
    ~/.acme.sh/acme.sh --issue --standalone -d "$DOMAIN" -k ec-256 --force
    if [ $? -ne 0 ]; then
        echo "证书申请失败，请检查域名解析和网络"
        exit 1
    fi
    echo "证书申请成功"
}

# 安装证书到当前目录
install_cert() {
    echo "正在安装证书到当前目录..."
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --key-file "$(pwd)/$DOMAIN.key" --fullchain-file "$(pwd)/$DOMAIN.crt" --ecc
    if [ $? -ne 0 ]; then
        echo "证书安装失败"
        exit 1
    fi
    
    # 更新配置文件
    if grep -q "cert:" "$CONFIG_FILE"; then
        sed -i "s|cert:.*|cert: $DOMAIN.crt|g" "$CONFIG_FILE"
    else
        sed -i "1i cert: $DOMAIN.crt" "$CONFIG_FILE"
    fi
    
    if grep -q "key:" "$CONFIG_FILE"; then
        sed -i "s|key:.*|key: $DOMAIN.key|g" "$CONFIG_FILE"
    else
        sed -i "2i key: $DOMAIN.key" "$CONFIG_FILE"
    fi
    
    echo "证书已安装到当前目录，并已更新配置文件"
    echo "证书文件: $DOMAIN.crt"
    echo "密钥文件: $DOMAIN.key"
}

# 主程序
main() {
    echo "===== ACME自动证书管理工具 ====="
    
    parse_config
    
    if ! check_acme; then
        install_acme
    fi
    
    # 执行证书操作
    issue_cert
    install_cert
    
    echo "证书管理操作完成"
    echo "您现在可以启动miningproxy了"
}

main 