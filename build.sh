#!/bin/bash

# 多平台编译脚本
# 支持Linux/Windows/macOS/ARM架构

# 设置输出目录
OUTPUT_DIR="build"
# 程序名称
APP_NAME="miningproxy"
# 版本号
VERSION="1.0.0"

# 创建输出目录
mkdir -p $OUTPUT_DIR

echo "=== 开始编译 $APP_NAME v$VERSION ==="

# 编译优化标志
LDFLAGS="-s -w" # 减小二进制文件体积

# 定义目标平台
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "linux/arm/v7"
    "windows/amd64"
    "windows/386"
    "darwin/amd64"
    "darwin/arm64"
    "freebsd/amd64"
)

# 编译所有平台
for PLATFORM in "${PLATFORMS[@]}"; do
    OS=${PLATFORM%/*}
    ARCH=${PLATFORM#*/}
    
    # 处理ARM版本
    if [[ "$ARCH" == "arm/v7" ]]; then
        GOARM=7
        ARCH="arm"
    else
        GOARM=""
    fi
    
    # 设置二进制文件名
    if [[ "$OS" == "windows" ]]; then
        BIN_NAME="${APP_NAME}_${OS}_${ARCH}.exe"
    else
        BIN_NAME="${APP_NAME}_${OS}_${ARCH}"
    fi
    
    OUTPUT_PATH="$OUTPUT_DIR/$BIN_NAME"
    
    echo "正在编译: $OS/$ARCH -> $OUTPUT_PATH"
    
    # 设置环境变量并编译
    if [[ "$GOARM" != "" ]]; then
        GOOS=$OS GOARCH=$ARCH GOARM=$GOARM go build -ldflags="-s -w" -o $OUTPUT_PATH
    else
        GOOS=$OS GOARCH=$ARCH go build -ldflags="-s -w" -o $OUTPUT_PATH
    fi
    
    if [ $? -ne 0 ]; then
        echo "编译失败: $OS/$ARCH"
    else
        # 在非Windows平台上添加执行权限
        if [[ "$OS" != "windows" ]]; then
            chmod +x $OUTPUT_PATH
        fi
        
        # 对Linux和macOS二进制文件进行压缩
        if [[ "$OS" == "linux" || "$OS" == "darwin" ]] && command -v upx &> /dev/null; then
            echo "压缩二进制文件: $OUTPUT_PATH"
            upx -9 $OUTPUT_PATH
        fi
        
        echo "编译成功: $BIN_NAME"
    fi
done

echo "=== 编译完成 ==="
echo "编译结果保存在: $(pwd)/$OUTPUT_DIR/"
# ls -la $OUTPUT_DIR/ 