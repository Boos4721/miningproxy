#!/bin/bash

VERSION="1.0.0"
BINARY_NAME="miningproxy"
BUILD_DIR="build"

echo "=== 开始编译 ${BINARY_NAME} v${VERSION} ==="

# 创建构建目录
mkdir -p ${BUILD_DIR}

# 编译函数
build() {
    local os=$1
    local arch=$2
    local output=$3
    
    echo "正在编译: ${os}/${arch} -> ${BUILD_DIR}/${output}"
    GOOS=${os} GOARCH=${arch} go build -ldflags="-s -w" -o ${BUILD_DIR}/${output} .
    
    if [ $? -ne 0 ]; then
        echo "编译失败: ${os}/${arch}"
        return 1
    fi
    
    # 对非macOS平台使用UPX压缩
    if [[ $os != "darwin" ]]; then
        echo "压缩二进制文件: ${BUILD_DIR}/${output}"
        upx --best ${BUILD_DIR}/${output} || true
    fi
    
    echo "编译成功: ${output}"
    return 0
}

# 各平台编译
build linux amd64 ${BINARY_NAME}_linux_amd64
build linux arm64 ${BINARY_NAME}_linux_arm64
build linux arm ${BINARY_NAME}_linux_arm  # 修正: 从 linux/arm/arm 改为 linux/arm
build windows amd64 ${BINARY_NAME}_windows_amd64.exe
build windows 386 ${BINARY_NAME}_windows_386.exe
build darwin amd64 ${BINARY_NAME}_darwin_amd64
build darwin arm64 ${BINARY_NAME}_darwin_arm64
build freebsd amd64 ${BINARY_NAME}_freebsd_amd64

echo "=== 编译完成 ==="
echo "编译结果保存在: $(pwd)/${BUILD_DIR}/"
ls -la ${BUILD_DIR}