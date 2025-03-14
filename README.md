# MiningProxy

## 项目简介

MiningProxy是一个高性能挖矿代理工具，用于优化矿工与矿池之间的连接，提供更稳定的挖矿体验和更高效的数据传输。

## 功能特点

- 支持多种主流挖矿协议
- 低延迟数据转发
- 断线自动重连
- 详细的日志记录
- 支持多平台（Windows, Linux, macOS等）
- 防拒绝服务攻击
- 矿工数据统计
- 支持加密连接

## 系统要求

- 64位操作系统
- 最小内存: 1GB
- 推荐网络带宽: 100Mbps以上

## 安装方法

### 预编译版本

从GitHub发布页面下载适合您系统的预编译版本，解压后即可使用。

### 从源码编译

```bash
git clone https://github.com/Boos4721/miningproxy.git
cd miningproxy
go mod tidy
./build.sh
```

## 快速开始

1. 创建配置文件`config.yaml`:

```yaml
listen: 0.0.0.0:9999
upstream: eth.pool.com:4444
log_level: info
worker_prefix: worker
```

2. 启动代理:

```bash
./miningproxy -config config.yaml
```

3. 配置您的挖矿软件，将其指向MiningProxy的地址和端口。

## 配置选项

| 参数 | 说明 | 默认值 |
|------|------|--------|
| listen | 本地监听地址 | 0.0.0.0:9999 |
| upstream | 上游矿池地址 | - |
| log_level | 日志级别(debug/info/warn/error) | info |
| worker_prefix | 矿工名前缀 | worker |
| max_connections | 最大连接数 | 1000 |
| connection_timeout | 连接超时(秒) | 30 |
| ssl | 是否启用SSL | false |
| ssl_cert | SSL证书路径 | - |
| ssl_key | SSL密钥路径 | - |

## 常见问题

1. **连接被拒绝**: 检查防火墙设置和端口是否开放
2. **高延迟**: 尝试使用更靠近您地理位置的上游矿池
3. **内存占用过高**: 调整最大连接数参数

## 贡献代码

欢迎提交Pull Request或Issue，帮助改进MiningProxy项目。

## 许可证

本项目采用MIT许可证，详见LICENSE文件。
