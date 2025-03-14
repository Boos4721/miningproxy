package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// 配置结构体
type Config struct {
	Cert    string   `yaml:"cert"`
	Key     string   `yaml:"key"`
	Servers []Server `yaml:"servers"`
}

type Server struct {
	Name  string `yaml:"name"`
	Port  int    `yaml:"port"`
	IsSSL bool   `yaml:"is_ssl"`
	Coin  string `yaml:"coin"`
	Pool  Pool   `yaml:"pool"`
}

type Pool struct {
	Host string `yaml:"host"`
}

// 连接统计
type Stats struct {
	activeConnections   int64
	totalConnections    int64
	acceptedShares      int64
	rejectedShares      int64
	invalidShares       int64
	networkErrors       int64
	lastConnectionTime  time.Time
	bytesReceived       int64
	bytesSent           int64
	startTime           time.Time
	lastShareSubmitTime time.Time
	mutex               sync.RWMutex
}

// Stratum协议相关结构
type StratumRequest struct {
	Id     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params []interface{}   `json:"params"`
}

// 缓冲区对象池的大小增加到32KB以提高效率
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024) // 32KB缓冲区
	},
}

// 添加连接信号量控制并发
var (
	stats     = make(map[string]*Stats)
	statsMux  sync.RWMutex
	connLimit = make(chan struct{}, 20000) // 限制最大20000个并发连接
)

func main() {
	// 设置GOMAXPROCS为CPU核心数的两倍，充分利用CPU
	runtime.GOMAXPROCS(runtime.NumCPU() * 2)

	// 读取配置文件
	configData, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatalf("无法读取配置文件: %v", err)
		return
	}

	var config Config
	if err := yaml.Unmarshal(configData, &config); err != nil {
		log.Fatalf("解析配置文件失败: %v", err)
		return
	}

	// 为每个服务器初始化统计信息
	for _, server := range config.Servers {
		statsMux.Lock()
		stats[server.Name] = &Stats{}
		statsMux.Unlock()
	}

	// 加载TLS证书
	var cert tls.Certificate
	if config.Cert != "" && config.Key != "" {
		cert, err = tls.LoadX509KeyPair(config.Cert, config.Key)
		if err != nil {
			log.Fatalf("加载证书失败: %v", err)
		}
	}

	// 从证书路径中提取域名
	domain := extractDomainFromCert(config.Cert)
	if domain == "" {
		// 如果无法从证书提取，使用默认域名
		domain = "pool.boos6.ggff.net"
	}

	// 首先展示所有矿池信息
	printPoolInfo(config.Servers, domain)

	// 启动统计信息报告
	go reportStats()

	// 然后启动所有服务器
	var wg sync.WaitGroup
	for _, server := range config.Servers {
		wg.Add(1)
		go func(s Server) {
			defer wg.Done()
			startServer(s, cert)
		}(server)
	}

	wg.Wait()
}

// 定期报告统计信息
func reportStats() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		statsMux.RLock()
		fmt.Println("\n=== 服务器统计信息 ===")
		for name, s := range stats {
			active := atomic.LoadInt64(&s.activeConnections)
			total := atomic.LoadInt64(&s.totalConnections)
			in := atomic.LoadInt64(&s.bytesReceived)
			out := atomic.LoadInt64(&s.bytesSent)

			fmt.Printf("%s: 活跃连接: %d, 总连接: %d, 流入: %s, 流出: %s\n",
				name, active, total, formatBytes(in), formatBytes(out))
		}
		statsMux.RUnlock()
	}
}

// 格式化字节数
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// 打印矿池信息
func printPoolInfo(servers []Server, domain string) {
	fmt.Println("\n矿池信息:")
	fmt.Println("==========================")

	for _, server := range servers {
		protocol := "stratum+tcp"
		if server.IsSSL {
			protocol = "stratum+ssl"
		}

		// 构建完整的矿池地址
		poolAddress := fmt.Sprintf("%s://%s:%d", protocol, domain, server.Port)

		// 按照用户要求的格式输出
		fmt.Printf("%s %s | 矿池地址 | %s\n", server.Name, server.Coin, poolAddress)
	}
}

// 修改打印统计信息的代码，只显示活跃连接
func printStats() {
	statsMux.RLock()
	defer statsMux.RUnlock()

	fmt.Println("=== 服务器统计信息 ===")
	activeServerFound := false

	for name, s := range stats {
		active := atomic.LoadInt64(&s.activeConnections)

		// 只显示有活跃连接的服务器
		if active > 0 {
			activeServerFound = true
			fmt.Printf("%s: 活跃连接: %d, 总连接: %d, 流入: %s, 流出: %s\n",
				name,
				active,
				atomic.LoadInt64(&s.totalConnections),
				formatBytes(atomic.LoadInt64(&s.bytesReceived)),
				formatBytes(atomic.LoadInt64(&s.bytesSent)))
		}
	}

	if !activeServerFound {
		fmt.Println("当前没有活跃连接")
	}
}

// 修改连接关闭的日志记录代码
func logConnectionClosed(serverName string, workerName string) {
	// 只记录已识别的worker连接关闭
	if workerName != "" && workerName != "未识别" {
		log.Printf("连接已关闭 - %s - Worker: %s", serverName, workerName)
	}
}

// 改进startServer函数，增加TCP优化（跨平台兼容）
func startServer(server Server, cert tls.Certificate) {
	addr := fmt.Sprintf("0.0.0.0:%d", server.Port)

	// 创建监听器时设置TCP参数
	config := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := setTCPSocketOptions(fd); err != nil {
					log.Printf("设置套接字选项失败: %v", err)
				}
			})
		},
	}

	var listener net.Listener
	var err error

	if server.IsSSL {
		// 优化的TLS配置
		tlsConfig := &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			SessionTicketsDisabled: false,
		}

		// 使用自定义的配置创建TCP Listener
		tcpListener, err := config.Listen(context.Background(), "tcp", addr)
		if err != nil {
			log.Printf("启动服务 %s 失败: %v", server.Name, err)
			return
		}

		listener = tls.NewListener(tcpListener, tlsConfig)
	} else {
		// 使用自定义的配置创建TCP Listener
		listener, err = config.Listen(context.Background(), "tcp", addr)
	}

	if err != nil {
		log.Printf("启动服务 %s 失败: %v", server.Name, err)
		return
	}
	defer listener.Close()

	// 获取统计对象
	statsMux.RLock()
	serverStats := stats[server.Name]
	statsMux.RUnlock()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			log.Printf("接受连接失败: %v", err)
			break
		}

		// 使用全局信号量控制并发连接数
		select {
		case connLimit <- struct{}{}:
			// 获取信号量成功，处理连接
			atomic.AddInt64(&serverStats.activeConnections, 1)
			atomic.AddInt64(&serverStats.totalConnections, 1)

			// 设置连接的超时时间
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(60 * time.Second)
				tcpConn.SetNoDelay(true)
				tcpConn.SetReadBuffer(128 * 1024)  // 增加读缓冲区
				tcpConn.SetWriteBuffer(128 * 1024) // 增加写缓冲区
			}

			go func() {
				handleConnection(conn, server, serverStats)
				// 完成后释放信号量
				<-connLimit
			}()
		default:
			// 连接数达到上限，关闭连接
			conn.Close()
			log.Printf("达到最大连接数限制，拒绝新连接")
		}
	}
}

// 修改handleConnection函数，完全移除worker识别和连接关闭日志
func handleConnection(clientConn net.Conn, server Server, serverStats *Stats) {
	var poolConn net.Conn

	defer func() {
		clientConn.Close()
		if poolConn != nil {
			poolConn.Close()
		}
		atomic.AddInt64(&serverStats.activeConnections, -1)
		// 不再记录连接关闭日志
	}()

	// 连接到上游矿池
	var err error
	poolConn, err = net.Dial("tcp", server.Pool.Host)
	if err != nil {
		// 只记录连接失败，不记录worker信息
		log.Printf("连接上游矿池失败: %v", err)
		atomic.AddInt64(&serverStats.networkErrors, 1)
		return
	}

	// 设置矿池连接的TCP选项
	if tcpConn, ok := poolConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(60 * time.Second)
		tcpConn.SetNoDelay(true)
		tcpConn.SetReadBuffer(128 * 1024)  // 增加读缓冲区
		tcpConn.SetWriteBuffer(128 * 1024) // 增加写缓冲区
	}

	// 数据转发部分不变
	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 -> 矿池
	go func() {
		defer wg.Done()
		n, err := io.Copy(poolConn, clientConn)
		if err != nil && err != io.EOF {
			// 只记录错误，不提及worker
			log.Printf("转发客户端数据到矿池失败: %v", err)
		}
		atomic.AddInt64(&serverStats.bytesReceived, n)
		poolConn.(*net.TCPConn).CloseWrite()
	}()

	// 矿池 -> 客户端
	go func() {
		defer wg.Done()
		n, err := io.Copy(clientConn, poolConn)
		if err != nil && err != io.EOF {
			// 只记录错误，不提及worker
			log.Printf("转发矿池数据到客户端失败: %v", err)
		}
		atomic.AddInt64(&serverStats.bytesSent, n)
		clientConn.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()
}

// 从证书路径中提取域名
func extractDomainFromCert(certPath string) string {
	// 获取证书文件名
	_, fileName := filepath.Split(certPath)

	// 移除扩展名
	fileName = strings.TrimSuffix(fileName, filepath.Ext(fileName))

	// 尝试提取域名部分
	parts := strings.Split(fileName, ".")
	if len(parts) >= 2 {
		return fileName
	}

	return ""
}
