package main

import (
	"bufio"
	"bytes"
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
	activeConnections int64
	totalConnections  int64
	bytesIn           int64
	bytesOut          int64
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
			in := atomic.LoadInt64(&s.bytesIn)
			out := atomic.LoadInt64(&s.bytesOut)

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

// 改进startServer函数，增加TCP优化（跨平台兼容）
func startServer(server Server, cert tls.Certificate) {
	addr := fmt.Sprintf("0.0.0.0:%d", server.Port)

	// 创建监听器时设置TCP参数
	config := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// 禁用Nagle算法
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)

				// 设置更大的接收缓冲区
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024)

				// 设置更大的发送缓冲区
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4*1024*1024)

				// 注：去除了TCP_FASTOPEN设置，因为它不是所有平台都支持
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

// 改进handleConnection函数，优化数据传输
func handleConnection(clientConn net.Conn, server Server, serverStats *Stats) {
	defer func() {
		clientConn.Close()
		atomic.AddInt64(&serverStats.activeConnections, -1)
	}()

	// 设置客户端连接超时
	clientConn.SetDeadline(time.Now().Add(10 * time.Second))

	// 使用多个并发连接到矿池以提高性能
	poolConn, err := net.DialTimeout("tcp", server.Pool.Host, 5*time.Second)
	if err != nil {
		return
	}
	defer poolConn.Close()

	// 设置矿池连接的TCP选项
	if tcpConn, ok := poolConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(60 * time.Second)
		tcpConn.SetNoDelay(true)
		tcpConn.SetReadBuffer(128 * 1024)  // 增加读缓冲区
		tcpConn.SetWriteBuffer(128 * 1024) // 增加写缓冲区
	}

	// 设置矿池连接超时
	poolConn.SetDeadline(time.Now().Add(10 * time.Second))

	// 双向复制数据
	var wg sync.WaitGroup
	wg.Add(2)

	// 用于识别worker的变量
	var workerName string
	var workerIdentified bool
	workerMutex := &sync.Mutex{}

	// 客户端 -> 矿池
	go func() {
		defer wg.Done()

		// 创建一个带缓冲的读取器
		reader := bufio.NewReaderSize(clientConn, 32*1024) // 增加到32K

		for {
			// 扩展读取超时
			clientConn.SetDeadline(time.Now().Add(120 * time.Second))

			// 读取一行数据
			line, err := reader.ReadBytes('\n')
			if err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
					// 只处理非EOF非关闭连接错误
				}
				break
			}

			// 更新读取的字节数
			atomic.AddInt64(&serverStats.bytesIn, int64(len(line)))

			// worker识别逻辑
			if !workerIdentified {
				if bytes.Contains(line, []byte("mining.authorize")) ||
					bytes.Contains(line, []byte("mining.subscribe")) {
					var request StratumRequest
					if err := json.Unmarshal(line, &request); err == nil {
						if (request.Method == "mining.authorize" || request.Method == "mining.subscribe") && len(request.Params) > 0 {
							if workerStr, ok := request.Params[0].(string); ok {
								workerMutex.Lock()
								workerName = workerStr
								workerIdentified = true
								workerMutex.Unlock()
							}
						}
					}
				}
			}

			// 扩展写入超时
			poolConn.SetDeadline(time.Now().Add(5 * time.Second))

			// 将数据转发到矿池
			_, err = poolConn.Write(line)
			if err != nil {
				break
			}
		}

		// 当客户端断开时，关闭矿池连接的写入端
		if conn, ok := poolConn.(*net.TCPConn); ok {
			conn.CloseWrite()
		}
	}()

	// 矿池 -> 客户端，使用更大的缓冲区
	go func() {
		defer wg.Done()

		// 从池中获取缓冲区
		buffer := bufferPool.Get().([]byte)
		defer bufferPool.Put(buffer)

		for {
			// 扩展读取超时
			poolConn.SetDeadline(time.Now().Add(120 * time.Second))

			n, err := poolConn.Read(buffer)
			if err != nil {
				break
			}

			// 更新读取的字节数
			atomic.AddInt64(&serverStats.bytesOut, int64(n))

			// 扩展写入超时
			clientConn.SetDeadline(time.Now().Add(5 * time.Second))

			_, err = clientConn.Write(buffer[:n])
			if err != nil {
				break
			}
		}

		// 当矿池断开时，关闭客户端连接的写入端
		if conn, ok := clientConn.(*net.TCPConn); ok {
			conn.CloseWrite()
		}
	}()

	// 等待两个方向的数据传输完成
	wg.Wait()

	workerMutex.Lock()
	workerInfo := workerName
	workerMutex.Unlock()

	if workerInfo != "" {
		log.Printf("连接已关闭 - %s - Worker: %s", server.Name, workerInfo)
	} else {
		log.Printf("连接已关闭 - %s - Worker: 未识别", server.Name)
	}
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
