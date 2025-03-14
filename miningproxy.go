package main

import (
	"bufio"
	"bytes"
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

// 缓冲区对象池
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 16*1024) // 16KB缓冲区
	},
}

var (
	stats    = make(map[string]*Stats)
	statsMux sync.RWMutex
)

func main() {
	// 设置GOMAXPROCS为CPU核心数
	runtime.GOMAXPROCS(runtime.NumCPU())

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

// 启动服务器
func startServer(server Server, cert tls.Certificate) {
	addr := fmt.Sprintf("0.0.0.0:%d", server.Port)
	// log.Printf("启动服务 %s 在端口 %d, SSL模式: %v", server.Name, server.Port, server.IsSSL)

	// 创建监听器
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
		}
		listener, err = tls.Listen("tcp", addr, tlsConfig)
	} else {
		listener, err = net.Listen("tcp", addr)
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
				// 临时错误，稍后重试
				time.Sleep(5 * time.Millisecond)
				continue
			}
			log.Printf("接受连接失败: %v", err)
			break
		}

		// 更新统计信息
		atomic.AddInt64(&serverStats.activeConnections, 1)
		atomic.AddInt64(&serverStats.totalConnections, 1)

		// 设置连接的超时时间
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(60 * time.Second)
			tcpConn.SetNoDelay(true)
		}

		go handleConnection(conn, server, serverStats)
	}
}

func handleConnection(clientConn net.Conn, server Server, serverStats *Stats) {
	clientAddr := clientConn.RemoteAddr().String()
	log.Printf("新连接: %s -> %s", clientAddr, server.Name)

	// 确保连接最终会关闭，并更新统计信息
	defer func() {
		clientConn.Close()
		atomic.AddInt64(&serverStats.activeConnections, -1)
	}()

	// 设置客户端连接超时
	clientConn.SetDeadline(time.Now().Add(10 * time.Second))

	// 连接到实际的矿池
	poolConn, err := net.DialTimeout("tcp", server.Pool.Host, 5*time.Second)
	if err != nil {
		log.Printf("连接到矿池 %s 失败: %v", server.Pool.Host, err)
		return
	}
	defer poolConn.Close()

	// 设置矿池连接超时
	poolConn.SetDeadline(time.Now().Add(10 * time.Second))

	log.Printf("成功连接到矿池: %s", server.Pool.Host)

	// 用于识别worker的变量
	var workerName string
	var workerIdentified bool
	workerMutex := &sync.Mutex{}

	// 双向复制数据
	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 -> 矿池，同时尝试解析worker name
	go func() {
		defer wg.Done()

		// 创建一个带缓冲的读取器
		reader := bufio.NewReaderSize(clientConn, 16*1024)

		for {
			// 扩展读取超时
			clientConn.SetDeadline(time.Now().Add(120 * time.Second))

			// 读取一行数据
			line, err := reader.ReadBytes('\n')
			if err != nil {
				if err != io.EOF {
					// 只记录非EOF错误
					if !strings.Contains(err.Error(), "use of closed network connection") {
						log.Printf("从客户端读取错误: %v", err)
					}
				}
				break
			}

			// 更新读取的字节数
			atomic.AddInt64(&serverStats.bytesIn, int64(len(line)))

			// 如果尚未识别worker
			if !workerIdentified {
				// 只解析可能含有worker信息的请求
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
								log.Printf("矿工连接成功: %s - Worker: %s", server.Name, workerStr)
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
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("向矿池写入错误: %v", err)
				}
				break
			}
		}

		// 当客户端断开时，关闭矿池连接的写入端
		if conn, ok := poolConn.(*net.TCPConn); ok {
			conn.CloseWrite()
		}
	}()

	// 矿池 -> 客户端
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
				if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("从矿池读取错误: %v", err)
				}
				break
			}

			// 更新读取的字节数
			atomic.AddInt64(&serverStats.bytesOut, int64(n))

			// 扩展写入超时
			clientConn.SetDeadline(time.Now().Add(5 * time.Second))

			_, err = clientConn.Write(buffer[:n])
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("向客户端写入错误: %v", err)
				}
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
