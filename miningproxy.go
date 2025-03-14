package main

import (
	"bufio"
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

// 改进的 MiningMessage 结构体，支持更多挖矿协议格式
type MiningMessage struct {
	Id      int             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Worker  string          `json:"worker"`  // 有些协议直接使用worker字段
	JsonRpc string          `json:"jsonrpc"` // 用于识别协议版本
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

	// 设置日志
	setupLogging()

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

	// 确保只有一个统计信息打印循环
	statsTimer := time.NewTimer(10 * time.Second)
	go func() {
		for {
			<-statsTimer.C
			printStats()
			statsTimer.Reset(10 * time.Second)
		}
	}()

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

// 修改setupLogging函数，不使用logs文件夹
func setupLogging() {
	// 创建日志文件，使用日期作为文件名，直接放在当前目录
	currentTime := time.Now()
	logFileName := fmt.Sprintf("miningproxy-%s.log", currentTime.Format("2006-01-02"))

	// 打开日志文件
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("无法创建日志文件: %v, 将使用标准输出", err)
		return
	}

	// 设置日志输出到文件和控制台
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)

	// 设置日志格式
	log.SetFlags(log.Ldate | log.Ltime)

	log.Printf("日志系统初始化完成，日志文件: %s", logFileName)
}

// 修改printStats函数，避免重复信息并只显示有用的统计
func printStats() {
	statsMux.RLock()
	defer statsMux.RUnlock()

	var statsBuffer strings.Builder
	statsBuffer.WriteString("=== 服务器统计信息 ===\n")

	// 记录显示的服务器
	shownServers := make(map[string]bool)
	anyServerShown := false

	// 首先显示有活跃连接的服务器
	for name, s := range stats {
		active := atomic.LoadInt64(&s.activeConnections)

		if active > 0 && !shownServers[name] {
			anyServerShown = true
			shownServers[name] = true

			statsBuffer.WriteString(fmt.Sprintf("%s: 活跃连接: %d, 总连接: %d, 流入: %s, 流出: %s\n",
				name,
				active,
				atomic.LoadInt64(&s.totalConnections),
				formatBytes(atomic.LoadInt64(&s.bytesReceived)),
				formatBytes(atomic.LoadInt64(&s.bytesSent))))
		}
	}

	// 然后显示历史有过连接但当前无活跃连接的服务器
	for name, s := range stats {
		active := atomic.LoadInt64(&s.activeConnections)
		total := atomic.LoadInt64(&s.totalConnections)

		if active == 0 && total > 0 && !shownServers[name] {
			anyServerShown = true
			shownServers[name] = true

			statsBuffer.WriteString(fmt.Sprintf("%s: 活跃连接: %d, 总连接: %d, 流入: %s, 流出: %s\n",
				name,
				active,
				total,
				formatBytes(atomic.LoadInt64(&s.bytesReceived)),
				formatBytes(atomic.LoadInt64(&s.bytesSent))))
		}
	}

	if !anyServerShown {
		statsBuffer.WriteString("当前没有任何服务器有连接记录\n")
	}

	// 使用log.Print输出到日志
	log.Print(statsBuffer.String())
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

// 修改 handleConnection 函数，提升 workerName 的可见性
func handleConnection(clientConn net.Conn, server Server, serverStats *Stats) {
	var poolConn net.Conn
	workerName := "未识别" // 默认worker名为未识别

	// 记录客户端连接信息
	clientAddr := clientConn.RemoteAddr().String()
	log.Printf("新连接 - %s - 来自: %s", server.Name, clientAddr)

	defer func() {
		clientConn.Close()
		if poolConn != nil {
			poolConn.Close()
		}
		atomic.AddInt64(&serverStats.activeConnections, -1)

		// 记录连接断开，包括worker信息（如果有）
		if workerName != "未识别" {
			log.Printf("连接断开 - %s - Worker: %s", server.Name, workerName)
		} else {
			log.Printf("连接断开 - %s - 来自: %s", server.Name, clientAddr)
		}
	}()

	// 连接到上游矿池
	var err error
	poolConn, err = net.Dial("tcp", server.Pool.Host)
	if err != nil {
		log.Printf("连接上游矿池失败: %v", err)
		atomic.AddInt64(&serverStats.networkErrors, 1)
		return
	}

	// 记录连接到矿池成功
	log.Printf("已连接到矿池 - %s -> %s", server.Name, server.Pool.Host)

	// 设置TCP选项
	if tcpConn, ok := poolConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(60 * time.Second)
		tcpConn.SetNoDelay(true)
		tcpConn.SetReadBuffer(128 * 1024)
		tcpConn.SetWriteBuffer(128 * 1024)
	}

	// 创建用于传递数据的通道
	clientToPool := make(chan []byte, 100)
	poolToClient := make(chan []byte, 100)
	done := make(chan bool, 2)

	// 读取客户端数据
	go func() {
		defer func() {
			done <- true
		}()

		// 移除未使用的buf变量
		bufReader := bufio.NewReader(clientConn)

		for {
			// 尝试按行读取（因为很多挖矿协议是基于行的JSON）
			data, err := bufReader.ReadBytes('\n')
			if err != nil {
				if err != io.EOF {
					log.Printf("读取客户端数据错误: %v", err)
				}
				break
			}

			// 尝试解析worker名称
			newWorker := parseWorkerName(data)
			if newWorker != "" {
				workerName = newWorker
				log.Printf("识别到Worker: %s - %s", workerName, server.Name)
			}

			// 发送数据到矿池
			clientToPool <- data
		}
	}()

	// 读取矿池数据
	go func() {
		defer func() {
			done <- true
		}()

		buf := make([]byte, 8192)
		for {
			n, err := poolConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("读取矿池数据错误: %v", err)
				}
				break
			}

			data := make([]byte, n)
			copy(data, buf[:n])
			poolToClient <- data
		}
	}()

	// 写入数据到矿池
	go func() {
		for data := range clientToPool {
			_, err := poolConn.Write(data)
			if err != nil {
				log.Printf("写入矿池数据错误: %v", err)
				break
			}
			atomic.AddInt64(&serverStats.bytesSent, int64(len(data)))
		}

		// 安全地关闭写入方向
		safeCloseWrite(poolConn)
	}()

	// 写入数据到客户端
	go func() {
		for data := range poolToClient {
			_, err := clientConn.Write(data)
			if err != nil {
				log.Printf("写入客户端数据错误: %v", err)
				break
			}
			atomic.AddInt64(&serverStats.bytesReceived, int64(len(data)))
		}

		// 安全地关闭写入方向
		safeCloseWrite(clientConn)
	}()

	// 等待任一方向的连接关闭
	<-done
	// 关闭通道，触发写入goroutine退出
	close(clientToPool)
	close(poolToClient)
	// 等待另一个读取goroutine结束
	<-done
}

// 改进的worker名称解析函数
func parseWorkerName(data []byte) string {
	// 日志记录收到的数据，便于排查问题（仅在调试模式下使用）
	// log.Printf("收到数据: %s", string(data))

	// 跳过非JSON数据
	if len(data) < 2 || data[0] != '{' {
		return ""
	}

	// 先尝试标准的Stratum协议格式
	var message MiningMessage
	if err := json.Unmarshal(data, &message); err != nil {
		// 不是有效的JSON，跳过
		return ""
	}

	// 检查是否有直接的worker字段
	if message.Worker != "" {
		return message.Worker
	}

	// 根据不同的挖矿协议方法提取worker名称
	if message.Method == "mining.authorize" || message.Method == "eth_submitLogin" ||
		message.Method == "login" || message.Method == "mining.submit" {

		// 尝试各种不同格式的参数解析
		// 1. 字符串数组格式 ["user.worker"]
		var stringParams []string
		if err := json.Unmarshal(message.Params, &stringParams); err == nil && len(stringParams) > 0 {
			return extractWorkerName(stringParams[0])
		}

		// 2. 对象格式 {"login": "user.worker"}
		var objParams map[string]interface{}
		if err := json.Unmarshal(message.Params, &objParams); err == nil {
			// 检查常见的登录字段
			for _, key := range []string{"login", "user", "username", "worker"} {
				if val, ok := objParams[key].(string); ok && val != "" {
					return extractWorkerName(val)
				}
			}
		}

		// 3. 单个字符串格式 "user.worker"
		var singleParam string
		if err := json.Unmarshal(message.Params, &singleParam); err == nil && singleParam != "" {
			return extractWorkerName(singleParam)
		}
	}

	// 没有识别到worker
	return ""
}

// 从登录字符串中提取worker名称
func extractWorkerName(loginStr string) string {
	// 处理常见的格式：wallet.worker 或 username.worker
	parts := strings.Split(loginStr, ".")
	if len(parts) > 1 {
		return parts[len(parts)-1] // 取最后一部分作为worker名
	}

	// 处理wallet/worker格式
	parts = strings.Split(loginStr, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}

	// 如果没有特殊分隔符，直接返回整个字符串
	return loginStr
}

// 安全地关闭连接的写入方向，支持不同类型的连接
func safeCloseWrite(conn net.Conn) {
	// 检查是否为TCP连接
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.CloseWrite()
		return
	}

	// 检查是否为TLS连接
	if tlsConn, ok := conn.(*tls.Conn); ok {
		// TLS连接不能直接CloseWrite，但可以获取底层连接
		if netConn, ok := tlsConn.NetConn().(*net.TCPConn); ok {
			netConn.CloseWrite()
			return
		}
	}

	// 如果不是特定类型，仅记录但不执行特殊关闭操作
	// 连接会在defer中完全关闭
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
