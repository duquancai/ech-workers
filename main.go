package main

import (
	"flag"
	"log"

	"ech-workers/config"
	"ech-workers/ech"
	"ech-workers/proxy"
	"ech-workers/websocket"
)

func main() {
	cfg := &config.Config{}

	flag.StringVar(&cfg.ListenAddr, "l", "127.0.0.1:30000", "代理监听地址 (支持SOCKS5和HTTP)")
	flag.StringVar(&cfg.ServerAddr, "f", "", "服务端地址 (格式: x.x.workers.dev:443)")
	flag.StringVar(&cfg.ServerIP, "ip", "", "指定服务端IP（绕过DNS解析）")
	flag.StringVar(&cfg.Token, "token", "", "身份验证令牌")
	flag.StringVar(&cfg.DNSServer, "dns", "dns.alidns.com/dns-query", "ECH查询DoH服务器")
	flag.StringVar(&cfg.ECHDomain, "ech", "cloudflare-ech.com", "ECH查询域名")
	flag.StringVar(&cfg.ProxyIP, "pyip", "", "代理服务器IP（用于Worker连接回退，proxyip）")

	flag.Parse()

	if err := cfg.Validate(); err != nil {
		log.Fatalf("配置错误: %v", err)
	}

	if cfg.ServerAddr == "" {
		log.Fatal("必须指定服务端地址 -f\n\n示例:\n  ./ech-win -l 127.0.0.1:1080 -f your-worker.workers.dev:443 -token your-token")
	}

	// 初始化ECH管理器
	echManager := ech.NewECHManager(cfg.ECHDomain, cfg.DNSServer)

	log.Printf("[启动] 正在获取ECH配置...")
	if err := echManager.Prepare(); err != nil {
		log.Fatalf("[启动] 获取ECH配置失败: %v", err)
	}

	// 初始化WebSocket客户端
	wsClient := websocket.NewWebSocketClient(cfg.ServerAddr, cfg.Token, echManager, cfg.ServerIP)

	// 初始化代理服务器
	proxyServer := proxy.NewProxyServer(cfg.ListenAddr, wsClient, cfg.ProxyIP)

	log.Printf("[代理] 后端服务器: %s", cfg.ServerAddr)
	if cfg.ServerIP != "" {
		log.Printf("[代理] 使用固定IP: %s", cfg.ServerIP)
	}

	// 运行代理服务器
	if err := proxyServer.Run(); err != nil {
		log.Fatalf("[代理] 运行失败: %v", err)
	}
}
