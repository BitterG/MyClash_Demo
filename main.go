// mini-clash：一个从零手写的 Clash 内核教学实现。
//
// 这是项目的唯一入口：加载配置 → 装配内核 → 启动监听 → 阻塞等待信号。
// 对应真实 Clash 的 main.go：main → hub.ParseHub → 启动。
package main

import (
	"bufio"
	"fmt"
	"mini-clash/internal/outboundgroup"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"mini-clash/internal/config"
	"mini-clash/internal/hub"
	"mini-clash/internal/log"
)

func main() {
	cfgPath := "config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Errorln("load config:", err)
		os.Exit(1)
	}

	h, err := hub.New(cfg)
	if err != nil {
		log.Errorln("build hub:", err)
		os.Exit(1)
	}
	h.LogConfig()

	if err := h.Start(); err != nil {
		log.Errorln("start listener:", err)
		os.Exit(1)
	}

	fmt.Println("mini-clash is running. Press Ctrl+C to stop.")

	// 简单控制台：输入 "set 组名 节点名" 切换
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) == 3 && fields[0] == "set" {
				if a, ok := h.Router.Adapter(fields[1]).(*outboundgroup.Selector); ok {
					if a.Set(fields[2]) {
						fmt.Println("switched", fields[1], "->", fields[2])
					} else {
						fmt.Println("node not found:", fields[2])
					}
				} else {
					fmt.Println("group not found:", fields[1])
				}
			}
		}
	}()

	// 等待 Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	log.Infoln("shutting down...")
	_ = h.Close()
}
