package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var version = "2.1.3"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "agent" {
		runAgent(os.Args[2:])
		return
	}
	listen := flag.String("listen", "0.0.0.0:18991", "面板监听地址")
	dataDir := flag.String("data", "/opt/koyun-warp/data", "数据目录")
	resetPw := flag.Bool("reset-password", false, "重置管理员密码并退出")
	showVer := flag.Bool("version", false, "显示版本")
	flag.Parse()
	if *showVer {
		fmt.Println("koyun-warp", version)
		return
	}

	store, fresh, err := OpenStore(*dataDir)
	if err != nil {
		log.Fatalf("打开数据目录失败: %v", err)
	}
	if fresh || *resetPw || store.S.Settings.AdminHash == "" {
		pw := randHex(8)
		h, _ := bcrypt.GenerateFromPassword([]byte(pw), 12)
		store.Update(func(st *State) error {
			if st.Settings.AdminUser == "" {
				st.Settings.AdminUser = "admin"
			}
			st.Settings.AdminHash = string(h)
			return nil
		})
		f := filepath.Join(*dataDir, "initial-password.txt")
		os.WriteFile(f, []byte(fmt.Sprintf("用户名: %s\n密码: %s\n", store.S.Settings.AdminUser, pw)), 0600)
		log.Printf("管理员账号 %s / %s（已写入 %s，登录后请修改）", store.S.Settings.AdminUser, pw, f)
		if *resetPw {
			return
		}
	}

	app := NewApp(store)
	app.metrics.Load(*dataDir)
	app.Boot()
	app.event("info", "Koyun WARP Relay 控制端 %s 已启动", version)

	srv := &http.Server{Addr: *listen, Handler: app.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("面板监听 %s", *listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	app.Shutdown()
	log.Print("已退出")
}

// runAgent 运行节点 Agent。控制端地址从环境变量 KW_SERVER 读取；令牌优先读数据目录里的
// token 文件，其次 KW_TOKEN（旧版安装），都没有时用 KW_INSTALL 安装凭证向控制端注册换取。
// 凭证不放在命令行参数里，避免出现在 ps 输出中。
func runAgent(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	dataDir := fs.String("data", "/var/lib/koyun-warp-agent", "Agent 数据目录（令牌与配置缓存）")
	fs.Parse(args)
	server := os.Getenv("KW_SERVER")
	if server == "" {
		log.Fatal("缺少环境变量 KW_SERVER")
	}
	if err := os.MkdirAll(*dataDir, 0700); err != nil {
		log.Fatal(err)
	}
	log.Printf("Koyun WARP Agent %s，控制端 %s", version, server)
	tokenFile := filepath.Join(*dataDir, "token")
	token := ""
	if b, err := os.ReadFile(tokenFile); err == nil {
		token = strings.TrimSpace(string(b))
	}
	if token == "" {
		token = os.Getenv("KW_TOKEN")
	}
	if token == "" {
		inst := os.Getenv("KW_INSTALL")
		if inst == "" {
			log.Fatal("没有 Agent 令牌，也没有安装凭证 KW_INSTALL，请在面板重新生成安装命令")
		}
		for {
			t, err := registerAgent(server, inst)
			if err == nil {
				token = t
				break
			}
			log.Printf("注册失败：%v（10 秒后重试）", err)
			time.Sleep(10 * time.Second)
		}
		if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
			log.Fatalf("保存令牌失败：%v", err)
		}
		log.Print("已向控制端注册，令牌已保存")
	}
	ag := NewAgent(server, token, *dataDir)
	go ag.Run()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Print("Agent 已退出")
}
