#!/usr/bin/env bash
# Koyun WARP Relay 控制端安装 / 升级脚本（节点 Agent 由面板生成的一键命令安装，不用本脚本）
#   用法：sudo ./install.sh [二进制路径] [面板监听地址]
#   例：  sudo ./install.sh ./koyun-warp 127.0.0.1:18991   # 配合 Caddy/Nginx 反代
# 同目录下若有 koyun-warp-linux-arm64，会一并装到 bin/，供 ARM 节点下载 Agent。
# 迁移：先停旧机服务，再把旧机 /opt/koyun-warp/data 整个拷到新机同路径后执行本脚本。
set -euo pipefail

BIN=${1:-./koyun-warp}
LISTEN=${2:-0.0.0.0:18991}
PREFIX=/opt/koyun-warp

[[ $EUID -eq 0 ]] || { echo "请用 root 运行" >&2; exit 1; }
[[ -x $BIN ]] || { echo "找不到可执行文件 $BIN" >&2; exit 1; }

install -d -m 755 "$PREFIX"
install -d -m 700 "$PREFIX/data"
systemctl stop koyun-warp 2>/dev/null || true
install -m 755 "$BIN" "$PREFIX/koyun-warp"
ARM="$(dirname "$BIN")/koyun-warp-linux-arm64"
if [[ -f $ARM ]]; then
  install -d -m 755 "$PREFIX/bin"
  install -m 755 "$ARM" "$PREFIX/bin/koyun-warp-linux-arm64"
fi
ln -sf "$PREFIX/koyun-warp" /usr/local/bin/koyun-warp

cat > /etc/systemd/system/koyun-warp.service <<EOF
[Unit]
Description=Koyun WARP Relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$PREFIX/koyun-warp -listen $LISTEN -data $PREFIX/data
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=$PREFIX/data

[Install]
WantedBy=multi-user.target
EOF

# 大量并发转发时放宽内核缓冲区
cat > /etc/sysctl.d/90-koyun-warp.conf <<'EOF'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_fastopen = 3
EOF
sysctl -q --system || true

systemctl daemon-reload
systemctl enable --now koyun-warp
sleep 2
systemctl --no-pager --lines=5 status koyun-warp || true
if [[ -f $PREFIX/data/initial-password.txt ]]; then
  echo; echo "初始管理员凭据："; cat "$PREFIX/data/initial-password.txt"
fi
echo; echo "面板：http://$(hostname -I | awk '{print $1}'):${LISTEN##*:}/"
echo "如启用了防火墙，请放行面板端口与系统设置中的转发端口范围（默认 20000-29999 TCP/UDP）。"
