#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-hosts-app}"

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
APP_PATH="${APP_PATH:-$SCRIPT_DIR/app}"
WORKDIR="${WORKDIR:-$SCRIPT_DIR}"

SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
TIMER_FILE="/etc/systemd/system/${SERVICE_NAME}.timer"

# --- 检查 app 是否存在 ---
if [[ ! -f "$APP_PATH" ]]; then
  echo "ERROR: 未找到可执行文件: $APP_PATH"
  exit 1
fi

if [[ ! -x "$APP_PATH" ]]; then
  echo "==> 自动添加执行权限"
  chmod +x "$APP_PATH"
fi

# --- 写入 service ---
echo "==> 生成 service: $SERVICE_FILE"
sudo tee "$SERVICE_FILE" >/dev/null <<'EOF'
[Unit]
Description=Run hosts_repo app once

[Service]
Type=oneshot
ExecStart=/home/zws/hosts_repo/app
WorkingDirectory=/home/zws/hosts_repo
StandardOutput=journal
StandardError=journal
EOF

# --- 写入 timer ---
# 东八区 05:00 对应 UTC 前一天 21:00
echo "==> 生成 timer: $TIMER_FILE"
sudo tee "$TIMER_FILE" >/dev/null <<EOF
[Unit]
Description=Daily run for hosts_repo app (UTC schedule)

[Timer]
OnCalendar=*-*-* 21:00:00
TimeZone=UTC
Persistent=true

[Install]
WantedBy=timers.target
EOF

echo "==> 重载 systemd"
sudo systemctl daemon-reload

echo "==> 启用 & 启动定时器"
sudo systemctl enable --now "${SERVICE_NAME}.timer"

echo "==> 状态："
systemctl status "${SERVICE_NAME}.timer"
