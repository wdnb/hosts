#!/usr/bin/env bash
set -euo pipefail

# ================================
#  基础设置（可覆盖）
# ================================
SERVICE_NAME="${SERVICE_NAME:-hosts-app}"
APP_PATH="${APP_PATH:-$(realpath "$(dirname "$0")")/app"}"
WORKDIR="${WORKDIR:-$(realpath "$(dirname "$0")")}"

SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
TIMER_FILE="/etc/systemd/system/${SERVICE_NAME}.timer"

# ================================
#  检查必要文件
# ================================
if [[ ! -f "$APP_PATH" ]]; then
  echo "ERROR: 可执行文件不存在: $APP_PATH"
  exit 1
fi

if [[ ! -x "$APP_PATH" ]]; then
  echo "==> app 不可执行，自动赋予执行权限"
  chmod +x "$APP_PATH"
fi

# ================================
#  创建 Service
# ================================
echo "==> 写入 service: $SERVICE_FILE"
sudo tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=Run hosts_repo app once

[Service]
Type=oneshot
ExecStart=${APP_PATH}
WorkingDirectory=${WORKDIR}
StandardOutput=journal
StandardError=journal
EOF

# ================================
#  创建 Timer
# ================================
echo "==> 写入 timer: $TIMER_FILE"
sudo tee "$TIMER_FILE" >/dev/null <<EOF
[Unit]
Description=Daily run for hosts_repo app

[Timer]
#东八区 05:00 对应的 UTC 时间是：前一天 21:00（UTC 21:00）。
OnCalendar=*-*-* 21:00:00
Timezone=UTC
Persistent=true

[Install]
WantedBy=timers.target
EOF

# ================================
#  启动 systemd
# ================================
echo "==> 重新加载 systemd"
sudo systemctl daemon-reload

echo "==> 启用并启动定时器"
sudo systemctl enable --now "${SERVICE_NAME}.timer"

echo "==> Timer 状态："
systemctl status "${SERVICE_NAME}.timer"