#!/bin/bash

# 停止并禁用可能存在的旧服务
systemctl stop redirect_server.service 2>/dev/null
systemctl disable redirect_server.service 2>/dev/null

# 交互式获取运行参数
read -p "请输入 Master IP 地址 [例如: 47.242.7.162]: " MASTER_IP
read -p "请输入节点名称: " NODE_NAME

# 验证输入
if [ -z "$MASTER_IP" ]; then
    echo "错误：Master IP 不能为空！"
    exit 1
fi

if [ -z "$NODE_NAME" ]; then
    echo "错误：节点名称不能为空！"
    exit 1
fi

# 定义关键路径
EXECUTABLE_PATH="/root/redirect_server_https"
LOG_DIR="/var/log/redirect_server"
SERVICE_FILE="/etc/systemd/system/redirect_server.service"

# 检查可执行文件是否存在
if [ ! -f "$EXECUTABLE_PATH" ]; then
    echo "错误：可执行文件不存在于 $EXECUTABLE_PATH"
    echo "请确保 redirect_server_https 文件已上传到 /root/ 目录并具有执行权限"
    exit 1
fi

# 确保可执行文件有执行权限
chmod +x "$EXECUTABLE_PATH" 2>/dev/null

# 创建日志目录
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

# 创建 systemd 服务文件
cat > $SERVICE_FILE <<EOF
[Unit]
Description=Redirect Server HTTPS Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=$EXECUTABLE_PATH -s wwvip.ap220.com -t 443 --master-ip $MASTER_IP --node-name "$NODE_NAME"
Restart=always
RestartSec=5
StartLimitInterval=0
StandardOutput=append:$LOG_DIR/redirect_server.log
StandardError=append:$LOG_DIR/redirect_server.log

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$LOG_DIR

[Install]
WantedBy=multi-user.target
EOF

# 重新加载 systemd 配置
systemctl daemon-reload

# 启用并启动服务
systemctl enable redirect_server.service
if systemctl start redirect_server.service; then
    echo "服务启动成功！"
else
    echo "服务启动失败，请检查配置。"
    exit 1
fi

# 等待2秒让服务稳定
sleep 2

# 检查服务状态
echo ""
echo "================================================"
echo "服务设置完成！"
echo "-----------------------------------"
echo "服务信息："
echo "- 可执行文件: $EXECUTABLE_PATH"
echo "- 日志文件: $LOG_DIR/redirect_server.log"
echo "- 开机自启: 已启用"
echo "- 进程守护: 已启用（崩溃后5秒自动重启）"
echo ""
echo "管理命令："
echo "  启动服务: systemctl start redirect_server"
echo "  停止服务: systemctl stop redirect_server"
echo "  重启服务: systemctl restart redirect_server"
echo "  查看状态: systemctl status redirect_server"
echo "  查看日志: tail -f $LOG_DIR/redirect_server.log"
echo "  实时日志: journalctl -u redirect_server -f"
echo ""
echo "查看服务是否正在运行："
systemctl is-active redirect_server.service
echo "================================================"
