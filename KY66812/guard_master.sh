#!/bin/bash
# transfer_server_setup.sh

# 创建 systemd 服务配置
cat << EOF | sudo tee /etc/systemd/system/transfer-server.service
[Unit]
Description=Transfer Server Service
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/root
ExecStart=/root/transfer_server
Restart=always
RestartSec=5
StandardOutput=append:/var/log/transfer-server.log
StandardError=append:/var/log/transfer-server.error.log

[Install]
WantedBy=multi-user.target
EOF

# 重载 systemd
sudo systemctl daemon-reload

# 启动并启用服务
sudo systemctl start transfer-server
sudo systemctl enable transfer-server

# 创建日志文件并设置权限
sudo touch /var/log/transfer-server.log /var/log/transfer-server.error.log
sudo chmod 644 /var/log/transfer-server*.log

echo "服务已配置完成！"
echo "使用以下命令管理服务："
echo "  sudo systemctl status transfer-server"
echo "  sudo journalctl -u transfer-server -f"
