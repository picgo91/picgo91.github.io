#!/bin/bash

echo "开始卸载 Nginx..."

# 停止并禁用服务
sudo systemctl stop nginx
sudo systemctl disable nginx

# 卸载 Nginx
sudo apt remove --purge nginx nginx-common nginx-core -y

# 删除相关文件
sudo rm -rf /var/www/html
sudo rm -f /etc/ssl/private/nginx-selfsigned.key
sudo rm -f /etc/ssl/certs/nginx-selfsigned.crt
sudo rm -f /etc/nginx/nginx.conf.backup
sudo rm -rf /etc/nginx
sudo rm -rf /var/log/nginx
sudo rm -rf /var/lib/nginx

# 清理系统
sudo apt autoremove -y
sudo apt autoclean

echo "Nginx 卸载完成！"
