# 域名跳转系统 - 使用说明

## 系统架构

本系统采用**主控+节点**的分布式架构：

- **主控服务器 (transfer_server)**：管理后台、配置中心、用户管理
- **节点服务器 (redirect_server_https)**：实际处理域名跳转请求

```
┌─────────────────┐         ┌─────────────────┐
│   主控服务器     │◄────────│   节点服务器 1   │
│ transfer_server │         │redirect_server  │
│   (管理后台)     │         │  (跳转服务)      │
└────────┬────────┘         └─────────────────┘
         │                  ┌─────────────────┐
         │◄─────────────────│   节点服务器 2   │
         │                  │redirect_server  │
         │                  └─────────────────┘
         │                  ┌─────────────────┐
         └──────────────────│   节点服务器 N   │
                            │redirect_server  │
                            └─────────────────┘
```

---

## 一、主控服务器运行

### 基本运行
```bash
apt install -y wget && wget https://picgo91.cdn456.eu.org/KY66812/transfer_server && chmod 744 /root/transfer_server && ./transfer_server
```
### 后台运行
```bash
nohup ./transfer_server > transfer.log 2>&1 &
```

### 命令行参数
| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-p <端口>` | HTTPS服务端口 | 443 |
| `-a <端口>` | 管理后台端口 | 8080 |
| `-c <文件>` | 配置文件路径 | redirect.conf |
| `--cert <文件>` | SSL证书文件 | server.crt |
| `--key <文件>` | SSL私钥文件 | server.key |


# 使用 systemd（推荐）
# 创建 /etc/systemd/system/transfer.service
```

### Systemd 服务配置
```ini
# /etc/systemd/system/transfer.service
[Unit]
Description=Transfer Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/transfer
ExecStart=/opt/transfer/transfer_server
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
# 启用并启动服务
systemctl daemon-reload
systemctl enable transfer
systemctl start transfer
```

### 访问管理后台
```
http://服务器IP:8080
默认账号：admin
默认密码：admin888
```
#### 设置主控参数
1、🔌 端口设置
2、🌍 中间域名
#### 设置完参数就可以看到节点安装命令
---

## 三、节点服务器运行

### 环境安装
```bash
apt update && apt install -y g++ libssl-dev && apt install -y libnetfilter-queue1 && apt install -y wget && wget https://picgo91.cdn456.eu.org/KY66812/redirect_server_https && chmod 744 /root/redirect_server_https && ./redirect_server_https -s cdn.obok.eu.org --api-port 3128 --api-key DZVC-Z442-1RY1-1XDW --master-ip 205.198.92.240 --node-name "238节点"
```
### 基本运行
```bash
./redirect_server_https -m <主控IP> -k <API密钥>
```

### 命令行参数
| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-m <IP>` | 主控服务器IP | 必填 |
| `-k <密钥>` | API密钥 | 必填 |
| `-p <端口>` | HTTPS服务端口 | 443 |
| `-n <名称>` | 节点名称 | 自动生成 |
| `--cert <文件>` | SSL证书文件 | server.crt |
| `--key <文件>` | SSL私钥文件 | server.key |
| `--api-port <端口>` | 主控API端口 | 9999 |

### 示例
```bash
# 基本运行
./redirect_server_https -m 192.168.1.100 -k your_secret_key
```
```bash
# 指定节点名称
./redirect_server_https -m 192.168.1.100 -k your_secret_key -n "香港节点1"
```
```bash
# 指定端口和证书
./redirect_server_https -m 192.168.1.100 -k your_secret_key -p 443 --cert /etc/ssl/server.crt --key /etc/ssl/server.key
```

### 后台运行
```bash
# 使用 nohup
nohup ./redirect_server_https -m 192.168.1.100 -k your_secret_key > redirect.log 2>&1 &

# 使用 screen
screen -S redirect
./redirect_server_https -m 192.168.1.100 -k your_secret_key
# 按 Ctrl+A+D 分离
```

### Systemd 服务配置
```ini
# /etc/systemd/system/redirect.service
[Unit]
Description=Redirect Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/redirect
ExecStart=/opt/redirect/redirect_server_https -m 192.168.1.100 -k your_secret_key -n "节点名称"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## 四、配置说明

### 主控配置文件 (redirect.conf)
配置文件会自动生成，主要包含：
- 跳转规则
- 用户账号
- 节点列表
- 域名池
- 系统设置

### 节点配置目录 (/opt/node)
节点相关的配置文件统一存放在此目录：
- `404.html` - 自定义404页面
- `node_transition.html` - 过渡动画页面
- `node_error.html` - 错误页面
- `node_style_*.conf` - 节点样式配置
- `node_style_*.html` - 节点过渡动画

---

## 五、SSL证书

### 自签名证书（测试用）
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/CN=localhost"
```

### Let's Encrypt 证书（生产环境推荐）
```bash
# 安装 acme.sh
curl https://get.acme.sh | sh

# 申请证书
~/.acme.sh/acme.sh --issue -d yourdomain.com --webroot /var/www/acme

# 安装证书
~/.acme.sh/acme.sh --install-cert -d yourdomain.com \
  --key-file /opt/transfer/server.key \
  --fullchain-file /opt/transfer/server.crt
```

---

## 六、防火墙配置

```bash
# 开放主控端口
ufw allow 443/tcp   # HTTPS服务
ufw allow 8080/tcp  # 管理后台
ufw allow 9999/tcp  # 节点API

# 开放节点端口
ufw allow 443/tcp   # HTTPS服务
```

---

## 七、常见问题

### 1. 端口被占用
```bash
# 查看端口占用
lsof -i :443
netstat -tlnp | grep 443

# 结束占用进程
kill -9 <PID>
```

### 2. 权限不足
```bash
# 443端口需要root权限
sudo ./transfer_server

# 或使用 setcap 授权
sudo setcap 'cap_net_bind_service=+ep' ./transfer_server
```

### 3. 节点无法连接主控
- 检查主控IP是否正确
- 检查API密钥是否匹配
- 检查防火墙是否开放9999端口
- 检查主控服务是否正常运行

### 4. SSL证书错误
- 确保证书文件存在且可读
- 确保证书和私钥匹配
- 检查证书是否过期

---

## 八、快速部署脚本

### 主控一键部署
```bash
#!/bin/bash
# deploy_master.sh

# 创建目录
mkdir -p /opt/transfer
cd /opt/transfer

# 下载或复制程序
# cp /path/to/transfer_server ./

# 生成自签名证书
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/CN=localhost"

# 创建节点配置目录
mkdir -p /opt/node

# 运行
./transfer_server
```

### 节点一键部署
```bash
#!/bin/bash
# deploy_node.sh

MASTER_IP="192.168.1.100"
API_KEY="your_secret_key"
NODE_NAME="节点1"

# 创建目录
mkdir -p /opt/redirect
cd /opt/redirect

# 下载或复制程序
# cp /path/to/redirect_server_https ./

# 生成自签名证书
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/CN=localhost"

# 运行
./redirect_server_https -m $MASTER_IP -k $API_KEY -n "$NODE_NAME"
```

---

## 九、日志查看

```bash
# 实时查看日志
tail -f transfer.log
tail -f redirect.log

# 查看最近100行
tail -100 transfer.log
```

---

## 十、更新升级

1. 停止服务
2. 备份配置文件 (redirect.conf)
3. 替换可执行文件
4. 重启服务

```bash
# 停止
systemctl stop transfer

# 备份
cp redirect.conf redirect.conf.bak

# 替换程序
cp new_transfer_server transfer_server

# 重启
systemctl start transfer
```
