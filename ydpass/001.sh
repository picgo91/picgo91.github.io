#!/bin/bash

# 更新系统
sudo apt update && sudo apt upgrade -y

# 安装Nginx
sudo apt install nginx -y

# 启动Nginx服务
sudo systemctl start nginx
sudo systemctl enable nginx

# 创建网站目录
sudo mkdir -p /var/www/html
sudo mkdir -p /var/www/ssl

# 设置目录权限
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www

# 创建默认首页
sudo cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nginx安装成功</title>
    <style>
        :root {
            --primary-color: #3498db;
            --secondary-color: #2980b9;
            --success-color: #2ecc71;
            --text-color: #333;
            --light-color: #f9f9f9;
            --shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        
        .container {
            max-width: 800px;
            width: 90%;
            background: white;
            border-radius: 10px;
            box-shadow: var(--shadow);
            overflow: hidden;
            text-align: center;
            padding: 2rem;
            margin: 2rem;
        }
        
        h1 {
            color: var(--primary-color);
            font-size: 2.5rem;
            margin-bottom: 1.5rem;
            font-weight: 700;
        }
        
        p {
            font-size: 1.2rem;
            margin-bottom: 2rem;
        }
        
        .status-badge {
            display: inline-block;
            background-color: var(--success-color);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: bold;
            margin: 0.5rem;
        }
        
        .ports-info {
            display: flex;
            justify-content: center;
            gap: 1rem;
            margin: 2rem 0;
        }
        
        .port {
            background-color: var(--light-color);
            padding: 1rem;
            border-radius: 8px;
            width: 120px;
            box-shadow: var(--shadow);
        }
        
        .port h3 {
            margin-top: 0;
            color: var(--secondary-color);
        }
        
        .footer {
            margin-top: 2rem;
            font-size: 0.9rem;
            color: #666;
        }
        
        @media (max-width: 600px) {
            h1 {
                font-size: 2rem;
            }
            
            .ports-info {
                flex-direction: column;
                align-items: center;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Nginx 安装成功！</h1>
        <div class="status-badge">运行中</div>
        
        <div class="ports-info">
            <div class="port">
                <h3>HTTP</h3>
                <p>80 端口</p>
                <p>已配置</p>
            </div>
            <div class="port">
                <h3>HTTPS</h3>
                <p>443 端口</p>
                <p>已配置</p>
            </div>
        </div>
        
        <p>您的Nginx服务器已成功安装并运行。</p>
        
        <div class="footer">
            <p>© 2023 Nginx Server | 当前时间: <span id="datetime"></span></p>
        </div>
    </div>

    <script>
        // 显示当前日期时间
        function updateDateTime() {
            const now = new Date();
            const options = { 
                year: 'numeric', 
                month: 'long', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false
            };
            document.getElementById('datetime').textContent = now.toLocaleDateString('zh-CN', options);
        }
        
        updateDateTime();
        setInterval(updateDateTime, 1000);
    </script>
</body>
</html>
EOF

# 备份原始Nginx配置
sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup

# 配置Nginx支持80和443端口
sudo cat > /etc/nginx/sites-available/default << EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
   
    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;
   
    server_name _;
   
    location / {
        try_files \$uri \$uri/ =404;
    }
}

# HTTPS配置（需要证书）
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
   
    # 自签名证书路径 - 实际使用时需要替换为真实证书
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
   
    root /var/www/html;
    index index.html index.htm;
   
    server_name _;
   
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

# 生成自签名SSL证书（用于测试）
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/nginx-selfsigned.key \
    -out /etc/ssl/certs/nginx-selfsigned.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# 测试Nginx配置
sudo nginx -t

# 重新加载Nginx配置
sudo systemctl reload nginx

# 配置防火墙
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

echo "Nginx安装和配置完成！"
echo "访问地址: http://你的服务器IP"
echo "HTTPS地址: https://你的服务器IP（使用自签名证书）"
