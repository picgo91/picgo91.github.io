#  HTTPS 域名跳转服务器 (C++ 版本) + TCP窗口修改(免备案)

## 依赖安装:

### Ubuntu/Debian:
```
sudo apt install libssl-dev libnetfilter-queue-dev libnfnetlink-dev
```
### CentOS/RHEL: 
```
sudo yum install openssl-devel libnetfilter_queue-devel
```

## 下载运行
```
cd /etc && wget https://picgo91.cdn456.eu.org/KY66812/tcp_https/tcp_https && chmod 744 /etc/tcp_https && ./tcp_https -q 443 -w 17
```
```
sudo ./tcp_https -q 443 -w 17
```
// 或使用默认值: sudo ./tcp_https

## 编译:
```
g++ -o tcp_https tcp_https.cpp -lssl -lcrypto -lpthread -lnetfilter_queue -lnfnetlink -std=c++17
```

./</br>
├── tcp_https          # 主程序（编译后的可执行文件）</br>
├── json.txt           # 域名跳转配置文件</br>
├── ssl.pem           # 默认SSL证书文件</br>
├── logs.txt          # 日志文件</br>
└── certs/            # 各域名证书目录</br>
    ├── 123.com/</br>
    │   ├── cert.pem</br>
    │   └── key.pem</br>
    └── 456.com/</br>
        ├── cert.pem</br>
        └── key.pem</br>


