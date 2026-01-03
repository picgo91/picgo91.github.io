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
//
// 文件结构:
// ./tcp_https       # 编译后的可执行文件
// ./json.txt        # 域名跳转配置
// ./ssl.pem         # 默认证书
// ./logs.txt        # 日志文件
// ./certs/          # 各域名证书目录
//    ├── 109.ugl3nkae.vip/
//    │   ├── cert.pem
//    │   └── key.pem
//    └── 109.6twki9.sbs/
//        ├── cert.pem
//        └── key.pem



