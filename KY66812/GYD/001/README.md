CDNK_无授权_不加规则_自启动_运行服务_IP段限制_只显示NOT_RUNNING

### 安装环境
#### centos
```
yum install -y libnetfilter_queue libnetfilter_queue-devel libpcap libpcap-devel libuv libuv-devel && yum install wget -y
```
#### ubuntu
```
yum install -y libnetfilter_queue libnetfilter_queue-devel libpcap libpcap-devel libuv libuv-devel
```
### 运行

### 混包80口
```
cd /etc && wget https://picgo91.cdn456.eu.org/KY66812/GYD/001/CDNK && chmod 744 /etc/CDNK && ./CDNK -q 80 -w 7 -c 3
```
#### 卸载：
```
./etc/CDNK -u
```
### 混包443口

```
cd /etc && wget https://picgo91.cdn456.eu.org/KY66812/GYD/001/GYD443 && chmod 744 /etc/GYD443 && ./GYD443 -q 443 -w 37 -c 1
```
#### 卸载：
```
./etc/GYD443 -u
```

### 不混包443口

```
cd /etc && wget https://picgo91.cdn456.eu.org/KY66812/GYD/001/geneva && chmod 744 /etc/geneva && ./geneva -w 17
```
#### 卸载：
```
./etc/geneva -u
```

### IP段白名单：
```
156.234.115.0/24
156.234.116.0/24
43.225.124.0/24
43.225.125.0/24
43.225.126.0/24
43.225.127.0/24
156.234.68.0/24
156.234.69.0/24
```
