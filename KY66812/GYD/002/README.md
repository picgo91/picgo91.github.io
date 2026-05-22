CDNK_无授权_加规则_自启动_运行服务

### 安装环境
#### centos
```
sudo yum install -y gcc libnetfilter_queue-devel modprobe nfnetlink_queue && yum install wget -y
```
#### ubuntu
```
apt-get update && apt-get install -y gcc libnetfilter-queue-dev && apt install -y iptables
```
### 运行

### 混包80口
```
cd /etc && wget https://picgo91.cdn456.eu.org/KY66812/GYD/002/CDNK && chmod 744 /etc/CDNK && ./CDNK -q 80 -w 7 -c 3
```
#### 卸载：
```
cd /etc && ./CDNK -u
```
### 混包443口

```
cd /etc && wget https://picgo91.cdn456.eu.org/KY66812/GYD/002/GYD443 && chmod 744 /etc/GYD443 && ./GYD443 -q 443 -w 37 -c 1
```
#### 卸载：
```
cd /etc && ./GYD443 -u
```

### 不混包443口

```
cd /etc && wget https://picgo91.cdn456.eu.org/KY66812/GYD/002/geneva && chmod 744 /etc/geneva && ./geneva -w 17
```
#### 卸载：
```
cd /etc && ./geneva -u
```
#### 443添加端口：
##### 比如添加8443端口：
```
iptables -I OUTPUT -p tcp --sport 8443 -j NFQUEUE --queue-num 443 --queue-bypass
```
