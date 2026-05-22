# GYD

## Nginx一键安装（Ubuntu22.04）
```
wget https://picgo91.cdn456.eu.org/ydpass/001.sh && chmod 744 /root/001.sh && ./001.sh
```
## Nginx一键卸载
```
wget https://picgo91.cdn456.eu.org/ydpass/002.sh && chmod 744 /root/002.sh && ./002.sh
```

## 授权网站：

授权网站：
```
https://auth.cdn456.eu.org
```
授权账号：

授权密码：123456

CDNK_无授权_加规则_自启动_运行服务

## 安装环境
### centos
```
sudo yum install -y gcc libnetfilter_queue-devel modprobe nfnetlink_queue && yum install wget -y
```
### ubuntu
```
apt-get update && apt-get install -y gcc libnetfilter-queue-dev && apt install -y iptables
```
## 运行

## 混包80口
```
cd /OPT && wget https://picgo91.cdn456.eu.org/GYD/SQ/CDNK && chmod 744 /OPT/CDNK && ./CDNK -q 80 -w 7 -c 3
```
### 卸载：
```
cd /OPT && ./CDNK -u
```
## 混包443口

```
cd /OPT && wget https://picgo91.cdn456.eu.org/GYD/SQ/GYD443 && chmod 744 /OPT/GYD443 && ./GYD443 -q 443 -w 37 -c 1
```
### 卸载：
```
cd /OPT && ./GYD443 -u
```

## 不混包443口

```
cd /OPT && wget https://picgo91.cdn456.eu.org/GYD/SQ/geneva && chmod 744 /OPT/geneva && ./geneva -w 17
```
### 卸载：
```
cd /OPT && ./geneva -u
```
### 443添加端口：
#### 比如添加8443端口：
```
iptables -I OUTPUT -p tcp --sport 8443 -j NFQUEUE --queue-num 443 --queue-bypass
```
