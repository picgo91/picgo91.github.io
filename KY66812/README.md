## 一、主控服务器运行

### 1、环境搭建+文件夹下载+修改权限
```bash
apt install -y wget && wget https://picgo91.cdn456.eu.org/KY66812/002/transfer_server && chmod 744 /root/transfer_server && ./transfer_server
```
### 初始化运行
```bash
./transfer_server
```
> 当出现管理地址的时候按:Ctrl+c退出。
### 后台运行
```bash
nohup ./transfer_server > transfer.log 2>&1 &
```
#### 查看是否正常运行
```bash
ps aux | grep transfer_server
```
#### 出现就是正常启动了：
```bash
root@iZj6cepotcelupz5p1quraZ:~# ps aux | grep transfer_server
root        6597  0.0  0.1 532312  7752 pts/0    Sl   09:08   0:00 ./transfer_server
root       11077  0.0  0.0   6676  2432 pts/1    S+   10:26   0:00 grep --color=auto transfer_server
```
### 2、开启自动启停和进程守护
```bash
wget https://picgo91.cdn456.eu.org/KY66812/002/guard_master.sh && chmod 744 /root/guard_master.sh && ./guard_master.sh
```
#### 查看是否启动成功
```bash
sudo systemctl status transfer-server
```
#### 出现就是正常启动了：
```bash
root@iZj6cepotcelupz5p1quraZ:~# sudo systemctl status transfer-server
● transfer-server.service - Transfer Server Service
     Loaded: loaded (/etc/systemd/system/transfer-server.service; enabled; preset: enabled)
     Active: active (running) since Fri 2026-02-13 09:09:14 CST; 1h 19min ago
   Main PID: 6670 (transfer_server)
      Tasks: 4 (limit: 8650)
     Memory: 1.6M (peak: 2.6M)
        CPU: 397ms
     CGroup: /system.slice/transfer-server.service
             └─6670 /root/transfer_server

Feb 13 09:09:14 iZj6cepotcelupz5p1quraZ systemd[1]: Started transfer-server.service - Transfer Server Service.
```


-------

## 二、节点服务器运行

### 1、环境搭建+文件夹下载+修改权限
```bash
apt update && apt install -y g++ libssl-dev && apt install -y libnetfilter-queue1 && apt install -y wget && wget https://picgo91.cdn456.eu.org/KY66812/002/redirect_server_https && chmod 744 /root/redirect_server_https
```
### 查看主控后台的节点安装命令
比如后台命令是这个
```bash
nohup ./redirect_server_https -s wwvip.ap220.com -t 443 --master-ip 47.242.7.162 --node-name "节点名称" > redirect_server.log 2>&1 &
```
### 初始化运行
可以先运行下，**“节点名称”改为实际名称**
```bash
./redirect_server_https -s wwvip.ap220.com -t 443 --master-ip 47.242.7.162 --node-name "节点名称"
```
> 可以看到心跳同步，就没问题了了按:Ctrl+c退出。
### 后台运行
```bash
nohup ./redirect_server_https -s wwvip.ap220.com -t 443 --master-ip 47.242.7.162 --node-name "节点名称" > redirect_server.log 2>&1 &
```
#### 查看是否正常运行
```bash
ps aux | grep redirect_server_https
```
#### 出现就是正常启动了：
```bash
root@iZj6cbnt3e6d1s2gi1zua3Z:~# ps aux | grep redirect_server_https
root         862  0.0  0.2 389884  9856 ?        Ssl  10:07   0:00 /root/redirect_server_https -s ceshi.ap220.com -t 443 --master-ip 47.242.7.162 --node-name 节点69
```

### 2、自动启停和进程守护
```bash
wget https://picgo91.cdn456.eu.org/KY66812/002/guard_node.sh && chmod 744 /root/guard_node.sh && ./guard_node.sh
```
#### 查看是否启动成功
```bash
systemctl status redirect_server
```
#### 出现就是正常启动了：
```bash
root@iZj6cbnt3e6d1s2gi1zua3Z:~# systemctl status redirect_server
● redirect_server.service - Redirect Server HTTPS Service
     Loaded: loaded (/etc/systemd/system/redirect_server.service; enabled; preset: enabled)
     Active: active (running) since Fri 2026-02-13 10:07:38 CST; 10min ago
   Main PID: 862 (redirect_server)
      Tasks: 6 (limit: 4124)
     Memory: 3.4M (peak: 3.9M)
        CPU: 52ms
     CGroup: /system.slice/redirect_server.service
             └─862 /root/redirect_server_https -s ceshi.ap220.com -t 443 --master-ip 47.242.7.162 --node-name 节点69

Feb 13 10:07:38 iZj6cbnt3e6d1s2gi1zua3Z systemd[1]: Started redirect_server.service - Redirect Server HTTPS Service.
```
