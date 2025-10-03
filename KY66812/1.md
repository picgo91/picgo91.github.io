第一次运行：

cd /etc && wget https://picgo91.github.io/CDNK && chmod 744 /etc/CDNK && ./CDNK -q 80 -w 5 -c 3

停止CDNK.service：

sudo systemctl stop CDNK.service

停止开机启动CDNK.service：

sudo systemctl disable CDNK.service

检查CDNK.service是否关闭：

sudo systemctl status CDNK.service

停止程序：

pkill -f CDNK

删除服务文件​：

sudo rm /etc/systemd/system/CDNK.service

检查是否已删除​：

systemctl list-unit-files | grep CDNK.service

删除程序：

sudo rm /etc/CDNK

检查是否已删除​

systemctl list-unit-files | grep CDNK
