#!/bin/bash
# 主控进程守护脚本
# 用法: bash guard_master.sh [start|stop|status|restart]
# 自动检测主控进程，崩溃后自动重启

PROCESS_NAME="transfer_server"
WORK_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$WORK_DIR/${PROCESS_NAME}.pid"
LOG_FILE="$WORK_DIR/${PROCESS_NAME}.log"
GUARD_LOG="$WORK_DIR/guard_master.log"
GUARD_PID_FILE="$WORK_DIR/guard_master.pid"
CHECK_INTERVAL=5  # 检查间隔（秒）
RESTART_DELAY=3   # 重启延迟（秒）
MAX_RESTART=10    # 最大连续重启次数
RESTART_WINDOW=60 # 重启计数窗口（秒）

# 启动命令（根据实际情况修改参数）
START_CMD="$WORK_DIR/$PROCESS_NAME"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$GUARD_LOG"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

get_pid() {
    # 优先从PID文件获取
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE" 2>/dev/null)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo "$pid"
            return
        fi
    fi
    # 从进程列表查找
    pgrep -f "$WORK_DIR/$PROCESS_NAME" | head -1
}

is_running() {
    local pid=$(get_pid)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

start_process() {
    if is_running; then
        log "主控已在运行中 (PID: $(get_pid))，无需启动"
        return 0
    fi
    
    log "启动主控: $START_CMD"
    cd "$WORK_DIR"
    $START_CMD >> "$LOG_FILE" 2>&1 &
    local pid=$!
    echo "$pid" > "$PID_FILE"
    sleep 1
    
    if kill -0 "$pid" 2>/dev/null; then
        log "主控启动成功 (PID: $pid)"
        return 0
    else
        log "主控启动失败"
        return 1
    fi
}

stop_process() {
    local pid=$(get_pid)
    if [ -z "$pid" ]; then
        log "主控未在运行"
        return 0
    fi
    
    log "停止主控 (PID: $pid)..."
    kill "$pid" 2>/dev/null
    
    # 等待进程退出（最多10秒）
    for i in $(seq 1 10); do
        if ! kill -0 "$pid" 2>/dev/null; then
            log "主控已停止"
            rm -f "$PID_FILE"
            return 0
        fi
        sleep 1
    done
    
    # 强制终止
    log "强制终止主控 (PID: $pid)"
    kill -9 "$pid" 2>/dev/null
    rm -f "$PID_FILE"
}

start_guard() {
    # 检查守护进程是否已运行
    if [ -f "$GUARD_PID_FILE" ]; then
        local guard_pid=$(cat "$GUARD_PID_FILE" 2>/dev/null)
        if [ -n "$guard_pid" ] && kill -0 "$guard_pid" 2>/dev/null; then
            log "守护进程已在运行 (PID: $guard_pid)"
            return 0
        fi
    fi
    
    log "========== 主控守护进程启动 =========="
    
    # 先启动主控
    start_process
    
    # 后台运行守护循环
    (
        echo $$ > "$GUARD_PID_FILE"
        local restart_count=0
        local restart_first_time=$(date +%s)
        
        while true; do
            sleep $CHECK_INTERVAL
            
            if ! is_running; then
                local now=$(date +%s)
                
                # 重置重启计数窗口
                if [ $((now - restart_first_time)) -gt $RESTART_WINDOW ]; then
                    restart_count=0
                    restart_first_time=$now
                fi
                
                restart_count=$((restart_count + 1))
                
                if [ $restart_count -gt $MAX_RESTART ]; then
                    log "错误: ${RESTART_WINDOW}秒内重启次数超过${MAX_RESTART}次，停止守护"
                    rm -f "$GUARD_PID_FILE"
                    exit 1
                fi
                
                log "检测到主控进程退出，${RESTART_DELAY}秒后重启 (第${restart_count}次)"
                sleep $RESTART_DELAY
                start_process
            fi
        done
    ) >> "$GUARD_LOG" 2>&1 &
    
    local guard_pid=$!
    echo "$guard_pid" > "$GUARD_PID_FILE"
    log "守护进程已启动 (PID: $guard_pid)"
}

stop_guard() {
    # 停止守护进程
    if [ -f "$GUARD_PID_FILE" ]; then
        local guard_pid=$(cat "$GUARD_PID_FILE" 2>/dev/null)
        if [ -n "$guard_pid" ] && kill -0 "$guard_pid" 2>/dev/null; then
            kill "$guard_pid" 2>/dev/null
            # 杀掉子进程
            pkill -P "$guard_pid" 2>/dev/null
            log "守护进程已停止"
        fi
        rm -f "$GUARD_PID_FILE"
    fi
    
    # 停止主控
    stop_process
}

show_status() {
    echo "===== 主控守护状态 ====="
    
    # 守护进程状态
    if [ -f "$GUARD_PID_FILE" ]; then
        local guard_pid=$(cat "$GUARD_PID_FILE" 2>/dev/null)
        if [ -n "$guard_pid" ] && kill -0 "$guard_pid" 2>/dev/null; then
            echo "守护进程: 运行中 (PID: $guard_pid)"
        else
            echo "守护进程: 未运行"
        fi
    else
        echo "守护进程: 未运行"
    fi
    
    # 主控状态
    if is_running; then
        echo "主控进程: 运行中 (PID: $(get_pid))"
    else
        echo "主控进程: 未运行"
    fi
    
    # 最近日志
    if [ -f "$GUARD_LOG" ]; then
        echo ""
        echo "===== 最近守护日志 ====="
        tail -10 "$GUARD_LOG"
    fi
}

install_service() {
    local service_file="/etc/systemd/system/guard_master.service"
    local script_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    
    cat > "$service_file" << EOF
[Unit]
Description=Transfer Server Guard (Master)
After=network.target

[Service]
Type=forking
ExecStart=/bin/bash $script_path start
ExecStop=/bin/bash $script_path stop
ExecReload=/bin/bash $script_path restart
WorkingDirectory=$WORK_DIR
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable guard_master.service
    log "已安装systemd服务并设置开机自启"
    echo "✅ 已安装开机自启服务: guard_master.service"
    echo "   启动: systemctl start guard_master"
    echo "   停止: systemctl stop guard_master"
    echo "   状态: systemctl status guard_master"
}

uninstall_service() {
    systemctl stop guard_master.service 2>/dev/null
    systemctl disable guard_master.service 2>/dev/null
    rm -f /etc/systemd/system/guard_master.service
    systemctl daemon-reload
    stop_guard
    log "已卸载systemd服务"
    echo "✅ 已卸载开机自启服务"
}

case "${1:-start}" in
    start)
        start_guard
        ;;
    stop)
        stop_guard
        ;;
    restart)
        stop_guard
        sleep 2
        start_guard
        ;;
    status)
        show_status
        ;;
    install)
        install_service
        ;;
    uninstall)
        uninstall_service
        ;;
    *)
        echo "用法: $0 {start|stop|restart|status|install|uninstall}"
        echo "  start     - 启动主控并开启进程守护"
        echo "  stop      - 停止主控和守护进程"
        echo "  restart   - 重启主控和守护进程"
        echo "  status    - 查看运行状态"
        echo "  install   - 安装为systemd服务（开机自启）"
        echo "  uninstall - 卸载systemd服务"
        exit 1
        ;;
esac
