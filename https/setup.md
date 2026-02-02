授权代码

```
/*
 * 301系统安装和证书申请服务器
 * 功能：许可证验证、系统初始化、HTTP服务器、证书申请
 * 获取管理账号密码
 * 编译：gcc -Wall -O2 -o setup setup.c -lpthread
 * 下载地址：https://picgo91.cdn456.eu.org/https
 * 授权地址：http://api.5205230.xyz
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>

/* 配置常量 */
#define PORT 5566                                                    // HTTP服务器端口
#define CERT_PATH "/root/301system/cert"                            // 证书存储路径
#define BUFFER_SIZE 4096                                            // 缓冲区大小
#define CONFIG_URL "https://picgo91.cdn456.eu.org/https/config.json"           // 配置文件下载地址
#define BINARY_URL "https://picgo91.cdn456.eu.org/https/301sys"                // 二进制文件下载地址
#define CONFIG_PATH "/root/301system/data/config.json"             // 配置文件本地路径
#define BINARY_PATH "/root/301system/bin/301sys"                   // 二进制文件本地路径

/* 网络和超时配置 */
#define LICENSE_SERVER_HOST "api.5205230.xyz"                     // 许可证验证服务器
#define LICENSE_SERVER_PORT 80                                      // 许可证服务器端口（HTTP）
#define SOCKET_TIMEOUT_SEC 30                                       // 套接字超时时间（秒）
#define MAX_RETRIES 3                                               // 最大重试次数
#define RETRY_INTERVAL_SEC 30                                       // 重试间隔（秒）
#define LICENSE_CHECK_INTERVAL_SEC 86400                            // 许可证检查间隔（24小时）
#define AUTH_FILE_REFRESH_INTERVAL_SEC 43200                        // 授权文件刷新间隔（12小时）
#define PROGRESS_DOTS 10                                            // 进度点数量
#define MAX_LICENSE_KEY_LEN 256                                     // 最大许可证长度


/* 全局变量 */
static volatile int server_running = 1;                            // 服务器运行状态标志

/*
 * 获取当前时间字符串
 * 返回：格式化的时间字符串
 */
char* get_current_time() {
    static char time_str[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    return time_str;
}

/*
 * 许可证验证函数
 * 通过HTTPS请求验证许可证密钥和有效期
 * 参数：license_key - 许可证密钥
 * 返回：验证结果字符串，失败返回NULL
 */
char* verify_license_key_and_date(const char* license_key) {
    char command[1024];
    char temp_file[] = "/tmp/license_response_XXXXXX";
    char *result = NULL;
    FILE *fp;
    int fd;
    struct stat st;
    
    // 创建临时文件
    fd = mkstemp(temp_file);
    if (fd == -1) {
        perror("创建临时文件失败");
        return NULL;
    }
    close(fd);
    
    // 构造curl HTTP请求命令
    snprintf(command, sizeof(command),
             "curl -s --connect-timeout 10 --max-time 30 "
             "'http://%s/verify_key_and_date.php?license_key=%s' "
             "-o '%s' 2>/dev/null",
             LICENSE_SERVER_HOST, license_key, temp_file);
    
    // 执行curl命令
    int curl_result = system(command);
    if (curl_result != 0) {
        fprintf(stderr, "HTTP请求失败\n");
        unlink(temp_file);
        return NULL;
    }
    
    // 检查文件是否存在且有内容
    if (stat(temp_file, &st) != 0 || st.st_size == 0) {
        fprintf(stderr, "响应文件为空或不存在\n");
        unlink(temp_file);
        return NULL;
    }
    
    // 读取响应内容
    fp = fopen(temp_file, "r");
    if (fp == NULL) {
        perror("打开响应文件失败");
        unlink(temp_file);
        return NULL;
    }
    
    // 分配内存并读取文件内容
    result = malloc(st.st_size + 1);
    if (result == NULL) {
        fprintf(stderr, "内存分配失败\n");
        fclose(fp);
        unlink(temp_file);
        return NULL;
    }
    
    size_t bytes_read = fread(result, 1, st.st_size, fp);
    result[bytes_read] = '\0';
    
    fclose(fp);
    unlink(temp_file);  // 删除临时文件
    
    // 移除可能的换行符
    char *newline = strchr(result, '\n');
    if (newline) *newline = '\0';
    
    // 检查是否为HTML响应，如果是则尝试提取有用信息
    if (strstr(result, "<html>") || strstr(result, "<HTML>")) {
        // 如果HTML中包含授权相关的关键词，提取它们
        if (strstr(result, "授权成功") || strstr(result, "authorized")) {
            char *extracted = strdup("授权成功");
            free(result);
            return extracted;
        } else if (strstr(result, "未授权") || strstr(result, "unauthorized")) {
            char *extracted = strdup("未授权");
            free(result);
            return extracted;
        } else if (strstr(result, "授权到期") || strstr(result, "expired")) {
            char *extracted = strdup("授权到期");
            free(result);
            return extracted;
        } else if (strstr(result, "授权数量已超过限制") || strstr(result, "exceeded")) {
            // 保留完整的错误信息（包含数量）
            return result;
        } else {
            // HTML响应但没有找到授权信息，返回授权成功（兼容性处理）
            char *extracted = strdup("授权成功");
            free(result);
            return extracted;
        }
    }
    
    // 非HTML响应，直接返回原始结果（保留完整信息）
    
    return result;
}

/*
 * 获取外网IP地址
 * 返回：外网IP字符串，失败返回默认值
 */
char* get_external_ip() {
    static char ip[64] = {0};
    FILE *fp;
    
    // 尝试多个服务获取外网IP
    const char* commands[] = {
        "curl -s --connect-timeout 5 ifconfig.me",
        "curl -s --connect-timeout 5 ipinfo.io/ip",
        "curl -s --connect-timeout 5 icanhazip.com",
        NULL
    };
    
    {
        int i;
        for (i = 0; commands[i] != NULL; i++) {
            fp = popen(commands[i], "r");
            if (fp != NULL) {
                if (fgets(ip, sizeof(ip), fp) != NULL) {
                    // 移除换行符
                    char *newline = strchr(ip, '\n');
                    if (newline) *newline = '\0';
                    
                    // 简单验证IP格式
                    if (strlen(ip) > 7 && strchr(ip, '.')) {
                        pclose(fp);
                        return ip;
                    }
                }
                pclose(fp);
            }
        }
    }
    
    // 如果都失败了，返回默认提示
    strcpy(ip, "你的服务器IP");
    return ip;
}

/*
 * 执行系统命令
 * 参数：command - 要执行的命令
 * 参数：silent - 是否静默执行（不显示错误信息）
 * 返回：命令执行结果，0表示成功
 */
int execute_command_with_option(const char *command, int silent) {
    if (!command) {
        if (!silent) {
            fprintf(stderr, "错误：命令为空\n");
        }
        return -1;
    }
    
    int result = system(command);
    if (result != 0 && !silent) {
        fprintf(stderr, "命令执行失败: %s\n", command);
    }
    return result;
}

/*
 * 执行系统命令（显示错误）
 * 参数：command - 要执行的命令
 * 返回：命令执行结果，0表示成功
 */
int execute_command(const char *command) {
    return execute_command_with_option(command, 0);
}

/*
 * 静默执行系统命令（不显示错误）
 * 参数：command - 要执行的命令
 * 返回：命令执行结果，0表示成功
 */
int execute_command_silent(const char *command) {
    return execute_command_with_option(command, 1);
}

/*
 * 下载文件函数
 * 参数：url - 下载地址，output_path - 输出路径
 * 返回：0表示成功，-1表示失败
 */
int download_file(const char *url, const char *output_path) {
    char command[BUFFER_SIZE];
    
    if (!url || !output_path) {
        fprintf(stderr, "错误：URL或输出路径为空\n");
        return -1;
    }
    
    // 创建目录（如果需要）
    char *dir_path = strdup(output_path);
    if (!dir_path) {
        fprintf(stderr, "错误：内存分配失败\n");
        return -1;
    }
    
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        snprintf(command, sizeof(command), "mkdir -p %s", dir_path);
        if (execute_command(command) != 0) {
            fprintf(stderr, "错误：创建目录失败: %s\n", dir_path);
            free(dir_path);
            return -1;
        }
    }
    free(dir_path);
    
    // 下载文件
    snprintf(command, sizeof(command), "curl -s -L %s -o %s", url, output_path);
    if (execute_command(command) != 0) {
        fprintf(stderr, "错误：下载文件失败: %s\n", url);
        return -1;
    }
    
    // 设置权限
    snprintf(command, sizeof(command), "chmod 755 %s", output_path);
    if (execute_command(command) != 0) {
        fprintf(stderr, "警告：设置文件权限失败: %s\n", output_path);
        // 权限设置失败不算致命错误
    }
    
    return 0;
}

/*
 * 处理HTTP客户端请求
 * 参数：client_socket - 客户端套接字
 */
// 发送config.json内容
void send_config_json(int client_socket) {
    FILE *fp = fopen(CONFIG_PATH, "r");
    char response[BUFFER_SIZE * 4];
    char config_content[BUFFER_SIZE * 2] = {0};
    
    if (fp == NULL) {
        // 文件不存在，返回错误
        snprintf(response, sizeof(response),
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: application/json; charset=UTF-8\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type\r\n\r\n"
            "{\"error\": \"配置文件不存在\", \"path\": \"%s\"}", CONFIG_PATH);
        send(client_socket, response, strlen(response), 0);
        return;
    }
    
    // 读取文件内容
    size_t bytes_read = fread(config_content, 1, sizeof(config_content) - 1, fp);
    config_content[bytes_read] = '\0';
    fclose(fp);
    
    // 构造HTTP响应
    snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json; charset=UTF-8\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n\r\n"
        "%s", config_content);
    
    send(client_socket, response, strlen(response), 0);
}

// 处理CORS预检请求
void send_cors_preflight(int client_socket) {
    const char *response =
        "HTTP/1.1 200 OK\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Content-Length: 0\r\n\r\n";
    send(client_socket, response, strlen(response), 0);
}

// 发送HTML表单页面
void send_form_page(int client_socket) {
    const char *response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n\r\n"
        "<html><head><style>"
        "body {font-family: Arial, sans-serif; background-color: #fff; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; height: 100vh;}"
        "form {background: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);}"
        "h2, input[type=text], input[type=submit] {display: inline-block; vertical-align: middle; margin: 0 10px;}"
        "h2 {margin-right: 20px;}"
        "input[type=text] {padding: 10px; border: 1px solid #ccc; border-radius: 5px; width: 250px;}"
        "input[type=submit] {background: #28a745; color: #fff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;}"
        "input[type=submit]:hover {background: #218838;}"
        "</style></head><body>"
        "<form action=\"/apply\" method=\"post\">"
        "申请域名证书: <input type=\"text\" name=\"domain\" required>"
        "<input type=\"submit\" value=\"申请\">"
        "</form>"
        "</body></html>";
    send(client_socket, response, strlen(response), 0);
}

// 处理证书申请
void handle_cert_request(int client_socket, const char* domain) {
    // 执行iptables命令，将80端口重定向到7070端口
    execute_command("sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 7070");

    // 构造certbot命令
    char command[BUFFER_SIZE];
    snprintf(command, sizeof(command), 
             "certbot certonly --force-renewal --standalone --http-01-port 7070 -d %s --non-interactive --agree-tos --email anwang5330@outlook.com --deploy-hook 'cp /etc/letsencrypt/live/%s/fullchain.pem %s/%s.cer && cp /etc/letsencrypt/live/%s/privkey.pem %s/%s.key' 2>&1",
             domain, domain, CERT_PATH, domain, domain, CERT_PATH, domain);

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("Failed to run command");
        execute_command("sudo iptables -t nat -D PREROUTING 1");
        return;
    }

    // 读取命令输出
    char full_result[BUFFER_SIZE * 10] = {0};
    char result_buffer[BUFFER_SIZE];
    while (fgets(result_buffer, sizeof(result_buffer), fp) != NULL) {
        strcat(full_result, result_buffer);
    }

    int result = pclose(fp);
    char response[BUFFER_SIZE * 12];

    if (result == 0) {
        // 成功时，列出iptables规则
        FILE *fp_iptables = popen("sudo iptables -t nat -L -n -v --line-numbers", "r");
        char iptables_result[BUFFER_SIZE * 10] = {0};
        
        if (fp_iptables != NULL) {
            while (fgets(result_buffer, sizeof(result_buffer), fp_iptables) != NULL) {
                strcat(iptables_result, result_buffer);
            }
            pclose(fp_iptables);
        }

        snprintf(response, sizeof(response),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n\r\n"
            "<html><body>"
            "<h1>申请成功</h1>"
            "<p>域名的证书已成功申请。</p>"
            "<pre>%s</pre>"
            "<script type=\"text/javascript\">"
            "setTimeout(function() { window.location.href = '/'; }, 5000);"
            "</script>"
            "</body></html>", iptables_result);
    } else {
        snprintf(response, sizeof(response),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n\r\n"
            "<html><body>"
            "<h1>申请失败</h1>"
            "<p>无法申请域名的证书。</p>"
            "<pre>%s</pre>"
            "<script type=\"text/javascript\">"
            "setTimeout(function() { window.location.href = '/'; }, 5000);"
            "</script>"
            "</body></html>", full_result);
    }

    // 删除iptables规则
    execute_command("sudo iptables -t nat -D PREROUTING 1");
    send(client_socket, response, strlen(response), 0);
}

void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE];
    
    // 设置接收超时
    struct timeval timeout;
    timeout.tv_sec = SOCKET_TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    int read_size = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (read_size <= 0) {
        close(client_socket);
        return;
    }

    buffer[read_size] = '\0';
    
    // 处理CORS预检请求
    if (strstr(buffer, "OPTIONS ") != NULL) {
        send_cors_preflight(client_socket);
    }
    // 处理获取配置文件请求
    else if (strstr(buffer, "GET /get_config") != NULL) {
        send_config_json(client_socket);
    }
    else if (strstr(buffer, "GET / ") != NULL) {
        send_form_page(client_socket);
    } else if (strstr(buffer, "POST /apply") != NULL) {
        char *domain = strstr(buffer, "domain=");
        if (domain) {
            domain += 7;
            char *end = strstr(domain, "&");
            if (end) *end = '\0';

            // 替换+号为空格（URL编码处理）
            char *p;
            for (p = domain; *p; ++p) {
                if (*p == '+') *p = ' ';
            }

            handle_cert_request(client_socket, domain);
        }
    }
    
    close(client_socket);
}


/*
 * 清理函数
 * 停止服务并清理文件
 */
void cleanup() {
    server_running = 0;
    
    // 静默停止301sys进程（不显示错误信息）
    execute_command_silent("pkill -f 301sys");
    
    // 删除文件
    remove(CONFIG_PATH);
    remove(BINARY_PATH);
    
    // 删除授权文件
    remove("/root/301system/.auth_success");
    remove("/root/301system/.last_auth_check");
}

/*
 * 轻量级清理函数（daemon化之前使用）
 * 只停止服务，不删除文件
 */
void cleanup_light() {
    server_running = 0;
    
    // 静默停止301sys进程（不显示错误信息）
    execute_command_silent("pkill -f 301sys");
}

/*
 * 信号处理函数
 * 处理SIGTERM和SIGINT信号
 */
void handle_signal(int signal) {
    cleanup();
    exit(0);
}

/*
 * 将程序转为守护进程
 * 返回：0表示成功，-1表示失败
 */
int daemonize() {
    pid_t pid, sid;
    
    // 第一次fork
    pid = fork();
    if (pid < 0) {
        perror("第一次fork失败");
        return -1;
    }
    
    // 父进程退出
    if (pid > 0) {
        printf("\n✅ 程序已转为后台运行，进程ID: %d\n", pid);
        exit(0);
    }
    
    // 子进程继续执行
    // 创建新的会话
    sid = setsid();
    if (sid < 0) {
        perror("创建新会话失败");
        return -1;
    }
    
    // 第二次fork
    pid = fork();
    if (pid < 0) {
        perror("第二次fork失败");
        return -1;
    }
    
    // 第一个子进程退出
    if (pid > 0) {
        exit(0);
    }
    
    // 保持当前工作目录，不要改变到根目录
    // 注释掉原来的 chdir("/") 调用
    // if (chdir("/") < 0) {
    //     perror("改变工作目录失败");
    //     return -1;
    // }
    
    // 设置文件权限掩码
    umask(0);
    
    // 创建日志文件目录
    if (system("mkdir -p /root/301system/logs") != 0) {
        perror("创建日志目录失败");
        return -1;
    }
    
    // 重定向标准输入到/dev/null
    int null_fd = open("/dev/null", O_RDONLY);
    if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        close(null_fd);
    }
    
    // 重定向stdout和stderr到日志文件，但保持文件描述符开放以支持HTTP服务器
    int log_fd = open("/root/301system/logs/setup.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (log_fd >= 0) {
        dup2(log_fd, STDOUT_FILENO); // stdout
        dup2(log_fd, STDERR_FILENO); // stderr
        close(log_fd);
    } else {
        // 如果无法创建日志文件，重定向到/dev/null
        int null_out = open("/dev/null", O_WRONLY);
        if (null_out >= 0) {
            dup2(null_out, STDOUT_FILENO);
            dup2(null_out, STDERR_FILENO);
            close(null_out);
        }
    }
    
    return 0;
}

/*
 * 许可证定期验证线程
 * 每小时验证一次许可证，失败时重试3-5次
 */
void* verify_license_periodically(void* arg) {
    const char* license_key = (const char*)arg;
    const int max_retries = MAX_RETRIES;
    const int retry_interval = RETRY_INTERVAL_SEC;
    
    while (server_running) {
        int retry_count = 0;
        int verification_success = 0;
        
        printf("\n[%s] 开始许可证验证...\n", get_current_time());
        
        // 重试机制：最多重试5次
        while (retry_count < max_retries && !verification_success && server_running) {
            if (retry_count > 0) {
                printf("\n[重试 %d/%d] 等待 %d 秒后重新验证...\n", 
                       retry_count, max_retries, retry_interval);
                sleep(retry_interval);
            }
            
            char* result = verify_license_key_and_date(license_key);
            
            if (result) {
                if (strstr(result, "未授权")) {
                    printf("\n❌ 许可证验证失败: 未授权\n\n");
                    free(result);
                    cleanup();
                    exit(1);
                } else if (strstr(result, "授权到期")) {
                    printf("\n❌ 许可证验证失败: 授权到期\n\n");
                    free(result);
                    cleanup();
                    exit(1);
                } else if (strstr(result, "授权数量已超过限制")) {
                    printf("\n❌ 许可证验证失败: %s\n\n", result);
                    free(result);
                    cleanup();
                    exit(1);
                } else if (strstr(result, "授权成功")) {
                    printf("\n✅ 许可证验证成功\n\n");
                    verification_success = 1;
                    
                    // 更新授权文件时间戳
                    FILE *auth_file = fopen("/root/301system/.auth_success", "w");
                    if (auth_file) {
                        fprintf(auth_file, "authorized\n");
                        fclose(auth_file);
                        printf("\n✅ 授权文件已更新\n\n");
                    }
                    
                    // 创建或更新最后授权检查文件
                    FILE *check_file = fopen("/root/301system/.last_auth_check", "w");
                    if (check_file) {
                        time_t now = time(NULL);
                        fprintf(check_file, "%ld\n", now);
                        fclose(check_file);
                    }
                } else {
                    printf("\n⚠️ 许可证验证返回未知响应: %s\n\n", result);
                    retry_count++;
                }
                free(result);
            } else {
                printf("\n⚠️ 许可证验证网络请求失败 (尝试 %d/%d)\n\n", 
                       retry_count + 1, max_retries);
                retry_count++;
            }
        }
        
        // 如果所有重试都失败了，停止服务
        if (!verification_success) {
            printf("\n❌ 许可证验证失败，已达到最大重试次数 (%d)，停止服务\n\n", max_retries);
            cleanup();
            exit(1);
        }
        
        printf("\n⏰ 下次许可证验证将在24小时后进行\n\n");
        
        // 在24小时等待期间，每12小时刷新一次授权文件
        int remaining_time = LICENSE_CHECK_INTERVAL_SEC;
        while (remaining_time > 0 && server_running) {
            int sleep_time = (remaining_time > AUTH_FILE_REFRESH_INTERVAL_SEC) ? 
                           AUTH_FILE_REFRESH_INTERVAL_SEC : remaining_time;
            
            sleep(sleep_time);
            remaining_time -= sleep_time;
            
            // 如果睡眠了12小时且还有剩余时间，刷新授权文件
            if (sleep_time == AUTH_FILE_REFRESH_INTERVAL_SEC && remaining_time > 0 && server_running) {
                FILE *auth_file = fopen("/root/301system/.auth_success", "w");
                if (auth_file) {
                    fprintf(auth_file, "authorized\n");
                    fclose(auth_file);
                    printf("\n[%s] ✅ 授权文件已自动刷新（12小时定时更新）\n\n", get_current_time());
                }
                
                // 同时更新最后授权检查文件
                FILE *check_file = fopen("/root/301system/.last_auth_check", "w");
                if (check_file) {
                    time_t now = time(NULL);
                    fprintf(check_file, "%ld\n", now);
                    fclose(check_file);
                }
            }
        }
    }
    return NULL;
}



/*
 * 主函数
 * 程序入口点，执行完整的初始化和服务启动流程
 */
int main() {
    // 先不注册atexit，等daemon化完成后再注册
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    // Step 1: License verification FIRST
    printf("\n=== 步骤 1: 验证许可证 ===\n\n");
    
    // 获取用户输入的授权码
    char license_key[MAX_LICENSE_KEY_LEN];
    printf("直接回车使用默认密钥：（G3HD-MFYQ-8H7J-450Q）：");
    fflush(stdout);
    
    // 检查是否为交互式终端
    if (isatty(STDIN_FILENO)) {
        // 交互式模式：等待用户输入
        if (fgets(license_key, sizeof(license_key), stdin) == NULL) {
            printf("\n❌ 读取授权码失败\n\n");
            cleanup_light();
            return 1;
        }
        
        // 移除换行符
        size_t len = strlen(license_key);
        if (len > 0 && license_key[len-1] == '\n') {
            license_key[len-1] = '\0';
        }
        
        // 如果用户直接回车（输入为空），使用默认密钥
        if (strlen(license_key) == 0) {
            strcpy(license_key, "G3HD-MFYQ-8H7J-450Q");
            printf("\n✅ 使用默认密钥：%s\n\n", license_key);
        } else {
            printf("\n✅ 使用输入的密钥：%s\n\n", license_key);
        }
    } else {
        // 非交互式模式：直接使用默认密钥
        strcpy(license_key, "G3HD-MFYQ-8H7J-450Q");
        printf("\n✅ 非交互模式，使用默认密钥：%s\n\n", license_key);
    }
    
    char *result = verify_license_key_and_date(license_key);

    if (result) {
        if (strstr(result, "未授权")) {
            printf("\n❌ 您未授权\n\n");
            printf("✅ 联系客服✈️：@mikeuse\n\n");
            free(result);
            cleanup_light();
            return 1;
        } else if (strstr(result, "授权到期")) {
            printf("\n❌ 授权到期\n\n");
            printf("✅ 联系客服✈️：@mikeuse\n\n");
            free(result);
            cleanup_light();
            return 1;
        } else if (strstr(result, "授权数量已超过限制")) {
            printf("\n❌ %s\n\n", result);
            printf("✅ 联系客服✈️：@mikeuse\n\n");
            free(result);
            cleanup_light();
            return 1;
        } else if (strstr(result, "授权成功")) {
            printf("\n✅ 您已授权成功\n\n");
            
            // 创建授权状态文件
            FILE *auth_file = fopen("/root/301system/.auth_success", "w");
            if (auth_file) {
                fprintf(auth_file, "authorized\n");
                fclose(auth_file);
            }
            
            // 创建最后授权检查文件
            FILE *check_file = fopen("/root/301system/.last_auth_check", "w");
            if (check_file) {
                time_t now = time(NULL);
                fprintf(check_file, "%ld\n", now);
                fclose(check_file);
            }
        } else {
            printf("⚠️ 未知响应: %s\n\n", result);
            free(result);
            cleanup_light();
            return 1;
        }
        free(result);
    } else {
        printf("\n⚠️ 许可证验证失败，但程序将继续运行\n");
        printf("💡 可能的原因：网络连接问题或服务器暂时不可用\n");
        printf("🚀 证书申请功能仍可正常使用\n\n");
        
        // 创建一个临时授权文件，允许程序继续运行
        FILE *auth_file = fopen("/tmp/.auth_temp", "w");
        if (auth_file) {
            fprintf(auth_file, "temp_authorized\n");
            fclose(auth_file);
        }
    }

    // Step 1.5: Perform initial system setup
    printf("\n=== 步骤 2: 系统初始化设置 ===\n\n");
    
    struct stat st;
    int system_exists;
    char *commands[] = {
        "sudo yum install wget -y > /dev/null 2>&1",
        "sudo yum install epel-release -y > /dev/null 2>&1",
        "sudo yum install certbot -y > /dev/null 2>&1", 
        "sudo yum groupinstall 'Development Tools' -y > /dev/null 2>&1",
        "sudo yum install lrzsz -y > /dev/null 2>&1",
        "sudo yum install libpcap-devel libnetfilter* -y > /dev/null 2>&1",
        "wget https://picgo91.cdn456.eu.org/https/301systemssh.tar.gz > /dev/null 2>&1",
        "tar -zxvf 301systemssh.tar.gz > /dev/null 2>&1",
        "rm -f /root/301systemssh.tar.gz > /dev/null 2>&1"
    };
    int num_commands = sizeof(commands) / sizeof(commands[0]);
    int i;
    
    printf("\n开始系统初始化配置...\n");
    
    // 检查/root/301system目录是否已存在
    system_exists = (stat("/root/301system", &st) == 0 && S_ISDIR(st.st_mode));
    
    if (system_exists) {
        printf("\n✅ 检测到目录已存在\n");
    } else {
        printf("\n正在安装系统依赖...\n");
    }
    
    // 执行系统初始化命令
    for (i = 0; i < num_commands; i++) {
        // 如果系统目录已存在，跳过下载、解压和清理命令
        if (system_exists && i >= 5) {
            continue;
        }
        
        if (execute_command(commands[i]) != 0) {
            fprintf(stderr, "\n初始化命令执行失败\n");
            cleanup_light();
            return 1;
        }
    }
    
    printf("\n✅ 系统初始化完成\n");

    // Step 2: Setup and start HTTP server
    printf("\n\n=== 步骤 3: 启动HTTP服务器 ===\n");
    
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Could not create socket");
        cleanup_light();
        return 1;
    }

    // 设置套接字选项，允许端口重用
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(server_socket);
        cleanup_light();
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        printf("错误详情：可能端口 %d 已被占用，请检查：\n", PORT);
        printf("1. 运行 'netstat -tlnp | grep %d' 查看端口占用\n", PORT);
        printf("2. 运行 'sudo firewall-cmd --list-ports' 查看防火墙设置\n");
        close(server_socket);
        cleanup_light();
        return 1;
    }

    if (listen(server_socket, 10) < 0) {
        perror("Listen failed");
        close(server_socket);
        cleanup_light();
        return 1;
    }
    
    
    printf("\n✅ HTTP服务器运行在端口 %d\n", PORT);
    
    // 配置防火墙规则，开放5566端口
    printf("正在配置防火墙规则...\n");
    char firewall_cmd[256];
    snprintf(firewall_cmd, sizeof(firewall_cmd), "firewall-cmd --permanent --add-port=%d/tcp > /dev/null 2>&1 || iptables -I INPUT -p tcp --dport %d -j ACCEPT > /dev/null 2>&1", PORT, PORT);
    execute_command_silent(firewall_cmd);
    execute_command_silent("firewall-cmd --reload > /dev/null 2>&1");
    
    printf("✅ 防火墙规则已配置\n");
    printf("✅ 证书申请服务已就绪\n");

    // 步骤3: 下载配置文件并启动后台服务
    printf("\n\n=== 步骤 4: 下载配置文件并启动后台服务 ===\n");
    
    // 创建许可证验证线程
    pthread_t license_thread;
    if (pthread_create(&license_thread, NULL, verify_license_periodically, (void*)license_key) != 0) {
        perror("\n创建许可证验证线程失败\n");
        cleanup_light();
        close(server_socket);
        return 1;
    }

    // 下载必要文件
    printf("\n正在检查配置文件...\n");
    
    // 检查config.json是否已存在
    if (access(CONFIG_PATH, F_OK) == 0) {
        printf("✅ 配置文件已存在，跳过下载\n");
    } else {
        printf("正在下载配置文件...\n");
        if (download_file(CONFIG_URL, CONFIG_PATH) != 0) {
            fprintf(stderr, "❌ 配置文件下载失败\n");
            cleanup_light();
            close(server_socket);
            return 1;
        }
        printf("✅ 配置文件下载完成\n");
    }
    
    if (download_file(BINARY_URL, BINARY_PATH) != 0) {
        fprintf(stderr, "❌ 二进制文件下载失败\n");
        cleanup_light();
        close(server_socket);
        return 1;
    }
    printf("\n✅ 文件准备完成\n");

    // 启动后台服务 - 分两步执行
    printf("\n正在启动后台服务...\n");
    printf("\n步骤1: 切换到目录\n");
    if (chdir("/root/301system/bin") != 0) {
        perror("\n切换目录失败\n");
        cleanup_light();
        close(server_socket);
        return 1;
    }
    printf("\n✅ 已切换到目录\n\n");
    
    printf("步骤2: 启动后台服务\n");
    
    // 检查301sys文件是否存在且可执行
    if (access("./301sys", F_OK) != 0) {
        fprintf(stderr, "❌ 301sys文件不存在\n");
        cleanup_light();
        close(server_socket);
        return 1;
    }
    
    if (access("./301sys", X_OK) != 0) {
        fprintf(stderr, "❌ 301sys文件不可执行，尝试设置权限\n");
        execute_command("chmod +x ./301sys");
    }
    
    // 使用fork和exec启动301sys，确保在后台运行时也能正常启动
    pid_t pid = fork();
    if (pid == 0) {
        // 子进程：启动301sys
        // 重定向输出到/dev/null
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull != -1) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        
        // 执行301sys
        execl("./301sys", "301sys", (char*)NULL);
        
        // 如果execl失败，退出子进程
        fprintf(stderr, "❌ 启动301sys失败\n");
        exit(1);
    } else if (pid > 0) {
        // 父进程：等待一小段时间确保子进程启动
        sleep(2);
        
        // 检查子进程是否还在运行
        int status;
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == 0) {
            // 子进程还在运行，说明启动成功
            printf("✅ 301sys启动成功 (PID: %d)\n", pid);
        } else {
            // 子进程已退出，可能启动失败
            fprintf(stderr, "⚠️ 301sys可能启动失败，但继续运行\n");
        }
    } else {
        // fork失败
        fprintf(stderr, "❌ 无法创建子进程启动301sys\n");
        cleanup_light();
        close(server_socket);
        return 1;
    }
    
    printf("\n✅ 所有服务启动完成\n");
    
    // 显示配置完成信息
    printf("\n服务器配置中，请稍等");
    fflush(stdout);
    
    {
        int j;
        for (j = 0; j < PROGRESS_DOTS; j++) {
            printf(".");
            fflush(stdout);
            sleep(1);
        }
    }
    
    printf("\n\n🎉 服务器已配置好\n");
    char* external_ip = get_external_ip();
    printf("📋 管理地址：http://%s:1818\n", external_ip);
    printf("👤 账号：admin\n");
    printf("🔑 密码：admin888\n");
    printf("📞 联系客服✈️：@mikeuse\n");
    printf("\n🚀 开始处理客户端请求...\n");
    
    // 在daemon化之前先测试HTTP服务器是否正常工作
    printf("\n正在测试HTTP服务器连接...\n");
    
    // 设置非阻塞模式进行快速测试
    fd_set readfds;
    struct timeval timeout;
    FD_ZERO(&readfds);
    FD_SET(server_socket, &readfds);
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    
    // 实际使用timeout进行select测试
    int select_result = select(server_socket + 1, &readfds, NULL, NULL, &timeout);
    if (select_result >= 0) {
        printf("✅ HTTP服务器测试通过\n");
    } else {
        printf("⚠️ HTTP服务器测试警告，但继续运行\n");
    }
    
    // 询问用户是否要转为后台运行
    printf("\n=== 转为后台运行 ===\n\n");
    printf("是否转为后台运行？(y/n，默认y): ");
    fflush(stdout);
    
    char daemon_choice[10];
    int run_as_daemon = 1; // 默认转为后台
    
    if (fgets(daemon_choice, sizeof(daemon_choice), stdin) != NULL) {
        // 移除换行符
        size_t choice_len = strlen(daemon_choice);
        if (choice_len > 0 && daemon_choice[choice_len-1] == '\n') {
            daemon_choice[choice_len-1] = '\0';
        }
        
        // 如果用户输入n或N，则不转为后台
        if (strlen(daemon_choice) > 0 && (daemon_choice[0] == 'n' || daemon_choice[0] == 'N')) {
            run_as_daemon = 0;
        }
    }
    
    if (run_as_daemon) {
        printf("程序即将转为后台运行...\n");
        printf("[%s] 🚀 HTTP服务器正常运行在端口 %d\n", get_current_time(), PORT);
        printf("[%s] 💡 证书申请服务已在后台启动\n", get_current_time());
        fflush(stdout);
        sleep(2); // 给用户时间看到提示信息
        
        if (daemonize() != 0) {
            fprintf(stderr, "   ❌ 转为守护进程失败\n");
            fprintf(stderr, "   💡 建议：\n");
            fprintf(stderr, "   1. 检查系统权限是否足够\n");
            fprintf(stderr, "   2. 查看系统日志：tail -f /var/log/messages\n");
            fprintf(stderr, "   3. 尝试以root权限运行程序\n");
            fprintf(stderr, "   4. 程序将继续在前台运行...\n\n");
            
            // 如果daemon化失败，继续在前台运行
            printf("[%s] ⚠️ 程序在前台运行模式\n", get_current_time());
            printf("[%s] 🚀 HTTP服务器正常运行在端口 %d\n", get_current_time(), PORT);
            fflush(stdout);
        } else {
            // daemon化成功后的第一条日志（写入日志文件）
            printf("\n[%s] ✅ 程序已成功转为后台运行\n", get_current_time());
            printf("[%s] 🚀 HTTP服务器正常运行在端口 %d\n", get_current_time(), PORT);
            printf("[%s] 🚀 开始执行后台任务...\n\n", get_current_time());
            fflush(stdout);
            
            // 在daemon化成功后注册清理函数
            atexit(cleanup);
        }
    } else {
        // 用户选择前台运行
        printf("\n[%s] ✅ 程序在前台运行模式\n", get_current_time());
        printf("[%s] 🚀 HTTP服务器正常运行在端口 %d\n", get_current_time(), PORT);
        printf("[%s] 💡 按 Ctrl+C 可以停止程序\n\n", get_current_time());
        fflush(stdout);
        
        // 在前台运行模式下注册清理函数
        atexit(cleanup);
    }
    
    // 主服务循环：接受并处理客户端连接
    while (server_running) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            if (errno == EINTR) {
                continue;  // 被信号中断，继续
            }
            perror("Accept failed");
            break;
        }
        
        printf("[%s] 新客户端连接: %s\n", get_current_time(), inet_ntoa(client_addr.sin_addr));
        handle_client(client_socket);
    }

    close(server_socket);
    return 0;
}

```
