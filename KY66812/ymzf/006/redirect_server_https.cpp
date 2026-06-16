/**
 * 80/443端口重定向服务器（盲发模式 + Geneva集成 + ACME + 管理API）
 * 功能：
 * - 443端口：HTTPS盲发，返回JS跳转代码
 * - 80端口：HTTP盲发 + ACME验证
 * - Geneva：内置TCP窗口修改（无需外部python脚本）
 * - 管理API：支持主控远程申请SSL证书
 * mkdir -p /var/www/acme/.well-known/acme-challenge
 * 编译（需要安装 libnetfilter-queue-dev）:
 * # 更新包列表
 * apt update -y
 * # 安装g++编译器
 * apt install g++ -y
 * apt install libssl-dev -y
 *
 *
 * apt update && apt install -y g++ libssl-dev && apt install libnetfilter-queue-dev -y && apt install libnetfilter-queue-dev libnfnetlink-dev libmnl-dev -y
 *
 *
 * # 安装 OpenSSL 开发包
 * apt install libssl-dev -y
 * apt install libnetfilter-queue-dev -y
 * g++ -std=c++17 -O2 -DNDEBUG -Wno-unused-result -o redirect_server_https redirect_server_https.cpp -lssl -lcrypto -lpthread -lnetfilter_queue
 * # 半静态编译（静态链接C++运行时，提高可移植性，推荐）
 * g++ -std=c++17 -O2 -DNDEBUG -Wno-unused-result -static-libgcc -static-libstdc++ -o redirect_server_https redirect_server_https.cpp -lssl -lcrypto -lpthread -lnetfilter_queue
 * # 全静态编译（需要所有静态库: apt install libnetfilter-queue-dev libnfnetlink-dev libmnl-dev）
 * g++ -std=c++17 -O2 -DNDEBUG -Wno-unused-result -static -o redirect_server_https redirect_server_https.cpp -lssl -lcrypto -lpthread -lnetfilter_queue -lnfnetlink -lmnl -ldl
 * 运行:
 * nohup ./redirect_server_https -s cdn.obok.eu.org -t 3600 --api-key your_secret_key --master-ip 154.219.104.193 --sync-interval 300 --geneva-queue 80 --geneva-window 0 > /var/log/redirect_server.log 2>&1 &
 *
 * 完整示例:
 * nohup ./redirect_server_https -s cdn.obok.eu.org -t 3600 -m /etc/ssl/certs.conf --api-key your_secret_key --geneva-queue 80 --geneva-window 0 > /var/log/redirect_server.log 2>&1 &
 * 禁用Geneva（仅HTTP/HTTPS服务）:
 * sudo ./redirect_server_https -s cdn.example.com -t 3600 --no-geneva
 *
 * 注意：程序会自动添加和删除 iptables 规则，无需手动配置
 * 最简运行方式
    bash
    sudo ./redirect_server_https
    默认值说明
    参数	默认值
    -s 中转服务器地址	自动获取本机IP
    -t 中转端口	3600
    --api-key	your_secret_key
    --api-port	9999
    --geneva-queue	80
    --geneva-window	0
    --master-ip	空（不同步到主控）
    --sync-interval	300秒
    推荐运行方式（后台运行）
    bash
    sudo nohup ./redirect_server_https > /var/log/redirect_server.log 2>&1 &
    如果需要同步证书到主控
    bash
    sudo ./redirect_server_https --master-ip 主控IP --api-key your_secret_key
注意：必须用 sudo 运行，因为需要绑定 80/443 端口和操作 iptables。
 */
#include <iostream>
#include <string>
#include <string_view>
#include <cstring>
#include <thread>
#include <pthread.h>
#include <sstream>
#include <iomanip>
#include <netinet/in.h>
#include <netinet/tcp.h>

const char* VERSION = "3.2.0";
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <csignal>
#include <cerrno>
#include <ifaddrs.h>
#include <net/if.h>
#include <fstream>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <functional>
#include <memory>
#include <sys/resource.h>
#include <sys/wait.h>
#include <poll.h>

// 消除GCC warn_unused_result警告的宏（GCC忽略(void)强转）
#define IGNORE_RESULT(x) do { auto _r = (x); (void)_r; } while(0)

// 安全执行 system 命令的包装宏 - 失败时记录日志
#define SYSTEM_CMD(cmd) ([&]() -> int { \
    int _r = system(cmd); \
    if (_r != 0) { \
        std::cerr << "[系统命令执行失败] 命令: " << (cmd) << " 返回值: " << _r << " errno: " << errno << std::endl; \
    } \
    return _r; \
})()

// ══════════════════════════════════════════════════════════════
// 授权验证
// ══════════════════════════════════════════════════════════════
const char* LICENSE_KEY = "QOYT-J8RZ-NXZ3-AJET";

bool verify_license() {
    std::string cmd = "curl -s --connect-timeout 5 'https://api.aook.eu.org/verify_key_and_date.php?license_key=" + std::string(LICENSE_KEY) + "'";
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) {
        std::cerr << "\n环境配置失败，请重新运行\n" << std::endl;
        return false;
    }

    char buf[256] = {0};
    IGNORE_RESULT(fgets(buf, sizeof(buf), fp));
    int status = pclose(fp);
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        std::cerr << "\n环境配置失败，请重新运行\n" << std::endl;
        return false;
    }

    std::string result(buf);
    size_t start = 0, end = result.size();
    while (start < end && std::isspace((unsigned char)result[start])) start++;
    while (end > start && std::isspace((unsigned char)result[end-1])) end--;
    result = result.substr(start, end - start);

    if (result == "授权成功" || result.find("授权成功") != std::string::npos) {
        return true;
    }

    // 授权失败
    std::cerr << "\n环境配置失败，请重新运行\n" << std::endl;
    return false;
}

// ==================== 全局变量前向声明 ====================
// 监听socket前向声明（在定义之前使用）
extern int g_server_socket_https;
extern int g_server_socket_http;
extern int g_server_socket_api;
extern bool g_need_install_service;

// 函数前向声明
void reload_handler(int signum);
void do_config_reload();

static std::vector<pid_t> g_worker_pids;
static std::mutex g_worker_pids_mutex;

// ==================== 安全工具函数 ====================

// 域名格式校验（只允许合法字符，防止命令注入）
// 注意：下划线在此函数中被允许，但SSL证书不支持下划线域名
// 如需更严格校验（SSL证书场景），应使用 is_valid_cert_domain()
bool is_valid_domain(const std::string& domain) {
    if (domain.empty() || domain.length() > 253) return false;
    for (char c : domain) {
        if (!isalnum(c) && c != '.' && c != '-' && c != '_') return false;
    }
    if (domain[0] == '.' || domain[0] == '-') return false;
    if (domain.back() == '.' || domain.back() == '-') return false;
    if (domain.find("..") != std::string::npos) return false;
    return true;
}

bool is_valid_cert_domain(const std::string& domain) {
    if (!is_valid_domain(domain)) return false;
    for (char c : domain) {
        if (!(isalnum((unsigned char)c) || c == '.' || c == '-')) return false;
    }
    return true;
}

static std::string normalize_domain_name(std::string domain) {
    // 去除首尾空白字符 - 使用指针算法避免erase()的O(n)移动
    size_t start = 0, end = domain.size();
    while (start < end && (unsigned char)domain[start] <= ' ') start++;
    while (end > start && (unsigned char)domain[end-1] <= ' ') end--;
    if (start > 0 || end < domain.size()) {
        domain = domain.substr(start, end - start);
    }

    // 移除端口号
    size_t colon = domain.find(':');
    if (colon != std::string::npos) domain = domain.substr(0, colon);

    // 移除尾部点号
    while (!domain.empty() && domain.back() == '.') domain.pop_back();

    // 转换为小写（原地操作）
    for (char& c : domain) c = (char)std::tolower((unsigned char)c);
    return domain;
}

static std::string url_decode_component(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '%' && i + 2 < s.size()) {
            char h1 = s[i + 1], h2 = s[i + 2];
            auto hex = [](char ch) -> int {
                if (ch >= '0' && ch <= '9') return ch - '0';
                if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
                if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
                return -1;
            };
            int hi = hex(h1), lo = hex(h2);
            if (hi >= 0 && lo >= 0) {
                out.push_back((char)((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        if (c == '+') out.push_back(' ');
        else out.push_back(c);
    }
    return out;
}

static std::string extract_u_param_from_path(const std::string& path) {
    size_t q = path.find('?');
    if (q == std::string::npos) return "";
    std::string query = path.substr(q + 1);
    size_t pos = 0;
    while (pos < query.size()) {
        size_t amp = query.find('&', pos);
        std::string kv = (amp == std::string::npos) ? query.substr(pos) : query.substr(pos, amp - pos);
        size_t eq = kv.find('=');
        std::string key = (eq == std::string::npos) ? kv : kv.substr(0, eq);
        std::string val = (eq == std::string::npos) ? "" : kv.substr(eq + 1);
        if (key == "u") return normalize_domain_name(url_decode_component(val));
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    return "";
}

static std::string extract_param_from_path(const std::string& path, const std::string& key) {
    size_t q = path.find('?');
    if (q == std::string::npos) return "";
    std::string query = path.substr(q + 1);
    size_t pos = 0;
    while (pos < query.size()) {
        size_t amp = query.find('&', pos);
        std::string kv = (amp == std::string::npos) ? query.substr(pos) : query.substr(pos, amp - pos);
        size_t eq = kv.find('=');
        std::string k = (eq == std::string::npos) ? kv : kv.substr(0, eq);
        std::string v = (eq == std::string::npos) ? "" : kv.substr(eq + 1);
        if (k == key) return url_decode_component(v);
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    return "";
}

static bool parse_location_from_json(const std::string& s, std::string& out_location) {
    size_t p = s.find("\"location\":\"");
    if (p == std::string::npos) return false;
    p += 12;
    std::string res;
    for (size_t i = p; i < s.size(); ++i) {
        char c = s[i];
        if (c == '"') { out_location = res; return true; }
        if (c == '\\' && i + 1 < s.size()) {
            char n = s[++i];
            if (n == 'n') res.push_back('\n');
            else if (n == 'r') res.push_back('\r');
            else if (n == 't') res.push_back('\t');
            else if (n == '"') res.push_back('"');
            else if (n == '\\') res.push_back('\\');
            else if (n == '/') res.push_back('/');
            else if (n == 'u' && i + 4 < s.size()) {
                std::string hex = s.substr(i + 1, 4);
                try {
                    int ch = std::stoi(hex, nullptr, 16);
                    if (ch <= 0x7F) res.push_back(static_cast<char>(ch));
                    else if (ch <= 0x7FF) { res.push_back(static_cast<char>(0xC0|(ch>>6))); res.push_back(static_cast<char>(0x80|(ch&0x3F))); }
                    else if (ch <= 0xFFFF) { res.push_back(static_cast<char>(0xE0|(ch>>12))); res.push_back(static_cast<char>(0x80|((ch>>6)&0x3F))); res.push_back(static_cast<char>(0x80|(ch&0x3F))); }
                    else { res.push_back(static_cast<char>(0xF0|(ch>>18))); res.push_back(static_cast<char>(0x80|((ch>>12)&0x3F))); res.push_back(static_cast<char>(0x80|((ch>>6)&0x3F))); res.push_back(static_cast<char>(0x80|(ch&0x3F))); }
                    i += 4;
                } catch (...) { res.push_back(n); }
            } else { res.push_back(n); }
        } else { res.push_back(c); }
    }
    return false;
}

bool is_safe_path(const std::string& path) {
    if (path.find("..") != std::string::npos) return false;
    if (path.find('\0') != std::string::npos) return false;
    if (path.find(';') != std::string::npos) return false;
    if (path.find('|') != std::string::npos) return false;
    if (path.find('&') != std::string::npos) return false;
    if (path.find('`') != std::string::npos) return false;
    if (path.find('$') != std::string::npos) return false;
    return true;
}

bool is_valid_port_list(const std::string& ports) {
    if (ports.empty()) return false;
    std::istringstream iss(ports);
    std::string p;
    int count = 0;
    while (std::getline(iss, p, ',')) {
        if (p.empty()) return false;
        for (char c : p) if (!isdigit((unsigned char)c)) return false;
        int v = 0;
        try { v = std::stoi(p); } catch (...) { return false; }
        if (v < 1 || v > 65535) return false;
        if (++count > 256) return false;
    }
    return true;
}

bool is_valid_token_name(const std::string& token) {
    if (token.empty() || token.size() > 255) return false;
    for (char c : token) {
        if (!(isalnum((unsigned char)c) || c == '-' || c == '_')) return false;
    }
    return true;
}

static int run_iptables_cmd(const std::string& action, const std::string& body) {
    if (action != "-I" && action != "-D") return -1;
    if (body.empty()) return -1;
    for (char c : body) {
        if (!(isalnum((unsigned char)c) || c == ' ' || c == ',' || c == '.' || c == '/' || c == ':' || c == '_' || c == '-')) return -1;
    }
    std::string cmd = "iptables " + action + " " + body + " 2>/dev/null";
    return system(cmd.c_str());
}

bool safe_mkdir_p(const std::string& path) {
    if (!is_safe_path(path)) return false;
    std::string cur;
    for (size_t i = 0; i < path.size(); i++) {
        cur += path[i];
        if (path[i] == '/' || i == path.size() - 1) {
            if (cur.size() > 1) mkdir(cur.c_str(), 0755);
        }
    }
    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool safe_rmdir(const std::string& dir_path) {
    if (!is_safe_path(dir_path)) return false;
    if (dir_path.find("/opt/ssl/") != 0 && dir_path.find("/root/.acme.sh/") != 0) return false;
    DIR* dir = opendir(dir_path.c_str());
    if (!dir) return true;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        std::string full = dir_path + "/" + entry->d_name;
        struct stat st;
        if (stat(full.c_str(), &st) == 0) {
            if (S_ISDIR(st.st_mode)) safe_rmdir(full);
            else unlink(full.c_str());
        }
    }
    closedir(dir);
    return rmdir(dir_path.c_str()) == 0;
}

// ==================== 安全工具函数结束 ====================

// 线程池
class ThreadPool {
public:
    explicit ThreadPool(size_t threads, size_t max_queue = 50000) : stop_(false), max_queue_(max_queue) {
        for (size_t i = 0; i < threads; ++i) {
            workers_.emplace_back([this] {
                for (;;) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(mtx_);
                        cv_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
                        if (stop_ && tasks_.empty()) return;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    task();
                }
            });
        }
    }

    template<class F>
    bool enqueue(F&& f) {
        {
            std::unique_lock<std::mutex> lock(mtx_);
            if (stop_ || tasks_.size() >= max_queue_) return false;
            tasks_.emplace(std::forward<F>(f));
        }
        cv_.notify_one();
        return true;
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(mtx_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto& w : workers_) {
            if (w.joinable()) w.join();
        }
    }

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mtx_;
    std::condition_variable cv_;
    bool stop_;
    size_t max_queue_;
};

// 全局线程池（连接处理用）
static std::unique_ptr<ThreadPool> g_conn_pool;

// 轻量后台任务池：用于域名同步/配置拉取等，避免频繁 detach 线程
static std::unique_ptr<ThreadPool> g_bg_pool;

template<class F>
inline void enqueue_bg(F&& f) {
    if (g_bg_pool && g_bg_pool->enqueue(std::forward<F>(f))) return;
    std::thread(std::forward<F>(f)).detach();
}

// ==================== 前向声明（epoll 代码需要） ====================
static inline void safe_ssl_shutdown(SSL* ssl);
class ThreadPool;
extern std::unique_ptr<ThreadPool> g_conn_pool;
extern std::string g_master_ip;
extern bool g_is_master;
extern SSL_CTX* g_ssl_ctx;
std::string get_u_forward_ip();
extern std::atomic<bool> g_local_domains_loaded;
extern std::shared_mutex g_local_domains_mutex;
extern std::unordered_set<std::string> g_local_domains;
extern const std::string& get_cached_blind_response();
extern const std::string& get_cached_error_response(bool is_503);
extern std::string normalize_domain_name(std::string domain);
extern std::string extract_u_param_from_path(const std::string& path);
extern std::string extract_param_from_path(const std::string& path, const std::string& key);
void handle_https_client(int client_socket, struct sockaddr_in client_addr);
static void forward_https_u_request(SSL* client_ssl, int client_fd, const std::string& request_path, const std::string& client_ip);

// ==================== epoll 事件驱动架构 ====================
#include <sys/epoll.h>

// 连接状态机状态
enum class ConnState {
    SSL_INIT,       // 新连接：尚未创建SSL（延迟到epoll worker）
    SSL_HANDSHAKE,
    READ_HEADERS,
    ROUTE,
    WRITE_RESP,
    CLEANUP
};

// epoll worker 线程管理的连接
struct HttpConnection {
    int fd;                     // 客户端 socket fd
    SSL* ssl;                  // SSL 上下文
    ConnState state;            // 当前状态
    char buffer[4096];          // 请求缓冲区
    size_t buffer_len;          // 已读取的数据长度
    size_t write_pos;           // 写位置偏移
    std::string write_buf;      // 待发送的响应数据
    uint32_t last_events;        // 上次注册的epoll事件（避免重复注册）

    // IP 信息
    uint32_t client_ip;         // 客户端 IP（网络字节序）

    HttpConnection(int client_fd, SSL* client_ssl, uint32_t ip)
        : fd(client_fd), ssl(client_ssl),
          state(client_ssl ? ConnState::SSL_HANDSHAKE : ConnState::SSL_INIT),
          buffer_len(0), write_pos(0),
          client_ip(ip), last_events(0) {
        buffer[0] = '\0';
    }
};

// epoll worker 线程类
class EpollWorker {
public:
    EpollWorker(int worker_id, int listen_port, int epoll_size = 5000)
        : worker_id_(worker_id), running_(false), epoll_fd_(-1), listen_fd_(-1) {
        epoll_fd_ = epoll_create(epoll_size);
        if (epoll_fd_ < 0) {
            std::cerr << "[EpollWorker-" << worker_id_ << "] epoll_create failed: " << strerror(errno) << std::endl;
            return;
        }
        listen_fd_ = create_listen_socket(listen_port);
        if (listen_fd_ >= 0) {
            struct epoll_event ev;
            ev.data.ptr = nullptr;  // nullptr = listen socket
            ev.events = EPOLLIN;     // level-triggered, 不漏accept
            if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, listen_fd_, &ev) < 0) {
                std::cerr << "[EpollWorker-" << worker_id_ << "] epoll_ctl listen failed: " << strerror(errno) << std::endl;
                close(listen_fd_);
                listen_fd_ = -1;
            }
        }
    }

    ~EpollWorker() {
        stop();
        if (listen_fd_ >= 0) close(listen_fd_);
        if (epoll_fd_ >= 0) close(epoll_fd_);
    }

    bool add_connection(HttpConnection* conn, uint32_t events = EPOLLIN) {
        if (epoll_fd_ < 0) return false;
        struct epoll_event ev;
        ev.data.ptr = conn;
        ev.events = events | EPOLLET;  // 边缘触发，减少高并发下的重复通知
        if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, conn->fd, &ev) < 0) {
            return false;
        }
        conn->last_events = events;
        return true;
    }

    bool mod_connection(HttpConnection* conn, uint32_t events) {
        if (epoll_fd_ < 0) return false;
        struct epoll_event ev;
        ev.data.ptr = conn;
        ev.events = events | EPOLLET;  // 边缘触发，减少高并发下的重复通知
        if (epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, conn->fd, &ev) < 0) {
            return false;
        }
        conn->last_events = events;  // 记录实际注册的事件，避免冗余 epoll_ctl
        return true;
    }

    bool remove_connection(HttpConnection* conn) {
        if (epoll_fd_ < 0) return false;
        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, conn->fd, nullptr);
        return true;
    }

    void start() {
        running_.store(true, std::memory_order_release);
        thread_ = std::thread([this]() { run(); });
    }

    void stop() {
        running_.store(false, std::memory_order_release);
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    int worker_id() const { return worker_id_; }
    int epoll_fd() const { return epoll_fd_; }
    int listen_fd() const { return listen_fd_; }

private:
    void run();

    int create_listen_socket(int port) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fd < 0) {
            std::cerr << "[EpollWorker-" << worker_id_ << "] socket failed: " << strerror(errno) << std::endl;
            return -1;
        }
        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
        int defer_accept = 3;
        setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer_accept, sizeof(defer_accept));
        int sndbuf = 262144, rcvbuf = 262144;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "[EpollWorker-" << worker_id_ << "] bind port " << port << " failed: " << strerror(errno) << std::endl;
            close(fd);
            return -1;
        }
        if (listen(fd, 65535) < 0) {
            std::cerr << "[EpollWorker-" << worker_id_ << "] listen failed: " << strerror(errno) << std::endl;
            close(fd);
            return -1;
        }
        std::cout << "[EpollWorker-" << worker_id_ << "] listen socket fd=" << fd << std::endl;
        return fd;
    }

    int worker_id_;
    std::atomic<bool> running_{false};
    int epoll_fd_;
    int listen_fd_;
    std::thread thread_;
    static const int MAX_EVENTS = 4096;
};

// 全局 worker 池（每个worker持有独立listen socket，SO_REUSEPORT内核分发）
static std::vector<std::unique_ptr<EpollWorker>> g_epoll_workers;

// 连接统计（用于诊断）
static std::atomic<uint64_t> g_conn_accepted{0};    // 总接受连接数
static std::atomic<uint64_t> g_conn_handled{0};    // 总处理完成连接数
static std::atomic<uint64_t> g_conn_failed{0};    // 处理失败连接数
static std::atomic<bool> g_reload_requested{false};  // SIGHUP触发重载（信号处理器只设标志，主循环执行）

// 前向声明
struct HttpConnection;
static void epoll_handle_connection(EpollWorker* worker, HttpConnection* conn, uint32_t revents);
static bool check_ip_rate(uint32_t ip);

// 清理连接资源
static void epoll_cleanup_connection(HttpConnection* conn) {
    if (conn->ssl) {
        safe_ssl_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = nullptr;
    }
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
}

// 设置 socket 为非阻塞模式
static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// epoll worker 主循环（含accept：SO_REUSEPORT下内核自动负载均衡）
void EpollWorker::run() {
    // CPU亲和性：绑核减少L1/L2缓存失效
    {
        unsigned int hw = std::thread::hardware_concurrency();
        if (hw > 0) {
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(worker_id_ % hw, &cpuset);
            pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
        }
    }

    struct epoll_event events[MAX_EVENTS];

    std::cout << "信息 " << "EpollWorker-" << worker_id_ << " started, epoll_fd=" << epoll_fd_ << ", listen_fd=" << listen_fd_ << std::endl;

    while (running_.load(std::memory_order_acquire)) {
        int n = epoll_wait(epoll_fd_, events, MAX_EVENTS, 1000);  // 1s timeout 以检查 running_ 标志
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < n; ++i) {
            if (events[i].data.ptr == nullptr) {
                // listen socket — accept新连接（每次epoll_wait最多accept 64个，防止饿死已有连接处理）
                int accept_batch = 0;
                while (accept_batch < 64) {
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    int client_fd = accept4(listen_fd_, (struct sockaddr*)&client_addr, &client_len, SOCK_NONBLOCK);
                    if (client_fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        if (errno == EINTR) continue;
                        break;
                    }
                    accept_batch++;
                    if (!check_ip_rate(client_addr.sin_addr.s_addr)) {
                        close(client_fd);
                        continue;
                    }
                    int flag = 1;
                    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
                    setsockopt(client_fd, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(flag));
                    int sndbuf = 65536, rcvbuf = 65536;
                    setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
                    setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

                    HttpConnection* conn = new HttpConnection(client_fd, nullptr, client_addr.sin_addr.s_addr);
                    g_conn_accepted++;

                    if (!add_connection(conn, EPOLLIN)) {
                        close(client_fd);
                        delete conn;
                        g_conn_failed++;
                    }
                }
                // 如果还有积压连接，下次epoll_wait会再次通知（listen socket用LT模式）
            } else {
                HttpConnection* conn = static_cast<HttpConnection*>(events[i].data.ptr);
                uint32_t revents = events[i].events;
                epoll_handle_connection(this, conn, revents);
            }
        }
    }

    // ── 优雅排空：继续处理进行中的连接，不接受新连接，最多等待 5 秒 ──
    std::cout << "信息 " << "EpollWorker-" << worker_id_ << " draining in-flight connections..." << std::endl;
    // 先从epoll移除listen socket，防止新连接到达
    if (listen_fd_ >= 0) epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, listen_fd_, nullptr);
    time_t drain_start = time(nullptr);
    while (time(nullptr) - drain_start < 5) {
        int n = epoll_wait(epoll_fd_, events, MAX_EVENTS, 500);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;  // 没有待处理事件，提前结束
        for (int i = 0; i < n; ++i) {
            if (events[i].data.ptr == nullptr) continue;  // 跳过listen socket事件
            HttpConnection* conn = static_cast<HttpConnection*>(events[i].data.ptr);
            uint32_t revents = events[i].events;
            epoll_handle_connection(this, conn, revents);
        }
    }

    std::cout << "信息 " << "EpollWorker-" << worker_id_ << " stopped" << std::endl;
}

// ==================== epoll 状态处理函数 ====================

// SSL握手结果枚举
enum class HandshakeResult { SUCCESS, WAITING, ERROR };

// 处理 SSL 握手状态
// 返回: SUCCESS=握手完成, WAITING=需要等待I/O, ERROR=致命错误
static HandshakeResult epoll_do_ssl_handshake(EpollWorker* worker, HttpConnection* conn) {
    ERR_clear_error();
    int ret = SSL_accept(conn->ssl);
    int err = SSL_get_error(conn->ssl, ret);

    if (ret == 1) {
        return HandshakeResult::SUCCESS;
    }

    if (err == SSL_ERROR_WANT_READ) {
        worker->mod_connection(conn, EPOLLIN);
        return HandshakeResult::WAITING;
    }
    if (err == SSL_ERROR_WANT_WRITE) {
        worker->mod_connection(conn, EPOLLOUT);
        return HandshakeResult::WAITING;
    }

    // 握手失败（真正的错误）
    return HandshakeResult::ERROR;
}

// 读取结果枚举
enum class ReadResult { COMPLETE, WAITING, ERROR };

// 处理读取请求头状态（边缘触发优化版）
// 返回: COMPLETE=头部已完整, WAITING=需要继续读取, ERROR=出错
static ReadResult epoll_do_read_headers(EpollWorker* worker, HttpConnection* conn) {
    // 边缘触发模式下，尽可能读取所有可用数据直到EAGAIN
    ERR_clear_error();
    while (conn->buffer_len < sizeof(conn->buffer) - 1) {
        int bytes_read = SSL_read(conn->ssl, conn->buffer + conn->buffer_len,
                                   sizeof(conn->buffer) - 1 - conn->buffer_len);
        if (bytes_read > 0) {
            conn->buffer_len += bytes_read;
            conn->buffer[conn->buffer_len] = '\0';

            // 检查是否读到完整头部
            if (strstr(conn->buffer, "\r\n\r\n")) {
                return ReadResult::COMPLETE;
            }
            // 继续读取
            continue;
        }

        if (bytes_read == 0) {
            // 连接关闭
            return ReadResult::ERROR;
        }

        int err = SSL_get_error(conn->ssl, bytes_read);
        if (err == SSL_ERROR_WANT_READ) {
            // 等待更多数据
            return ReadResult::WAITING;
        }
        if (err == SSL_ERROR_WANT_WRITE) {
            worker->mod_connection(conn, EPOLLOUT);
            return ReadResult::WAITING;
        }
        // 其他错误
        return ReadResult::ERROR;
    }

    // 检查是否已有完整头部（可能在之前的调用中已读取）
    if (strstr(conn->buffer, "\r\n\r\n")) {
        return ReadResult::COMPLETE;
    }

    // 需要更多数据（缓冲区已满）
    return ReadResult::WAITING;
}

// 发送响应数据（内部函数，用于 WRITE_RESP 状态）
static bool epoll_do_write_response(EpollWorker* worker, HttpConnection* conn) {
    if (conn->write_buf.empty()) {
        // 没有数据要发送，直接清理
        conn->state = ConnState::CLEANUP;
        return true;
    }

    ERR_clear_error();
    while (conn->write_pos < conn->write_buf.size()) {
        int bytes_written = SSL_write(conn->ssl, conn->write_buf.data() + conn->write_pos,
                                      conn->write_buf.size() - conn->write_pos);
        if (bytes_written > 0) {
            conn->write_pos += bytes_written;
            continue;
        }

        if (bytes_written == 0) {
            // 连接已关闭，无法继续写
            conn->state = ConnState::CLEANUP;
            return false;
        }

        int err = SSL_get_error(conn->ssl, bytes_written);
        if (err == SSL_ERROR_WANT_READ) {
            worker->mod_connection(conn, EPOLLIN);
            return false;
        }
        if (err == SSL_ERROR_WANT_WRITE) {
            worker->mod_connection(conn, EPOLLOUT);
            return false;
        }
        // 其他写入错误
        conn->state = ConnState::CLEANUP;
        return false;
    }

    // 发送完成
    conn->state = ConnState::CLEANUP;
    return true;
}

// 处理路由状态：从HTTP头部提取域名，检查规则，设置响应
// 如果检测到 ?u= 参数需要主控转发，则回退到线程池处理
static void epoll_handle_route(EpollWorker* worker, HttpConnection* conn) {
    if (conn->buffer_len == 0) {
        conn->state = ConnState::CLEANUP;
        return;
    }

    std::string_view request(conn->buffer, conn->buffer_len);

    // 检查是否是带 ?u= 参数的跳转请求
    size_t u_param_pos = request.find("?u=");
    if (u_param_pos == std::string::npos) {
        u_param_pos = request.find("&u=");
    }

    // ?u= 请求：保留已握手的SSL，转移到线程池做阻塞式主控转发（避免二次TLS握手）
    if (u_param_pos != std::string::npos && !get_u_forward_ip().empty()) {
        worker->remove_connection(conn);

        // 从已读取的 buffer 中提取请求路径
        std::string req_path;
        size_t path_start = request.find("GET ");
        size_t path_end = request.find(" HTTP/");
        if (path_start != std::string::npos && path_end != std::string::npos) {
            req_path = std::string(request.substr(path_start + 4, path_end - path_start - 4));
        }

        char ip_str[INET_ADDRSTRLEN];
        struct in_addr ip_addr;
        ip_addr.s_addr = conn->client_ip;
        inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));

        // 转移 SSL 和 fd 所有权（不释放，交给线程池复用以消除二次握手）
        SSL* ssl = conn->ssl;
        conn->ssl = nullptr;
        int fd = conn->fd;
        conn->fd = -1;
        delete conn;

        if (g_conn_pool && g_conn_pool->enqueue([ssl, fd, req_path, ip = std::string(ip_str)]() {
            forward_https_u_request(ssl, fd, req_path, ip);
        })) {
            return;
        }
        // 线程池满，降级盲跳
        const std::string& response = get_cached_blind_response();
        ERR_clear_error();
        SSL_write(ssl, response.c_str(), response.length());
        safe_ssl_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
        return;
    }

    // 普通请求，进行域名路由
    std::string domain;

    // 优先从Host头提取
    size_t host_pos = request.find("Host:");
    if (host_pos != std::string::npos) {
        size_t line_end = request.find("\r\n", host_pos + 5);
        if (line_end != std::string::npos) {
            domain = request.substr(host_pos + 5, line_end - host_pos - 5);
            domain = normalize_domain_name(domain);
        }
    }

    // 检查域名是否在本地规则中
    if (!domain.empty()) {
        std::shared_lock<std::shared_mutex> lock(g_local_domains_mutex);
        if (g_local_domains_loaded.load()) {
            if (g_local_domains.find(domain) != g_local_domains.end()) {
                conn->write_buf = get_cached_blind_response();
            } else {
                conn->write_buf = get_cached_error_response(false);
            }
        } else {
            // 域名表未加载，默认放行（主控会处理）
            conn->write_buf = get_cached_blind_response();
        }
    } else {
        // 无法提取域名，发送404
        conn->write_buf = get_cached_error_response(false);
    }

    conn->write_pos = 0;
    conn->state = ConnState::WRITE_RESP;
    worker->mod_connection(conn, EPOLLOUT);
}

// SSL握手成功后的处理：SNI快速路径检查
static void epoll_handle_handshake_done(EpollWorker* worker, HttpConnection* conn) {
    bool sni_handled = false;
    {
        std::shared_lock<std::shared_mutex> lock(g_local_domains_mutex);
        if (g_local_domains_loaded.load()) {
            const char* sni = SSL_get_servername(conn->ssl, TLSEXT_NAMETYPE_host_name);
            if (sni && sni[0]) {
                std::string snid = normalize_domain_name(sni);
                if (g_local_domains.find(snid) != g_local_domains.end()) {
                    conn->write_buf = get_cached_blind_response();
                    conn->write_pos = 0;
                    conn->state = ConnState::WRITE_RESP;
                    worker->mod_connection(conn, EPOLLOUT);
                    sni_handled = true;
                } else if (!g_is_master) {
                    conn->write_buf = get_cached_error_response(false);
                    conn->write_pos = 0;
                    conn->state = ConnState::WRITE_RESP;
                    worker->mod_connection(conn, EPOLLOUT);
                    sni_handled = true;
                }
            }
        }
    }
    if (!sni_handled) {
        conn->state = ConnState::READ_HEADERS;
        worker->mod_connection(conn, EPOLLIN);
    }
}

// epoll 事件分发处理
static void epoll_handle_connection(EpollWorker* worker, HttpConnection* conn, uint32_t revents) {
    // 处理异常事件
    if (revents & (EPOLLERR | EPOLLHUP)) {
        conn->state = ConnState::CLEANUP;
    }

    switch (conn->state) {
        case ConnState::SSL_INIT: {
            // 延迟创建SSL：将SSL_new从accept热路径移到epoll worker
            if (!(revents & (EPOLLIN | EPOLLOUT))) {
                conn->state = ConnState::CLEANUP;
                break;
            }
            SSL* ssl = SSL_new(g_ssl_ctx);
            if (!ssl) {
                conn->state = ConnState::CLEANUP;
                break;
            }
            SSL_set_fd(ssl, conn->fd);
            SSL_set_accept_state(ssl);
            conn->ssl = ssl;
            // 立即尝试SSL握手（socket上已缓冲ClientHello）
            HandshakeResult result = epoll_do_ssl_handshake(worker, conn);
            if (result == HandshakeResult::ERROR) {
                conn->state = ConnState::CLEANUP;
                break;
            }
            if (result == HandshakeResult::WAITING) {
                conn->state = ConnState::SSL_HANDSHAKE;
                break;
            }
            epoll_handle_handshake_done(worker, conn);
            break;
        }

        case ConnState::SSL_HANDSHAKE: {
            if (revents & (EPOLLIN | EPOLLOUT)) {
                HandshakeResult result = epoll_do_ssl_handshake(worker, conn);
                if (result == HandshakeResult::ERROR) {
                    conn->state = ConnState::CLEANUP;
                    break;
                }
                if (result == HandshakeResult::WAITING) {
                    break;
                }
                epoll_handle_handshake_done(worker, conn);
                } else {
                conn->state = ConnState::CLEANUP;
            }
            break;
        }

        case ConnState::READ_HEADERS: {
            if (revents & (EPOLLIN | EPOLLOUT)) {
                ReadResult result = epoll_do_read_headers(worker, conn);
                if (result == ReadResult::COMPLETE) {
                    // 头部已完整，切换到路由状态并立即处理
                    conn->state = ConnState::ROUTE;
                    epoll_handle_route(worker, conn);
                } else if (result == ReadResult::ERROR) {
                    conn->state = ConnState::CLEANUP;
                }
                // WAITING: 保持 READ_HEADERS 状态，等待下次 epoll 事件
            } else {
                conn->state = ConnState::CLEANUP;
            }
            break;
        }

        case ConnState::ROUTE: {
            // 直接调用路由处理（可能通过 READ_HEADERS 阶段触发，或收到意外事件）
            // 注意：epoll_handle_route 可能在 ?u= 路径中 delete conn，必须立即返回
            epoll_handle_route(worker, conn);
            return;
        }

        case ConnState::WRITE_RESP: {
            if (revents & (EPOLLOUT | EPOLLIN)) {
                if (!epoll_do_write_response(worker, conn)) {
                    // 写失败或出错，可能已被标记为CLEANUP
                    // 如果状态未改为CLEANUP（I/O需要等待），直接返回，不fall-through
                    if (conn->state != ConnState::CLEANUP) {
                        return;
                    }
                }
            }
            // 如果状态被改为CLEANUP，立即处理
            if (conn->state == ConnState::CLEANUP) {
                worker->remove_connection(conn);
                epoll_cleanup_connection(conn);
                g_conn_handled++;
                delete conn;
                return;
            }
            break;
        }

        case ConnState::CLEANUP: {
            worker->remove_connection(conn);
            epoll_cleanup_connection(conn);
            g_conn_handled++;
            delete conn;
            return;  // conn 已被删除，不要再访问
        }

        default:
            break;
    }

    // 延迟清理：各状态可能在出错时将 conn->state 设为 CLEANUP 后 break
    // 不清理会导致 epoll 集合膨胀（僵尸连接），随运行时间增长而变慢
    if (conn->state == ConnState::CLEANUP) {
        worker->remove_connection(conn);
        epoll_cleanup_connection(conn);
        g_conn_handled++;
        delete conn;
    }
}

// ==================== 日志系统 ====================
// 日志级别: 0=静默, 1=ERROR, 2=WARN, 3=INFO, 4=DEBUG
int g_log_level = 3;
std::string g_log_file;       // 日志文件路径（空 = 仅输出到终端）
std::mutex g_log_mutex;       // 日志写入互斥锁
std::ofstream g_log_stream;   // 日志文件流

inline std::string log_timestamp() {
    time_t now = time(nullptr);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char buf[64];
    strftime(buf, sizeof(buf), "[%Y-%m-%d %H:%M:%S]", &tm_buf);
    return buf;
}

inline const char* log_level_label(int lvl) {
    switch (lvl) {
        case 1: return "ERROR";
        case 2: return "WARN ";
        case 3: return "INFO ";
        case 4: return "DEBUG";
        default: return "?????";
    }
}

inline void log_emit(int lvl, const std::string& msg) {
    if (lvl > g_log_level && g_log_file.empty()) return;
    if (lvl > g_log_level) {
        if (!g_log_stream.is_open()) return;
        std::lock_guard<std::mutex> lock(g_log_mutex);
        if (g_log_stream.is_open()) {
            g_log_stream << log_timestamp() << " [" << log_level_label(lvl) << "] " << msg << "\n" << std::flush;
        }
        return;
    }
    std::lock_guard<std::mutex> lock(g_log_mutex);
    std::string line = log_timestamp() + " [" + log_level_label(lvl) + "] " + msg + "\n";
    std::ostream* out = (lvl <= 1) ? &std::cerr : &std::cout;
    (*out) << line << std::flush;
    if (g_log_stream.is_open()) {
        g_log_stream << line << std::flush;
    }
}

inline void log_open_file() {
    if (g_log_file.empty()) return;
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_stream.is_open()) g_log_stream.close();
    g_log_stream.open(g_log_file, std::ios::app);
}

#define LOG_ERROR(msg) do { if (g_log_level >= 1) { std::ostringstream _ls; _ls << msg; log_emit(1, _ls.str()); } } while(0)
#define LOG_WARN(msg)  do { if (g_log_level >= 2) { std::ostringstream _ls; _ls << msg; log_emit(2, _ls.str()); } } while(0)
#define LOG_INFO(msg)  do { if (g_log_level >= 3) { std::ostringstream _ls; _ls << msg; log_emit(3, _ls.str()); } } while(0)
#define LOG_DEBUG(msg) do { if (g_log_level >= 4) { std::ostringstream _ls; _ls << msg; log_emit(4, _ls.str()); } } while(0)

// ==================== 锁顺序规范（防止死锁）====================
// 全局锁获取顺序（按此顺序获取，数字小的先获取）：
// 1. g_ip_rate_mutex
// 2. g_ip_blocked_mutex
// 3. g_acme_ips_mutex
// 4. g_domain_cache_mutex
// 5. g_local_domains_mutex (shared_mutex)
// 6. g_blind_cache_mutex / g_error_cache_mutex
// 7. g_gyd443_ports_mutex
// 8. g_gyd443_conn_mutex
// 9. g_extra_listeners_mutex
// 10. g_geneva443_ports_mutex
// 注意：never 在持有一个 mutex 时尝试获取它两次（递归）
// epoll 相关：epoll_handle_connection 中不持有任何全局锁，避免阻塞其他连接

// ==================== Per-IP 连接速率限制（防DDoS） ====================
struct IPRateEntry {
    std::atomic<int> count{0};    // 当前窗口内连接数
    time_t window_start{0};       // 窗口开始时间
};
std::unordered_map<uint32_t, IPRateEntry> g_ip_rate_map;  // IP(网络字节序) -> 速率条目
std::mutex g_ip_rate_mutex;
const int IP_RATE_LIMIT = 100000;        // 每IP每秒最大连接数
const int IP_RATE_WINDOW = 1;         // 速率窗口（秒）
const int IP_RATE_BLOCK_DURATION = 60; // 超限后封禁时长（秒）

// 被封禁的IP（超过速率限制）
std::unordered_map<uint32_t, time_t> g_ip_blocked;  // IP -> 封禁到期时间
std::mutex g_ip_blocked_mutex;

// 检查IP是否被封禁
bool is_ip_blocked(uint32_t ip) {
    std::lock_guard<std::mutex> lock(g_ip_blocked_mutex);
    auto it = g_ip_blocked.find(ip);
    if (it == g_ip_blocked.end()) return false;
    if (time(nullptr) > it->second) {
        g_ip_blocked.erase(it);
        return false;
    }
    return true;
}

// 记录连接并检查是否超限，返回true表示允许，false表示应拒绝
bool check_ip_rate(uint32_t ip) {
    if (is_ip_blocked(ip)) return false;

    time_t now = time(nullptr);

    std::lock_guard<std::mutex> lock(g_ip_rate_mutex);

    // 防止 SYN flood 导致 map 无限增长：超过 50000 条目时触发清理
    // 加冷却机制（每秒最多清理一次），避免每次调用都全量遍历
    if (g_ip_rate_map.size() > 50000) {
        static time_t last_cleanup = 0;
        if (now - last_cleanup >= 1) {
            for (auto it = g_ip_rate_map.begin(); it != g_ip_rate_map.end(); ) {
                if (now - it->second.window_start > 10) {
                    it = g_ip_rate_map.erase(it);
                } else {
                    ++it;
                }
            }
            last_cleanup = now;
        }
        if (g_ip_rate_map.size() > 50000) return true;  // 仍超限，放行
    }

    auto& entry = g_ip_rate_map[ip];

    if (now - entry.window_start >= IP_RATE_WINDOW) {
        entry.count.store(1);
        entry.window_start = now;
        return true;
    }

    int cur = entry.count.fetch_add(1) + 1;
    if (cur > IP_RATE_LIMIT) {
        std::lock_guard<std::mutex> block(g_ip_blocked_mutex);
        g_ip_blocked[ip] = now + IP_RATE_BLOCK_DURATION;
        LOG_WARN("[速率限制] IP " << ((ip>>0)&0xFF) << "." << ((ip>>8)&0xFF) << "." << ((ip>>16)&0xFF) << "." << ((ip>>24)&0xFF) << " 超过 " << IP_RATE_LIMIT << " 连接/秒，封禁 " << IP_RATE_BLOCK_DURATION << " 秒");
        return false;
    }
    return true;
}

// 定期清理过期的速率记录（由后台线程调用）
void cleanup_ip_rate_entries() {
    time_t now = time(nullptr);
    {
        std::lock_guard<std::mutex> lock(g_ip_rate_mutex);
        for (auto it = g_ip_rate_map.begin(); it != g_ip_rate_map.end(); ) {
            if (now - it->second.window_start > 10) {
                it = g_ip_rate_map.erase(it);
            } else {
                ++it;
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(g_ip_blocked_mutex);
        for (auto it = g_ip_blocked.begin(); it != g_ip_blocked.end(); ) {
            if (now > it->second) {
                it = g_ip_blocked.erase(it);
            } else {
                ++it;
            }
        }
    }
}
// ==================== Per-IP 速率限制结束 ====================

// 配置参数
std::string g_transfer_server = "";      // 中转服务器地址（IP或域名）
int g_transfer_server_port = 3600;       // 中转服务器端口
static std::shared_mutex g_transfer_server_mutex;  // 保护 g_transfer_server / g_transfer_server_port 并发读写
int g_listen_port_https = 443;           // HTTPS监听端口
int g_listen_port_http = 80;             // HTTP监听端口
bool g_enable_http = true;               // 是否启用HTTP服务
std::string g_cert_file = "server.crt";  // 默认SSL证书
std::string g_key_file = "server.key";   // 默认SSL私钥
std::string g_cert_config = "/etc/ssl/certs.conf";  // 多证书配置文件（默认路径）
bool g_auto_daemonize = true;            // 是否自动转后台（默认启用，与主控复制命令保持一致）
bool g_daemonized = false;               // 是否已经转后台

// ACME转发配置
std::string g_acme_backend = "";         // ACME后端服务器IP（空则不转发）
int g_acme_backend_port = 80;            // ACME后端端口

// 管理API配置
int g_api_port = 9999;                   // 管理API端口
std::string g_api_key = "your_secret_key";  // API认证密钥
std::string g_acme_webroot = "/var/www/acme"; // ACME验证目录
std::string g_acme_path = "";            // acme.sh路径（空则自动检测）
int g_geneva_queue = 80;                 // Geneva队列号
int g_geneva_window = 0;                 // Geneva窗口大小（默认0）
bool g_geneva_enabled = true;            // 是否启用Geneva功能
std::atomic<bool> g_acme_mode_active{false};  // ACME模式是否激活（激活时Geneva暂停修改窗口）

// 动态IP白名单（用于ACME验证服务器IP）
std::mutex g_acme_ips_mutex;
std::unordered_set<uint32_t> g_acme_whitelist_ips;  // 存储网络字节序的IP

// 动态CIDR白名单（用于ACME验证服务器IP段，CIRD合并后存为 host-order [start,end] 区间）
struct CidrRange { uint32_t start; uint32_t end; };  // host-order
std::vector<CidrRange> g_acme_whitelist_cidrs;

// 证书同步到主控配置
std::string g_master_ip = "";            // 主控服务器IP（空则不同步）

// 获取 ?u= 转发目标IP：节点用主控IP，主控用 127.0.0.1 转发到本地 transfer_server
std::string get_u_forward_ip() {
    if (!g_master_ip.empty()) return g_master_ip;
    if (g_is_master) return "127.0.0.1";
    return "";
}

int g_master_port = 8080;                // 主控管理端口（默认8080）
int g_sync_interval = 0;                 // 证书同步间隔（秒），默认0不启用定时同步（主控申请后直接推送）
std::thread g_sync_thread;               // 证书同步线程

// 心跳上报配置
std::string g_node_name = "";            // 节点名称（用于心跳上报）
int g_heartbeat_interval = 10;           // 心跳间隔（秒）
std::thread g_heartbeat_thread;          // 心跳线程

// 复用的客户端 SSL_CTX（用于 check_domain_exists 连接主控）
SSL_CTX* g_client_ssl_ctx = nullptr;
std::once_flag g_client_ssl_ctx_init;

void init_client_ssl_ctx() {
    g_client_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (g_client_ssl_ctx) {
        SSL_CTX_set_verify(g_client_ssl_ctx, SSL_VERIFY_NONE, nullptr);
    }
}

// ==================== 主控SSL连接池 ====================
struct MasterSSLConnection {
    SSL* ssl;
    int sock;
    time_t last_used;  // 最后使用时间
    bool in_use;       // 是否正在使用
};

class MasterSSLPool {
private:
    std::vector<MasterSSLConnection> connections_;
    mutable std::mutex mutex_;
    int max_connections_;
    time_t max_idle_time_;  // 最大空闲时间（秒）
    std::atomic<uint64_t> hits_{0};    // 池命中次数（复用连接）
    std::atomic<uint64_t> misses_{0};  // 池未命中次数（新建连接）
    std::atomic<uint64_t> full_{0};    // 池满降级次数

public:
    MasterSSLPool(int max_conn = 8, int max_idle = 30) : max_connections_(max_conn), max_idle_time_(max_idle) {
        connections_.reserve(max_connections_);
    }

    ~MasterSSLPool() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& conn : connections_) {
            if (conn.sock >= 0) close(conn.sock);
            if (conn.ssl) {
                SSL_free(conn.ssl);
            }
        }
    }

    // 获取一个可用连接（如果没有可用连接则创建新的）
    SSL* get_connection(const std::string& master_ip, int master_port, int& out_sock, bool& success) {
        std::lock_guard<std::mutex> lock(mutex_);
        time_t now = time(nullptr);

        // 先查找一个可用的空闲连接
        for (auto& conn : connections_) {
            if (!conn.in_use && conn.ssl && conn.sock >= 0) {
                // 检查连接是否过期
                if (now - conn.last_used > max_idle_time_) {
                    // 连接太旧，关闭它
                    close(conn.sock);
                    SSL_free(conn.ssl);
                    conn.sock = -1;
                    conn.ssl = nullptr;
                    conn.in_use = false;
                    continue;
                }
                // 尝试用这个连接发送数据，检测是否还活着
                conn.in_use = true;
                out_sock = conn.sock;
                success = true;
                hits_.fetch_add(1, std::memory_order_relaxed);
                return conn.ssl;
            }
        }

        // 没有可用连接，创建新的
        if (connections_.size() < (size_t)max_connections_) {
            MasterSSLConnection new_conn;
            new_conn.sock = socket(AF_INET, SOCK_STREAM, 0);
            if (new_conn.sock < 0) {
                success = false;
                out_sock = -1;
                return nullptr;
            }

            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(master_port);
            if (inet_pton(AF_INET, master_ip.c_str(), &addr.sin_addr) <= 0) {
                close(new_conn.sock);
                success = false;
                out_sock = -1;
                return nullptr;
            }

            // 设置超时
            struct timeval tv = {5, 0};
            setsockopt(new_conn.sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(new_conn.sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

            // 连接主控
            if (connect(new_conn.sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                close(new_conn.sock);
                success = false;
                out_sock = -1;
                return nullptr;
            }

            // 创建SSL
            std::call_once(g_client_ssl_ctx_init, init_client_ssl_ctx);
            if (!g_client_ssl_ctx) {
                close(new_conn.sock);
                success = false;
                out_sock = -1;
                return nullptr;
            }

            new_conn.ssl = SSL_new(g_client_ssl_ctx);
            if (!new_conn.ssl) {
                close(new_conn.sock);
                success = false;
                out_sock = -1;
                return nullptr;
            }

            SSL_set_fd(new_conn.ssl, new_conn.sock);

            // SSL握手
            int retry = 0;
            bool handshake_ok = false;
            while (retry < 5) {  // 最多5次重试，每次3秒 = 15秒
                ERR_clear_error();
                int ret = SSL_connect(new_conn.ssl);
                if (ret == 1) {
                    handshake_ok = true;
                    break;
                }
                int err = SSL_get_error(new_conn.ssl, ret);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    struct pollfd pfd;
                    pfd.fd = new_conn.sock;
                    pfd.events = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
                    int sel = poll(&pfd, 1, 3000);  // 3秒=3000毫秒
                    if (sel > 0) {
                        retry++;
                        continue;
                    }
                }
                break;
            }

            if (!handshake_ok) {
                SSL_free(new_conn.ssl);
                close(new_conn.sock);
                success = false;
                out_sock = -1;
                return nullptr;
            }

            new_conn.last_used = now;
            new_conn.in_use = true;
            connections_.push_back(new_conn);
            out_sock = new_conn.sock;
            success = true;
            misses_.fetch_add(1, std::memory_order_relaxed);
            return new_conn.ssl;
        }

        // 连接池已满，返回失败
        full_.fetch_add(1, std::memory_order_relaxed);
        static time_t last_pool_full_warn = 0;
        time_t now_warn = time(nullptr);
        if (now_warn - last_pool_full_warn >= 10) {
            std::cerr << "[SSL连接池] 连接池已满(" << max_connections_ << ")，降级为每次创建新连接" << std::endl;
            last_pool_full_warn = now_warn;
        }
        success = false;
        out_sock = -1;
        return nullptr;
    }

    // 归还连接
    void return_connection(SSL* ssl) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& conn : connections_) {
            if (conn.ssl == ssl) {
                conn.last_used = time(nullptr);
                conn.in_use = false;
                return;
            }
        }
        // 没找到对应连接，可能是超时被关闭了，忽略
    }

    // 关闭并移除无效连接
    void cleanup() {
        std::lock_guard<std::mutex> lock(mutex_);
        time_t now = time(nullptr);
        for (auto it = connections_.begin(); it != connections_.end(); ) {
            if (it->in_use) {
                ++it;
                continue;
            }
            if (now - it->last_used > max_idle_time_) {
                if (it->sock >= 0) close(it->sock);
                if (it->ssl) SSL_free(it->ssl);
                it = connections_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // 主动关闭所有连接（主控IP变更时调用）
    void close_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& conn : connections_) {
            if (conn.sock >= 0) close(conn.sock);
            if (conn.ssl) SSL_free(conn.ssl);
            conn.sock = -1;
            conn.ssl = nullptr;
            conn.in_use = false;
        }
        connections_.clear();
    }

    // 监控指标
    uint64_t pool_hits() const   { return hits_.load(std::memory_order_relaxed); }
    uint64_t pool_misses() const { return misses_.load(std::memory_order_relaxed); }
    uint64_t pool_full() const   { return full_.load(std::memory_order_relaxed); }
    size_t total_conn() const    { std::lock_guard<std::mutex> lock(mutex_); return connections_.size(); }
    size_t in_use_conn() const   {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t n = 0;
        for (const auto& c : connections_) if (c.in_use) n++;
        return n;
    }
    int max_conn() const { return max_connections_; }
};

static MasterSSLPool* g_master_ssl_pool = nullptr;

// 域名存在性缓存（避免每次请求都查询主控）
struct DomainCacheEntry {
    bool exists;
    time_t expire_time;  // 缓存过期时间
};
std::unordered_map<std::string, DomainCacheEntry> g_domain_cache;
std::mutex g_domain_cache_mutex;
const int DOMAIN_CACHE_TTL_EXISTS = 120;      // 存在的域名缓存120秒
const int DOMAIN_CACHE_TTL_NOT_EXISTS = 30;   // 不存在的域名缓存30秒
const int DOMAIN_CACHE_TTL_FAIL = 10;         // 查询失败缓存10秒（用上次结果）

// 本地域名列表（从主控同步，避免每次HTTPS请求都远程查询主控）
std::unordered_set<std::string> g_local_domains;      // 本地缓存的活跃域名集合
std::shared_mutex g_local_domains_mutex;               // 读写锁（读多写少场景）
std::atomic<bool> g_local_domains_loaded{false};       // 是否已成功加载过域名列表
std::atomic<time_t> g_local_domains_sync_time{0};      // 上次同步时间
std::atomic<uint64_t> g_local_domain_version{0};       // 本地域名版本号（从主控同步时更新）
int g_domain_sync_interval = 30;                       // 域名列表同步间隔（秒）

// 从主控获取的配置
std::string g_custom_transition_html = "";  // 自定义过渡动画HTML（空则使用默认）
std::string g_custom_error_html = "";       // 自定义错误页面HTML（空则使用默认）
std::string g_custom_404_html = "";         // 自定义404页面HTML（空则使用默认）
std::string g_custom_response_header = "X-Support: ";  // 自定义HTTP响应头
bool g_transition_enabled = true;           // 是否启用过渡动画（由主控per-node控制）

// 盲发响应缓存（避免每请求重建~4KB HTML + Base64编码 + ostringstream）
std::string g_cached_blind_response;       // 缓存的完整盲发HTTP响应
std::mutex g_blind_cache_mutex;
// 缓存失效条件（任一变更时需重建）
std::string g_blind_cache_key;             // 缓存key = transfer_server + ":" + port + "|" + custom_html + "|" + custom_header

// 错误页面响应缓存（避免每请求重建2KB HTML，高并发下可观节省CPU）
std::string g_cached_404_response;         // 缓存的404响应
std::string g_cached_503_response;         // 缓存的503响应
std::string g_error_cache_key;             // 缓存key = custom_html + "|" + custom_header
std::mutex g_error_cache_mutex;            // 错误缓存专用锁（避免与盲发缓存竞争）

// Geneva (TCP窗口修改) 全局变量
struct nfq_handle *g_nfq_h = nullptr;
struct nfq_q_handle *g_nfq_qh = nullptr;
int g_nfq_fd = -1;

// GYD443 (TCP窗口修改 - 多端口) 全局变量
std::atomic<bool> g_gyd443_running{false};    // GYD443线程是否运行中
std::string g_gyd443_ports;                   // 当前活跃端口列表(逗号分隔)，空=关闭
std::mutex g_gyd443_ports_mutex;              // 端口列表保护锁
int g_gyd443_queue = 443;                     // GYD443队列号
uint16_t g_gyd443_window = 47;               // GYD443窗口大小
uint8_t g_gyd443_confusion = 0;              // 混淆包数量
std::thread g_gyd443_thread;                  // GYD443线程
struct nfq_handle *g_gyd443_nfq_h = nullptr;
struct nfq_q_handle *g_gyd443_nfq_qh = nullptr;
std::atomic<int> g_gyd443_nfq_fd{-1};
std::atomic<int> g_gyd443_raw_socket{-1};     // 原始套接字（发送混淆包）
// SSL安全关闭（双向关闭确保完全分手，避免半关闭导致资源泄漏）
static inline void safe_ssl_shutdown(SSL* ssl) {
    if (!ssl) return;
    SSL_shutdown(ssl);  // 发送close_notify
    SSL_shutdown(ssl);  // 等待对方close_notify（如果有）
}

// GYD443 连接跟踪（unordered_map: O(1) 查找/插入/删除）
struct GYD443ConnInfo {
    uint16_t edit_count;
    time_t last_seen;
};
// key = (dst_ip << 16) | dst_port
static inline uint64_t gyd443_conn_key(uint32_t ip, uint16_t port) {
    return ((uint64_t)ip << 16) | port;
}
std::unordered_map<uint64_t, GYD443ConnInfo> g_gyd443_conns;
std::mutex g_gyd443_conn_mutex;
// GYD443 额外HTTPS监听器（非主端口的动态监听）
struct ExtraListener {
    int port;
    std::atomic<int> socket_fd{-1};
    std::thread thread;
    std::atomic<bool> running{false};
};
std::vector<std::unique_ptr<ExtraListener>> g_extra_listeners;
std::mutex g_extra_listeners_mutex;

// Geneva443 (简单TCP窗口修改 - 兼容geneva.py，与GYD443互斥) 全局变量
std::atomic<bool> g_geneva443_running{false};
std::string g_geneva443_ports;                   // 端口列表(逗号分隔)，空=关闭
std::mutex g_geneva443_ports_mutex;
int g_geneva443_queue = 443;                     // 队列号（与GYD443共用443，因为互斥）
std::atomic<uint16_t> g_geneva443_window{4};     // 窗口大小（默认4）
std::thread g_geneva443_thread;
struct nfq_handle *g_geneva443_nfq_h = nullptr;
struct nfq_q_handle *g_geneva443_nfq_qh = nullptr;
std::atomic<int> g_geneva443_nfq_fd{-1};

std::atomic<bool> g_running{true};
time_t g_server_start_time = 0;
std::atomic<bool> g_config_fetch_inflight{false};
std::atomic<bool> g_domain_sync_inflight{false};
std::atomic<int> g_master_forward_inflight{0};
const int MAX_MASTER_FORWARD_INFLIGHT = 4096;

// 监听socket描述符列表（用于shutdown+close中断accept）
std::vector<int> g_listen_fds;
std::mutex g_listen_fds_mutex;

// ==================== 多进程架构 ====================
// Worker进程数（1 = 单进程默认模式）
int g_num_workers = 1;
// 是否为Master进程（fork前为true，worker子进程设为false）
bool g_is_master = true;
// Master进程PID（用于supervision）
pid_t g_master_pid = -1;
// reload标志文件路径（master写，workers读）
const char* g_reload_flag_file = "/tmp/redirect_server_reload.flag";
// Workerspoll reload标志的间隔（秒）
const int RELOAD_POLL_INTERVAL_SEC = 5;
// 子进程退出标志（worker收到SIGTERM/SIGINT时设true，通知main loop退出）
std::atomic<bool> g_worker_exit_requested{false};

// ==================== 多进程辅助函数 ====================

// 关闭本进程的所有监听socket（在fork后worker调用，避免继承）
static void close_listening_sockets_in_child() {
    if (g_server_socket_https >= 0) { close(g_server_socket_https); g_server_socket_https = -1; }
    if (g_server_socket_http >= 0)  { close(g_server_socket_http);  g_server_socket_http = -1; }
    if (g_server_socket_api >= 0)   { close(g_server_socket_api);   g_server_socket_api = -1; }
    // 关闭 g_listen_fds 中记录的所有额外监听 socket
    {
        std::lock_guard<std::mutex> lock(g_listen_fds_mutex);
        for (int fd : g_listen_fds) {
            if (fd >= 0) close(fd);
        }
        g_listen_fds.clear();
    }
    // 关闭其他无用的继承fd（保留 stdin/stdout/stderr 用于日志输出）
    int max_fd = static_cast<int>(sysconf(_SC_OPEN_MAX));
    if (max_fd <= 0 || max_fd > 65536) max_fd = 1024;  // 兜底
    for (int fd = 3; fd < max_fd; ++fd) {
        if (fd == g_server_socket_https || fd == g_server_socket_http || fd == g_server_socket_api) continue;
        // 跳过 g_listen_fds 中已关闭的 fd
        bool already_closed = false;
        for (int lf : g_listen_fds) { if (fd == lf) { already_closed = true; break; } }
        if (already_closed) continue;
        close(fd);
    }
}

// Master进程：生成Workers并supervise
// 返回false表示不以worker模式运行（单进程），返回true表示已fork出workers，master进入supervision loop
bool spawn_workers(int argc, char* argv[]) {
    // 若workers<=1 单进程模式不fork
    if (g_num_workers <= 1) return false;

    std::cout << "[多进程] Master启动，将fork " << g_num_workers << " 个worker进程" << std::endl;
    g_master_pid = getpid();

    for (int i = 0; i < g_num_workers; ++i) {
        pid_t pid = fork();
        if (pid < 0) {
            std::cerr << "[多进程] fork失败: " << strerror(errno) << std::endl;
            return false;
        }
        if (pid == 0) {
            // === 我是Worker子进程 ===
            g_is_master = false;
            // 子进程忽略SIGHUP（由master处理配置重载）
            signal(SIGHUP, SIG_IGN);
            // worker进程不daemonize（由master fork出来已经是后台进程）
            g_daemonized = true;
            // 关闭master可能打开的与业务无关的fd
            close_listening_sockets_in_child();
            // 不再需要systemd服务安装（master已处理）
            g_need_install_service = false;
            std::cout << "[多进程] Worker PID=" << getpid() << " 已启动" << std::endl;
            return true;  // 跳出spawn_workers，worker继续执行main后续代码
        }
        // === 我是Master父进程，继续fork下一个 ===
        std::cout << "[多进程] Master forked worker PID=" << pid << std::endl;
        {
            std::lock_guard<std::mutex> lk(g_worker_pids_mutex);
            g_worker_pids.push_back(pid);
        }
    }

    // === Master父进程进入supervision loop ===
    // 不创建任何监听socket，不accept连接
    std::cout << "[多进程] Master进入监督循环，Workers数量=" << g_num_workers << std::endl;

    // 设置reload标志文件初始值（不含时间戳表示无待处理reload）
    {
        std::ofstream f(g_reload_flag_file);
        f << "0";
    }

    int active_workers = g_num_workers;
    // 注册master的信号处理（SIGTERM停服务，SIGINT停服务、SIGHUP重载配置、SIGUSR1打印统计）
    signal(SIGTERM, [](int){ g_running.store(false, std::memory_order_release); });
    signal(SIGINT,  [](int){ g_running.store(false, std::memory_order_release); });
    signal(SIGUSR1, [](int){
        std::cout << "[统计] accepted=" << g_conn_accepted.load()
                  << " handled=" << g_conn_handled.load()
                  << " failed=" << g_conn_failed.load()
                  << " diff=" << (g_conn_accepted.load() - g_conn_handled.load() - g_conn_failed.load())
                  << std::endl;
    });
    signal(SIGHUP,  [](int){
        g_reload_requested.store(true, std::memory_order_release);
    });

    while (g_running) {
        // 检查是否有配置重载请求（由SIGHUP触发）
        if (g_reload_requested.exchange(false, std::memory_order_acq_rel)) {
            std::cout << "[多进程] Master收到SIGHUP，正在重载配置..." << std::endl;
            do_config_reload();
            std::ofstream f(g_reload_flag_file);
            f << time(nullptr);
        }

        // 检查是否有worker退出
        int status;
        pid_t died = waitpid(-1, &status, WNOHANG);
        if (died > 0) {
            std::cout << "[多进程] Worker PID=" << died << " 退出，status=" << WEXITSTATUS(status)
                      << "，正在重启..." << std::endl;
            // 重启退出的worker
            pid_t new_pid = fork();
            if (new_pid < 0) {
                std::cerr << "[多进程] 重启worker fork失败" << std::endl;
            } else if (new_pid == 0) {
                // 新worker子进程
                g_is_master = false;
                signal(SIGHUP, SIG_IGN);
                g_daemonized = true;
                close_listening_sockets_in_child();
                g_need_install_service = false;
                std::cout << "[多进程] Restarted Worker PID=" << getpid() << std::endl;
                return true;  // 以worker身份继续main
            }
            if (new_pid > 0) {
                std::lock_guard<std::mutex> lk(g_worker_pids_mutex);
                g_worker_pids.push_back(new_pid);
            }
            // 父进程继续supervise
        }

        // 定期写心跳时间戳到flag文件（workers可检测master存活）
        std::ofstream f(g_reload_flag_file);
        f << "0";  // 0表示master存活但无reload请求

        sleep(1);
        // 检查g_running
    }

    // Master收到SIGTERM/SIGINT，给所有workers发SIGTERM
    std::cout << "[多进程] Master正在关闭所有Workers..." << std::endl;
    {
        std::lock_guard<std::mutex> lk(g_worker_pids_mutex);
        for (pid_t wp : g_worker_pids) {
            if (wp > 1) kill(wp, SIGTERM);
        }
    }
    // 先关闭所有监听socket的接受方向，中断workers的accept()阻塞
    // 关闭主监听端口
    {
        std::lock_guard<std::mutex> lock(g_listen_fds_mutex);
        for (int lfd : g_listen_fds) {
            if (lfd >= 0) {
                shutdown(lfd, SHUT_RD);  // 关闭接受方向，中断accept()
                close(lfd);
            }
        }
        g_listen_fds.clear();
    }
    // 等待workers退出（最多5秒）
    sleep(1);
    for (int i = 0; i < 4; i++) {
        int status;
        pid_t died = waitpid(-1, &status, WNOHANG);
        if (died <= 0) break;
        sleep(1);
    }
    std::cout << "[多进程] Master退出" << std::endl;
    _exit(0);
    return false;  // 不会到这里
}

// Worker进程：检查reload标志文件
bool is_reload_requested() {
    std::ifstream f(g_reload_flag_file);
    if (!f.is_open()) return false;
    std::string line;
    if (!std::getline(f, line)) return false;
    // 如果时间戳 > 0 表示有reload请求
    time_t ts = (time_t)std::atoll(line.c_str());
    return ts > 0;
}

// Worker进程：poll reload标志（每 RELOAD_POLL_INTERVAL_SEC 秒）
void poll_reload_flag() {
    static time_t last_check = 0;
    time_t now = time(nullptr);
    if (now - last_check >= RELOAD_POLL_INTERVAL_SEC) {
        last_check = now;
        if (is_reload_requested()) {
            std::cout << "[多进程] Worker检测到配置重载请求，执行重载..." << std::endl;
            do_config_reload();
            // 写回0表示已处理
            std::ofstream f(g_reload_flag_file);
            f << "0";
        }
    }
}

// ==================== 后台运行（Daemon化）====================
int g_saved_argc = 0;
char** g_saved_argv = nullptr;
bool g_need_install_service = true;   // 默认自动安装systemd服务
bool g_allow_auto_install = false;    // 默认不自动安装依赖

// 前向声明
bool create_systemd_service(int argc, char* argv[]);
void reload_handler(int signum);   // SIGHUP 热重载（定义在 1682 行，需前向声明）
void do_config_reload();           // 配置热重载（定义在 1689 行，需前向声明）
SSL_CTX* create_ssl_ctx(const std::string& cert_file, const std::string& key_file); // SSL_CTX 创建（定义在 1759 行）
bool sync_domains_from_master();  // 从主控同步域名列表（定义在 1977 行）
void fetch_config_from_master();  // 从主控获取配置（过渡动画/错误页面等）

// ==================== 后台运行（Daemon化）====================

// 转为后台进程
bool daemonize() {
    if (g_daemonized) {
        return true;  // 已经是后台进程
    }

    std::cout << "[系统] 正在转入后台运行..." << std::endl;
    std::cout.flush();

    // 忽略SIGHUP信号（在第一次fork之前设置，防止信号竞态）
    signal(SIGHUP, SIG_IGN);

    // 第一次fork
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "[错误] fork失败: " << strerror(errno) << std::endl;
        return false;
    }

    if (pid > 0) {
        // 父进程退出（必须用_exit避免触发std::thread析构导致terminate）
        std::cout << "[系统] 后台进程PID: " << pid << std::endl;
        std::cout << "[系统] 日志输出到: /opt/redirect_server.log" << std::endl;
        std::cout.flush();
        _exit(0);
    }

    // 子进程继续
    // 创建新会话
    if (setsid() < 0) {
        std::cerr << "[错误] setsid失败: " << strerror(errno) << std::endl;
        return false;
    }

    // 第二次fork（防止daemon进程重新获得控制终端）
    pid = fork();
    if (pid < 0) {
        std::cerr << "[错误] 第二次fork失败: " << strerror(errno) << std::endl;
        return false;
    }

    if (pid > 0) {
        // 第一个子进程退出（必须用_exit避免触发std::thread析构导致terminate）
        _exit(0);
    }

    // 第二个子进程继续（真正的daemon进程）
    // 改变工作目录到根目录
    IGNORE_RESULT(chdir("/"));

    // 重定向标准输入输出到日志文件
    int log_fd = open("/opt/redirect_server.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (log_fd >= 0) {
        dup2(log_fd, STDOUT_FILENO);
        dup2(log_fd, STDERR_FILENO);
        close(log_fd);
    }

    // 关闭标准输入
    close(STDIN_FILENO);
    int null_fd = open("/dev/null", O_RDONLY);
    if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        close(null_fd);
    }

    g_daemonized = true;
    std::cout << "[系统] 已成功转入后台运行，PID: " << getpid() << std::endl;

    return true;
}

// 检查是否应该转后台（当关键服务都启动后）
void check_and_daemonize() {
    if (!g_auto_daemonize || g_daemonized) {
        return;
    }

    // 检查关键服务是否都已启动
    static bool geneva_started = false;
    static bool heartbeat_started = false;

    // 这个函数会在Geneva和心跳线程启动后被调用
    // 当两个都启动后，自动转后台
    if (geneva_started && heartbeat_started) {
        // daemonize() 会将 SIGHUP 设为 SIG_IGN（覆盖 reload_handler）
        // 因此在 daemonize() 之后必须重新注册 reload_handler
        daemonize();
        signal(SIGHUP, reload_handler);  // daemonize后重新注册SIGHUP
    }
}

// ==================== 后台运行结束 ====================

// ==================== 自动安装systemd服务 ====================

// 创建systemd服务文件
bool create_systemd_service(int argc, char* argv[]) {
    std::cout << "[服务安装] 正在创建systemd服务..." << std::endl;

    // 获取当前可执行文件的完整路径
    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len == -1) {
        std::cerr << "[服务安装] 无法获取可执行文件路径" << std::endl;
        return false;
    }
    exe_path[len] = '\0';

    // 获取工作目录
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == nullptr) {
        std::cerr << "[服务安装] 无法获取当前工作目录" << std::endl;
        return false;
    }

    // 构建ExecStart命令（包含所有参数）
    std::ostringstream exec_start;
    exec_start << exe_path;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        // 跳过 --install-service 参数
        if (arg == "--install-service") {
            continue;
        }
        // 如果参数包含空格，需要加引号
        if (arg.find(' ') != std::string::npos) {
            exec_start << " \"" << arg << "\"";
        } else {
            exec_start << " " << arg;
        }
    }

    // 添加 --no-daemon 参数，systemd管理进程生命周期，不需要自行后台化
    exec_start << " --no-daemon";

    // 创建服务文件内容
    std::ostringstream service_content;
    service_content << "[Unit]\n"
                    << "Description=Redirect Server HTTPS with Geneva\n"
                    << "After=network.target\n"
                    << "\n"
                    << "[Service]\n"
                    << "Type=simple\n"
                    << "WorkingDirectory=" << cwd << "\n"
                    << "ExecStart=" << exec_start.str() << "\n"
                    << "Restart=always\n"
                    << "RestartSec=10\n"
                    << "StandardOutput=append:/opt/redirect_server.log\n"
                    << "StandardError=append:/opt/redirect_server.log\n"
                    << "KillMode=process\n"
                    << "KillSignal=SIGTERM\n"
                    << "TimeoutStopSec=30\n"
                    << "\n"
                    << "[Install]\n"
                    << "WantedBy=multi-user.target\n";

    // 写入服务文件
    std::ofstream service_file("/etc/systemd/system/redirect_server.service");
    if (!service_file.is_open()) {
        std::cerr << "[服务安装] 无法创建服务文件，请确保有root权限" << std::endl;
        return false;
    }
    service_file << service_content.str();
    service_file.close();

    std::cout << "[服务安装] 服务文件已创建: /etc/systemd/system/redirect_server.service" << std::endl;

    // 重新加载systemd配置
    if (system("systemctl daemon-reload") != 0) {
        std::cerr << "[服务安装] systemctl daemon-reload 失败" << std::endl;
        return false;
    }
    std::cout << "[服务安装] systemd配置已重新加载" << std::endl;

    // 启用开机自启动
    if (system("systemctl enable redirect_server") != 0) {
        std::cerr << "[服务安装] 启用开机自启动失败" << std::endl;
        return false;
    }
    std::cout << "[服务安装] 已启用开机自启动" << std::endl;

    // 创建日志文件（避免使用shell）
    if (mkdir("/opt", 0755) != 0 && errno != EEXIST) {
        std::cerr << "[服务安装] 创建 /opt 目录失败: " << strerror(errno) << std::endl;
    }
    {
        std::ofstream log_file("/opt/redirect_server.log", std::ios::app);
        if (!log_file.is_open()) {
            std::cerr << "[服务安装] 创建日志文件失败: /opt/redirect_server.log" << std::endl;
        }
    }
    IGNORE_RESULT(chmod("/opt/redirect_server.log", 0644));

    // 创建logrotate配置（日志只保留3天）
    std::ofstream logrotate_file("/etc/logrotate.d/redirect_server");
    if (logrotate_file.is_open()) {
        logrotate_file << "/opt/redirect_server.log {\n"
                       << "    daily\n"
                       << "    rotate 3\n"
                       << "    missingok\n"
                       << "    notifempty\n"
                       << "    compress\n"
                       << "    delaycompress\n"
                       << "    copytruncate\n"
                       << "}\n";
        logrotate_file.close();
        std::cout << "[服务安装] 日志轮转配置已创建（保留3天）" << std::endl;
    }

    std::cout << "[服务安装] ========================================" << std::endl;
    std::cout << "[服务安装] systemd服务安装成功！" << std::endl;
    std::cout << "[服务安装] ========================================" << std::endl;
    std::cout << "[服务安装] 服务名称: redirect_server" << std::endl;
    std::cout << "[服务安装] 日志文件: /opt/redirect_server.log" << std::endl;
    std::cout << "[服务安装] " << std::endl;
    std::cout << "[服务安装] 管理命令:" << std::endl;
    std::cout << "[服务安装]   查看状态: systemctl status redirect_server" << std::endl;
    std::cout << "[服务安装]   停止服务: systemctl stop redirect_server" << std::endl;
    std::cout << "[服务安装]   重启服务: systemctl restart redirect_server" << std::endl;
    std::cout << "[服务安装]   查看日志: tail -f /opt/redirect_server.log" << std::endl;
    std::cout << "[服务安装] ========================================" << std::endl;

    // 停止可能正在运行的旧服务
    SYSTEM_CMD("systemctl stop redirect_server 2>/dev/null");

    // 启动服务
    std::cout << "[服务安装] 正在启动服务..." << std::endl;
    if (SYSTEM_CMD("systemctl start redirect_server") != 0) {
        std::cerr << "[服务安装] 启动服务失败" << std::endl;
        return false;
    }
    std::cout << "[服务安装] 服务已启动！" << std::endl;
    std::cout << "[服务安装] 当前进程将退出，服务由 systemd 管理" << std::endl;

    return true;
}

// ==================== 自动安装systemd服务结束 ====================

// ==================== 环境检测和自动安装 ====================

// 执行命令并获取输出
std::string exec_cmd(const std::string& cmd) {
    std::string result;
    char buffer[128];
    FILE* pipe = popen(cmd.c_str(), "r");
    if (pipe) {
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        pclose(pipe);
    }
    return result;
}

static bool command_exists(const std::string& cmd) {
    if (cmd.empty()) return false;
    const char* path_env = getenv("PATH");
    if (!path_env) return false;
    std::string path(path_env);
    std::istringstream iss(path);
    std::string dir;
    while (std::getline(iss, dir, ':')) {
        if (dir.empty()) continue;
        std::string full = dir + "/" + cmd;
        if (access(full.c_str(), X_OK) == 0) return true;
    }
    return false;
}

// 检测包管理器类型
std::string detect_package_manager() {
    if (command_exists("apt-get")) return "apt";
    if (command_exists("yum")) return "yum";
    if (command_exists("dnf")) return "dnf";
    if (command_exists("pacman")) return "pacman";
    if (command_exists("apk")) return "apk";
    return "";
}

// 检测并安装依赖
bool check_and_install_dependencies() {
    std::cout << "🔍 检测运行环境..." << std::endl;

    bool all_ok = true;
    std::string pkg_mgr = detect_package_manager();

    // 检测 iptables
    if (!command_exists("iptables")) {
        std::cout << "⚠️  iptables 未安装" << std::endl;
        if (!pkg_mgr.empty() && g_allow_auto_install) {
            std::cout << "📦 正在安装 iptables..." << std::endl;
            if (pkg_mgr == "apt") IGNORE_RESULT(system("apt-get update -qq && apt-get install -y iptables > /dev/null 2>&1"));
            else if (pkg_mgr == "yum") IGNORE_RESULT(system("yum install -y iptables > /dev/null 2>&1"));
            else if (pkg_mgr == "dnf") IGNORE_RESULT(system("dnf install -y iptables > /dev/null 2>&1"));
            else if (pkg_mgr == "pacman") IGNORE_RESULT(system("pacman -S --noconfirm iptables > /dev/null 2>&1"));
            else if (pkg_mgr == "apk") IGNORE_RESULT(system("apk add iptables > /dev/null 2>&1"));

            if (command_exists("iptables")) {
                std::cout << "✅ iptables 安装成功" << std::endl;
            } else {
                std::cerr << "❌ iptables 安装失败，请手动安装" << std::endl;
                all_ok = false;
            }
        } else if (!g_allow_auto_install) {
            std::cout << "ℹ️  已禁用自动安装（如需启用请加 --allow-auto-install）" << std::endl;
            all_ok = false;
        } else {
            std::cerr << "❌ 未检测到包管理器，请手动安装 iptables" << std::endl;
            all_ok = false;
        }
    } else {
        std::cout << "✅ iptables 已安装" << std::endl;
    }

    // 检测内核模块 nfnetlink_queue（Geneva需要）
    if (g_geneva_enabled) {
        std::string lsmod_output = exec_cmd("lsmod | grep nfnetlink_queue");
        if (lsmod_output.empty()) {
            std::cout << "⚠️  nfnetlink_queue 内核模块未加载，尝试加载..." << std::endl;
            if (system("modprobe nfnetlink_queue 2>/dev/null") == 0) {
                std::cout << "✅ nfnetlink_queue 模块加载成功" << std::endl;
            } else {
                std::cout << "⚠️  无法加载 nfnetlink_queue 模块，Geneva功能可能不可用" << std::endl;
                std::cout << "   提示：可以使用 --no-geneva 参数禁用Geneva功能" << std::endl;
            }
        } else {
            std::cout << "✅ nfnetlink_queue 内核模块已加载" << std::endl;
        }
    }

    // 检测 acme.sh（仅当未配置主控时需要，节点模式从主控同步证书）
    if (g_master_ip.empty()) {
        bool acme_found = false;
        if (access("/root/.acme.sh/acme.sh", X_OK) == 0) acme_found = true;
        else if (access("/usr/local/bin/acme.sh", X_OK) == 0) acme_found = true;
        else {
            const char* home = getenv("HOME");
            if (home) {
                std::string home_path = std::string(home) + "/.acme.sh/acme.sh";
                if (access(home_path.c_str(), X_OK) == 0) acme_found = true;
            }
        }

        if (!acme_found) {
            std::cout << "⚠️  acme.sh 未安装（本地证书申请功能不可用）" << std::endl;
            std::cout << "   安装命令: curl https://get.acme.sh | sh" << std::endl;
        } else {
            std::cout << "✅ acme.sh 已安装" << std::endl;
        }
    } else {
        std::cout << "ℹ️  节点模式：证书由主控申请，无需本地 acme.sh" << std::endl;
    }

    // 检测 openssl
    if (!command_exists("openssl")) {
        std::cout << "⚠️  openssl 未安装" << std::endl;
        if (!pkg_mgr.empty() && g_allow_auto_install) {
            std::cout << "📦 正在安装 openssl..." << std::endl;
            if (pkg_mgr == "apt") IGNORE_RESULT(system("apt-get install -y openssl > /dev/null 2>&1"));
            else if (pkg_mgr == "yum") IGNORE_RESULT(system("yum install -y openssl > /dev/null 2>&1"));
            else if (pkg_mgr == "dnf") IGNORE_RESULT(system("dnf install -y openssl > /dev/null 2>&1"));
            else if (pkg_mgr == "pacman") IGNORE_RESULT(system("pacman -S --noconfirm openssl > /dev/null 2>&1"));
            else if (pkg_mgr == "apk") IGNORE_RESULT(system("apk add openssl > /dev/null 2>&1"));
        } else if (!g_allow_auto_install) {
            std::cout << "ℹ️  已禁用自动安装（如需启用请加 --allow-auto-install）" << std::endl;
            all_ok = false;
        }
    } else {
        std::cout << "✅ openssl 已安装" << std::endl;
    }

    std::cout << "🔍 环境检测完成" << std::endl;
    std::cout << std::endl;

    return all_ok;
}

int g_server_socket_https = -1;
int g_server_socket_http = -1;
int g_server_socket_api = -1;            // 管理API socket
SSL_CTX* g_ssl_ctx = nullptr;
std::thread g_geneva_thread;             // Geneva线程（全局）

// 多域名证书映射: 域名 -> SSL_CTX
std::unordered_map<std::string, SSL_CTX*> g_domain_ssl_ctx;
std::shared_mutex g_domain_ssl_ctx_mutex;  // SNI回调读/证书更新写

// ==================== Geneva (TCP窗口修改) 实现 ====================

// 计算TCP校验和（需要伪头部）
static uint16_t compute_tcp_checksum(struct iphdr *ip, struct tcphdr *tcp) {
    uint32_t sum = 0;
    uint16_t tcp_len = ntohs(ip->tot_len) - (ip->ihl << 2);

    // 伪头部
    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += ip->saddr & 0xFFFF;
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += ip->daddr & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_len);

    // TCP头部和数据
    tcp->check = 0;
    uint16_t *ptr = (uint16_t *)tcp;
    int len = tcp_len;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t *)ptr;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

// 计算IP校验和
static uint16_t compute_ip_checksum(uint16_t *addr, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t *)addr;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

// Let's Encrypt 验证服务器IP检查（动态白名单 + 静态白名单）
// 动态白名单由主控在申请证书前推送，静态白名单作为兜底
static bool is_letsencrypt_ip(uint32_t ip_addr) {
    // 1. 先检查动态白名单（主控推送的IP）
    {
        std::lock_guard<std::mutex> lock(g_acme_ips_mutex);
        if (g_acme_whitelist_ips.count(ip_addr) > 0) {
            return true;
        }
        // 1.1 检查动态CIDR白名单（主控推送的CIDR段）
        uint32_t host_ip = ntohl(ip_addr);
        for (const auto& r : g_acme_whitelist_cidrs) {
            if (host_ip >= r.start && host_ip <= r.end) {
                return true;
            }
        }
    }

    // 2. 检查静态白名单（常见的验证服务器IP段）
    uint32_t ip = ntohl(ip_addr);
    uint8_t b1 = (ip >> 24) & 0xFF;
    uint8_t b2 = (ip >> 16) & 0xFF;

    // === Akamai CDN (Primary validation) ===
    if (b1 == 23) return true;
    if (b1 == 104 && b2 >= 64 && b2 <= 127) return true;

    // === AWS (Secondary validation) ===
    if (b1 == 18) return true;
    if (b1 == 3) return true;
    if (b1 == 13) return true;
    if (b1 == 15) return true;
    if (b1 == 16) return true;
    if (b1 == 35) return true;
    if (b1 == 47) return true;
    if (b1 == 52) return true;
    if (b1 == 54) return true;

    // === Google Cloud ===
    if (b1 == 34) return true;

    // === Cloudflare ===
    if (b1 == 172 && b2 >= 64 && b2 <= 71) return true;

    // === Let's Encrypt 自有 ===
    if (b1 == 66 && b2 == 133) return true;
    if (b1 == 64 && b2 == 78) return true;

    return false;
}

// NetfilterQueue 回调函数
static int geneva_nfq_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                               struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ph ? ntohl(ph->packet_id) : 0;

    unsigned char *payload;
    int payload_len = nfq_get_payload(nfa, &payload);

    if (payload_len >= (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) {
        struct iphdr *ip = (struct iphdr *)payload;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(payload + (ip->ihl << 2));

            // 检查 TCP flags: SA (SYN-ACK), FA (FIN-ACK), PA (PSH-ACK), A (ACK)
            bool is_target = (tcp->syn && tcp->ack) ||   // SYN-ACK (SA)
                            (tcp->fin && tcp->ack) ||    // FIN-ACK (FA)
                            (tcp->psh && tcp->ack) ||    // PSH-ACK (PA)
                            (tcp->ack && !tcp->syn && !tcp->fin && !tcp->psh && !tcp->rst);  // Pure ACK (A)

            if (is_target) {
                // ACME模式下：只对Let's Encrypt验证服务器IP跳过窗口修改
                // 其他流量继续抢答，保持抢答功能
                if (g_acme_mode_active.load() && is_letsencrypt_ip(ip->daddr)) {
                    // 目标是Let's Encrypt服务器，不修改窗口
                    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                }

                // 正常模式或非Let's Encrypt流量：修改窗口大小为配置值（默认0）
                tcp->window = htons(g_geneva_window);

                // 重新计算IP校验和
                ip->check = 0;
                ip->check = compute_ip_checksum((uint16_t *)ip, ip->ihl << 2);

                // 重新计算TCP校验和
                tcp->check = compute_tcp_checksum(ip, tcp);

                // 发送修改后的包
                return nfq_set_verdict(qh, id, NF_ACCEPT, payload_len, payload);
            }
        }
    }

    // 接受包（不修改）
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

// 检测 iptables 中是否已存在指定队列号的 NFQUEUE 规则
bool check_nfqueue_rule_exists(int queue_num) {
    std::ostringstream pattern;
    pattern << "NFQUEUE --queue-num " << queue_num;
    FILE* pipe = popen("iptables -S OUTPUT 2>/dev/null", "r");
    if (!pipe) return false;
    std::string out;
    char buf[256] = {};
    while (fgets(buf, sizeof(buf), pipe)) out += buf;
    pclose(pipe);
    return out.find(pattern.str()) != std::string::npos;
}

// Geneva 线程函数
void geneva_thread_func() {
    std::cout << "[Geneva] 启动 TCP 窗口修改, 队列: " << g_geneva_queue
              << ", 窗口: " << g_geneva_window << std::endl;

    // 检测是否已存在 NFQUEUE 规则
    if (check_nfqueue_rule_exists(g_geneva_queue)) {
        std::cout << "[Geneva] iptables NFQUEUE 规则已存在（队列 " << g_geneva_queue << "），跳过添加" << std::endl;
    } else {
        // 添加 iptables 规则（排除本地回环接口，避免影响ACME验证）
        IGNORE_RESULT(run_iptables_cmd("-I", "OUTPUT -o lo -p tcp --sport 80 -j ACCEPT"));
        std::ostringstream nfq_body;
        nfq_body << "OUTPUT -p tcp --sport 80 -j NFQUEUE --queue-num " << g_geneva_queue << " --queue-bypass";
        IGNORE_RESULT(run_iptables_cmd("-I", nfq_body.str()));
        std::cout << "[Geneva] 已添加 iptables 规则（排除本地回环）" << std::endl;
    }

    // 打开 netfilter queue
    g_nfq_h = nfq_open();
    if (!g_nfq_h) {
        std::cerr << "[Geneva] 无法打开 nfqueue" << std::endl;
        return;
    }

    // 解绑现有处理器
    nfq_unbind_pf(g_nfq_h, AF_INET);

    // 绑定到 AF_INET
    if (nfq_bind_pf(g_nfq_h, AF_INET) < 0) {
        std::cerr << "[Geneva] 无法绑定到 AF_INET" << std::endl;
        nfq_close(g_nfq_h);
        g_nfq_h = nullptr;
        return;
    }

    // 创建队列
    g_nfq_qh = nfq_create_queue(g_nfq_h, g_geneva_queue, &geneva_nfq_callback, NULL);
    if (!g_nfq_qh) {
        std::cerr << "[Geneva] 无法创建队列 " << g_geneva_queue << std::endl;
        nfq_close(g_nfq_h);
        g_nfq_h = nullptr;
        return;
    }

    // 设置复制模式
    if (nfq_set_mode(g_nfq_qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::cerr << "[Geneva] 无法设置复制模式" << std::endl;
        nfq_destroy_queue(g_nfq_qh);
        nfq_close(g_nfq_h);
        g_nfq_h = nullptr;
        g_nfq_qh = nullptr;
        return;
    }

    g_nfq_fd = nfq_fd(g_nfq_h);
    if (g_nfq_fd < 0) {
        std::cerr << "[Geneva] nfq_fd() 失败" << std::endl;
        return;
    }

    // 设置接收超时，避免阻塞导致无法停止
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(g_nfq_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    alignas(64) char buf[4096];

    while (g_running && g_geneva_enabled) {
        int rv = recv(g_nfq_fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(g_nfq_h, buf, rv);
        } else if (rv < 0) {
            if (!g_running || !g_geneva_enabled) break;
            if (errno == EINTR) continue;
            if (errno == ENOBUFS) {
                usleep(1000);
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            usleep(10000);
        }
    }

    // 清理
    if (g_nfq_qh) {
        nfq_destroy_queue(g_nfq_qh);
        g_nfq_qh = nullptr;
    }
    if (g_nfq_h) {
        nfq_close(g_nfq_h);
        g_nfq_h = nullptr;
    }

    // 删除 iptables 规则（包含和不包含 --queue-bypass 的都删）
    std::ostringstream del_body1;
    del_body1 << "OUTPUT -p tcp --sport 80 -j NFQUEUE --queue-num " << g_geneva_queue << " --queue-bypass";
    IGNORE_RESULT(run_iptables_cmd("-D", del_body1.str()));
    std::ostringstream del_body2;
    del_body2 << "OUTPUT -p tcp --sport 80 -j NFQUEUE --queue-num " << g_geneva_queue;
    IGNORE_RESULT(run_iptables_cmd("-D", del_body2.str()));
    // 删除本地回环排除规则
    IGNORE_RESULT(run_iptables_cmd("-D", "OUTPUT -o lo -p tcp --sport 80 -j ACCEPT"));

    std::cout << "[Geneva] 线程已停止" << std::endl;
}

// 停止 Geneva
void stop_geneva() {
    g_geneva_enabled = false;
    if (g_nfq_fd >= 0) {
        shutdown(g_nfq_fd, SHUT_RDWR);
    }
    // 等待线程结束
    if (g_geneva_thread.joinable()) {
        g_geneva_thread.join();
    }
    // 清理 netfilter 队列资源（防止 handle 泄漏）
    if (g_nfq_qh) {
        nfq_destroy_queue(g_nfq_qh);
        g_nfq_qh = nullptr;
    }
    if (g_nfq_h) {
        nfq_close(g_nfq_h);
        g_nfq_h = nullptr;
    }
}

// 重新启动 Geneva
void restart_geneva() {
    std::cout << "[Geneva] 正在重新启动..." << std::endl;

    // 确保旧线程已结束
    if (g_geneva_thread.joinable()) {
        g_geneva_thread.join();
    }

    // 清理旧资源（如果有残留）
    if (g_nfq_qh) {
        nfq_destroy_queue(g_nfq_qh);
    }
    if (g_nfq_h) {
        nfq_close(g_nfq_h);
    }

    // 重置状态
    g_nfq_h = nullptr;
    g_nfq_qh = nullptr;
    g_nfq_fd = -1;

    // 等待资源完全释放
    usleep(500000);  // 500ms

    // 重新启用并启动新线程
    g_geneva_enabled = true;
    g_geneva_thread = std::thread(geneva_thread_func);

    std::cout << "[Geneva] 已重新启动线程" << std::endl;
}

// ==================== Geneva 结束 ====================

// ==================== GYD443 (TCP窗口修改 - 443端口) 实现 ====================

// GYD443: 发送混淆RST包（异步调用）
static void gyd443_send_confusion(struct iphdr ip_copy, struct tcphdr tcp_copy) {
    int raw_sock = g_gyd443_raw_socket.load(std::memory_order_relaxed);
    if (raw_sock < 0 || g_gyd443_confusion == 0) return;
    struct sockaddr_in dest = {};
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip_copy.saddr;
    char pkt[128];
    struct iphdr *ip = (struct iphdr *)pkt;
    struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(struct iphdr));
    // rand() 在单线程（detached 混淆线程）内使用，不跨线程共享，此处无竞态
    for (int i = 0; i < g_gyd443_confusion && i < 30; i++) {
        memset(pkt, 0, sizeof(struct iphdr) + sizeof(struct tcphdr));
        ip->version = 4; ip->ihl = 5;
        ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        ip->id = htons(rand() % 65536); ip->ttl = 64; ip->protocol = IPPROTO_TCP;
        ip->saddr = ip_copy.daddr; ip->daddr = ip_copy.saddr;
        tcp->source = tcp_copy.dest; tcp->dest = tcp_copy.source;
        tcp->seq = htonl(ntohl(tcp_copy.seq) + 1 + rand() % 20);
        tcp->ack_seq = tcp_copy.ack_seq; tcp->doff = 5;
        tcp->window = htons(g_gyd443_window); tcp->rst = 1;
        tcp->check = compute_tcp_checksum(ip, tcp);
        sendto(raw_sock, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)&dest, sizeof(dest));
        usleep(1000);
    }
}

// GYD443: NFQueue回调（带连接跟踪和窗口策略）
static int gyd443_nfq_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                                struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ph ? ntohl(ph->packet_id) : 0;
    unsigned char *payload;
    int payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr)))
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    struct iphdr *ip = (struct iphdr *)payload;
    if (ip->protocol != IPPROTO_TCP)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    struct tcphdr *tcp = (struct tcphdr *)(payload + (ip->ihl << 2));
    uint8_t flags = ((tcp->syn ? 0x02 : 0) | (tcp->ack ? 0x10 : 0) |
                     (tcp->fin ? 0x01 : 0) | (tcp->rst ? 0x04 : 0) | (tcp->psh ? 0x08 : 0));
    bool need_modify = false, is_sa = false;
    uint16_t new_window = g_gyd443_window;
    uint64_t ckey = gyd443_conn_key(ip->daddr, tcp->dest);
    {
        std::lock_guard<std::mutex> lock(g_gyd443_conn_mutex);
        switch (flags) {
        case 0x02: need_modify = true; break; // SYN
        case 0x12: { // SYN+ACK
            if (g_gyd443_conns.find(ckey) == g_gyd443_conns.end()) {
                if (g_gyd443_conns.size() >= 10000) {
                    time_t now = time(nullptr);
                    for (auto jt = g_gyd443_conns.begin(); jt != g_gyd443_conns.end(); )
                        if (now - jt->second.last_seen >= 60 || jt->second.edit_count >= 100)
                            jt = g_gyd443_conns.erase(jt);
                        else ++jt;
                }
                if (g_gyd443_conns.size() < 10000)
                    g_gyd443_conns[ckey] = {1, time(nullptr)};
            }
            need_modify = true; is_sa = true; break;
        }
        case 0x11: case 0x18: case 0x10: { // FIN+ACK, PSH+ACK, ACK
            auto [it, inserted] = g_gyd443_conns.emplace(ckey, GYD443ConnInfo{1, time(nullptr)});
            if (!inserted || g_gyd443_conns.size() <= 10000) {
                new_window = it->second.edit_count <= 6 ? g_gyd443_window : 28960;
                it->second.edit_count++; it->second.last_seen = time(nullptr);
                need_modify = true;
            } else if (g_gyd443_conns.size() > 10000) {
                g_gyd443_conns.erase(it);
            }
            break;
        }
        }
        if ((flags & 0x01) || (flags & 0x04)) { // FIN or RST
            g_gyd443_conns.erase(ckey);
        }
    }
    if (need_modify) {
        if (flags == 0x02 || flags == 0x12) {
            if (tcp->doff > 5) {
                int removed = tcp->doff * 4 - 20;
                tcp->doff = 5;
                memset((char*)tcp + 20, 0, removed);
                ip->tot_len = htons(ntohs(ip->tot_len) - removed);
                payload_len -= removed;
            }
        }
        tcp->window = htons(new_window);
        ip->check = 0;
        ip->check = compute_ip_checksum((uint16_t *)ip, ip->ihl << 2);
        tcp->check = compute_tcp_checksum(ip, tcp);
        if (is_sa && g_gyd443_confusion > 0) {
            struct iphdr ipc = *ip; struct tcphdr tcpc = *tcp;
            enqueue_bg([ipc, tcpc]() { gyd443_send_confusion(ipc, tcpc); });
        }
        return nfq_set_verdict(qh, id, NF_ACCEPT, payload_len, payload);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

// GYD443: 添加iptables规则（多端口，每批≤15个，超过自动分批）
static void gyd443_add_iptables(const std::string& ports) {
    if (ports.empty()) return;
    std::vector<std::string> port_list;
    port_list.reserve(32);  // 预分配，避免多次扩容
    { std::istringstream iss(ports); std::string p; while (std::getline(iss, p, ',')) if (!p.empty()) port_list.push_back(p); }
    for (size_t i = 0; i < port_list.size(); i += 15) {
        std::string chunk;
        for (size_t j = i; j < std::min(i + (size_t)15, port_list.size()); j++) { if (!chunk.empty()) chunk += ","; chunk += port_list[j]; }
        std::ostringstream body;
        if (chunk.find(',') == std::string::npos)
            body << "OUTPUT -p tcp --sport " << chunk << " -j NFQUEUE --queue-num " << g_gyd443_queue << " --queue-bypass";
        else
            body << "OUTPUT -p tcp -m multiport --sports " << chunk << " -j NFQUEUE --queue-num " << g_gyd443_queue << " --queue-bypass";
        IGNORE_RESULT(run_iptables_cmd("-I", body.str()));
    }
    LOG_INFO("[GYD443] 已添加 iptables 规则, 端口: " << ports);
}

// GYD443: 删除iptables规则（多端口，每批≤15个，超过自动分批）
static void gyd443_del_iptables(const std::string& ports) {
    if (ports.empty()) return;
    std::vector<std::string> port_list;
    port_list.reserve(32);  // 预分配，避免多次扩容
    { std::istringstream iss(ports); std::string p; while (std::getline(iss, p, ',')) if (!p.empty()) port_list.push_back(p); }
    for (size_t i = 0; i < port_list.size(); i += 15) {
        std::string chunk;
        for (size_t j = i; j < std::min(i + (size_t)15, port_list.size()); j++) { if (!chunk.empty()) chunk += ","; chunk += port_list[j]; }
        std::ostringstream body;
        if (chunk.find(',') == std::string::npos)
            body << "OUTPUT -p tcp --sport " << chunk << " -j NFQUEUE --queue-num " << g_gyd443_queue << " --queue-bypass";
        else
            body << "OUTPUT -p tcp -m multiport --sports " << chunk << " -j NFQUEUE --queue-num " << g_gyd443_queue << " --queue-bypass";
        IGNORE_RESULT(run_iptables_cmd("-D", body.str()));
    }
}

// GYD443: 线程函数
void gyd443_thread_func() {
    std::string active_ports;
    { std::lock_guard<std::mutex> lock(g_gyd443_ports_mutex); active_ports = g_gyd443_ports; }
    LOG_INFO("[GYD443] 启动 TCP窗口修改, 端口:" << active_ports << " 队列:" << g_gyd443_queue << " 窗口:" << g_gyd443_window << " 混淆:" << (int)g_gyd443_confusion);
    // 清理函数：统一清理所有资源（确保早退路径不泄漏）
    auto cleanup_on_error = [&]() {
        if (g_gyd443_nfq_qh) { nfq_destroy_queue(g_gyd443_nfq_qh); g_gyd443_nfq_qh = nullptr; }
        if (g_gyd443_nfq_h) { nfq_close(g_gyd443_nfq_h); g_gyd443_nfq_h = nullptr; }
        { int rfd = g_gyd443_raw_socket.exchange(-1, std::memory_order_acq_rel); if (rfd >= 0) close(rfd); }
        gyd443_del_iptables(active_ports);
        g_gyd443_running = false;
    };
    {
        int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        g_gyd443_raw_socket.store(raw_fd, std::memory_order_release);
        if (raw_fd >= 0) {
            int on = 1; setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
        }
    }
    // 添加iptables规则
    gyd443_add_iptables(active_ports);
    g_gyd443_nfq_h = nfq_open();
    if (!g_gyd443_nfq_h) { LOG_ERROR("[GYD443] 无法打开nfqueue"); cleanup_on_error(); return; }
    nfq_unbind_pf(g_gyd443_nfq_h, AF_INET);
    nfq_bind_pf(g_gyd443_nfq_h, AF_INET);
    g_gyd443_nfq_qh = nfq_create_queue(g_gyd443_nfq_h, g_gyd443_queue, &gyd443_nfq_callback, NULL);
    if (!g_gyd443_nfq_qh) {
        LOG_ERROR("[GYD443] 无法创建队列 " << g_gyd443_queue);
        cleanup_on_error(); return;
    }
    if (nfq_set_mode(g_gyd443_nfq_qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        LOG_ERROR("[GYD443] 无法设置复制模式");
        cleanup_on_error(); return;
    }
    {
        int nfq_fd_val = nfq_fd(g_gyd443_nfq_h);
        if (nfq_fd_val < 0) {
            std::cerr << "[GYD443] nfq_fd() 失败" << std::endl;
            cleanup_on_error(); return;
        }
        g_gyd443_nfq_fd.store(nfq_fd_val, std::memory_order_release);
        struct timeval tv = {1, 0};
        setsockopt(nfq_fd_val, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    alignas(64) char buf[4096];
    while (g_running && g_gyd443_running.load()) {
        int nfq_fd_val = g_gyd443_nfq_fd.load(std::memory_order_acquire);
        int rv = recv(nfq_fd_val, buf, sizeof(buf), 0);
        if (rv >= 0) { nfq_handle_packet(g_gyd443_nfq_h, buf, rv); }
        else {
            if (!g_running || !g_gyd443_running.load()) break;
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (errno == ENOBUFS) { usleep(1000); continue; }
            usleep(10000);
        }
    }
    if (g_gyd443_nfq_qh) { nfq_destroy_queue(g_gyd443_nfq_qh); g_gyd443_nfq_qh = nullptr; }
    if (g_gyd443_nfq_h) { nfq_close(g_gyd443_nfq_h); g_gyd443_nfq_h = nullptr; }
    { int rfd = g_gyd443_raw_socket.exchange(-1, std::memory_order_acq_rel); if (rfd >= 0) close(rfd); }
    g_gyd443_nfq_fd.store(-1, std::memory_order_release);
    // 删除iptables规则
    gyd443_del_iptables(active_ports);
    { std::lock_guard<std::mutex> lock(g_gyd443_conn_mutex); g_gyd443_conns.clear(); }
    g_gyd443_running = false;
    LOG_INFO("[GYD443] 线程已停止");
}

// 前向声明
void stop_gyd443();
void stop_geneva443();
void handle_https_client(int client_socket, struct sockaddr_in client_addr);

// GYD443: 额外HTTPS监听线程函数
static void extra_listener_thread_func(ExtraListener* listener) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        LOG_ERROR("[GYD443] 创建额外HTTPS socket失败, 端口: " << listener->port);
        listener->running = false;
        return;
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    int defer_accept = 3;
    setsockopt(server_fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer_accept, sizeof(defer_accept));

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listener->port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("[GYD443] 绑定额外HTTPS端口 " << listener->port << " 失败: " << strerror(errno));
        close(server_fd);
        listener->running = false;
        return;
    }
    if (listen(server_fd, 65535) < 0) {
        LOG_ERROR("[GYD443] 额外HTTPS端口 " << listener->port << " 监听失败");
        close(server_fd);
        listener->running = false;
        return;
    }
    listener->socket_fd = server_fd;
    LOG_INFO("[GYD443] 额外HTTPS监听已启动, 端口: " << listener->port);

    while (g_running && listener->running.load()) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            if (!g_running || !listener->running.load()) break;
            if (errno == EINTR) continue;
            if (errno == EMFILE || errno == ENFILE) { usleep(100000); continue; }
            usleep(10000);
            continue;
        }
        if (!check_ip_rate(client_addr.sin_addr.s_addr)) {
            close(client_socket);
            continue;
        }
        if (!g_conn_pool->enqueue([client_socket, client_addr]{ handle_https_client(client_socket, client_addr); })) {
            close(client_socket);
        }
    }
    // 用 exchange(-1) 原子地取走 fd 并清零，避免与 stop_extra_listeners 的 double-close 竞态
    int own_fd = listener->socket_fd.exchange(-1, std::memory_order_acq_rel);
    if (own_fd >= 0) close(own_fd);
    listener->running = false;
    LOG_INFO("[GYD443] 额外HTTPS监听已停止, 端口: " << listener->port);
}

// GYD443: 启动额外HTTPS监听器（跳过主端口）
static void start_extra_listeners(const std::string& ports) {
    std::istringstream iss(ports);
    std::string item;
    std::lock_guard<std::mutex> lock(g_extra_listeners_mutex);
    while (std::getline(iss, item, ',')) {
        if (item.empty()) continue;
        int p = 0;
        try { p = std::stoi(item); } catch (...) { continue; }
        // 跳过主HTTPS端口（已有主循环监听）
        if (p == g_listen_port_https) continue;
        // 跳过已存在的监听
        bool exists = false;
        for (auto& el : g_extra_listeners) {
            if (el->port == p && el->running.load()) { exists = true; break; }
        }
        if (exists) continue;
        auto el = std::make_unique<ExtraListener>();
        el->port = p;
        el->socket_fd = -1;
        el->running = true;
        ExtraListener* raw = el.get();
        el->thread = std::thread(extra_listener_thread_func, raw);
        g_extra_listeners.push_back(std::move(el));
    }
}

// GYD443: 停止所有额外HTTPS监听器
static void stop_extra_listeners() {
    std::lock_guard<std::mutex> lock(g_extra_listeners_mutex);
    for (auto& el : g_extra_listeners) {
        el->running = false;
        // exchange(-1) 原子地取走 fd，避免与线程函数的 double-close 竞态
        int sfd = el->socket_fd.exchange(-1, std::memory_order_acq_rel);
        if (sfd >= 0) {
            shutdown(sfd, SHUT_RDWR);
            close(sfd);
        }
    }
    for (auto& el : g_extra_listeners) {
        if (el->thread.joinable()) el->thread.join();
    }
    g_extra_listeners.clear();
}

// GYD443: 启动（指定端口列表）
void start_gyd443(const std::string& ports) {
    if (ports.empty()) return;
    // 互斥：启动GYD443时停止Geneva443
    if (g_geneva443_running.load()) {
        std::cout << "[GYD443] 停止Geneva443（互斥）" << std::endl;
        stop_geneva443();
    }
    // 如果已运行，检查端口是否变化
    if (g_gyd443_running.load()) {
        { std::lock_guard<std::mutex> lock(g_gyd443_ports_mutex); if (g_gyd443_ports == ports) return; }
        stop_gyd443();
    }
    { std::lock_guard<std::mutex> lock(g_gyd443_ports_mutex); g_gyd443_ports = ports; }
    g_gyd443_running = true;
    if (g_gyd443_thread.joinable()) g_gyd443_thread.join();
    g_gyd443_thread = std::thread(gyd443_thread_func);
    // 启动额外端口的HTTPS监听
    start_extra_listeners(ports);
    LOG_INFO("[GYD443] 已启动, 端口: " << ports);
}

// GYD443: 停止
void stop_gyd443() {
    // 先停止额外监听器
    stop_extra_listeners();
    // 无论 g_gyd443_running 当前值如何，统一执行停止流程
    // 避免线程处于清理尾段（running已设false但join未完成）时提前返回导致资源泄漏
    g_gyd443_running = false;
    { int fd = g_gyd443_nfq_fd.load(std::memory_order_acquire); if (fd >= 0) shutdown(fd, SHUT_RDWR); }
    if (g_gyd443_thread.joinable()) g_gyd443_thread.join();
    { std::lock_guard<std::mutex> lock(g_gyd443_ports_mutex); g_gyd443_ports = ""; }
    LOG_INFO("[GYD443] 已停止");
}

// ==================== GYD443 结束 ====================

// ==================== Geneva443 开始 ====================

// Geneva443: NFQueue回调（简单窗口修改，不做连接跟踪/混淆/选项剥离）
static int geneva443_nfq_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                                   struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ph ? ntohl(ph->packet_id) : 0;
    unsigned char *payload;
    int payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr)))
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    struct iphdr *ip = (struct iphdr *)payload;
    if (ip->protocol != IPPROTO_TCP)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    struct tcphdr *tcp = (struct tcphdr *)(payload + (ip->ihl << 2));
    uint8_t flags = ((tcp->syn ? 0x02 : 0) | (tcp->ack ? 0x10 : 0) |
                     (tcp->fin ? 0x01 : 0) | (tcp->rst ? 0x04 : 0) | (tcp->psh ? 0x08 : 0));
    // 修改 SYN+ACK(0x12), FIN+ACK(0x11), PSH+ACK(0x18), ACK(0x10) 包的窗口大小
    if (flags == 0x12 || flags == 0x11 || flags == 0x18 || flags == 0x10) {
        tcp->window = htons(g_geneva443_window.load(std::memory_order_acquire));
        ip->check = 0;
        ip->check = compute_ip_checksum((uint16_t *)ip, ip->ihl << 2);
        tcp->check = compute_tcp_checksum(ip, tcp);
        return nfq_set_verdict(qh, id, NF_ACCEPT, payload_len, payload);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

// Geneva443: 添加iptables规则（每批≤15个，超过自动分批）
static void geneva443_add_iptables(const std::string& ports) {
    if (ports.empty()) return;
    std::vector<std::string> port_list;
    port_list.reserve(32);  // 预分配，避免多次扩容
    { std::istringstream iss(ports); std::string p; while (std::getline(iss, p, ',')) if (!p.empty()) port_list.push_back(p); }
    for (size_t i = 0; i < port_list.size(); i += 15) {
        std::string chunk;
        for (size_t j = i; j < std::min(i + (size_t)15, port_list.size()); j++) { if (!chunk.empty()) chunk += ","; chunk += port_list[j]; }
        std::ostringstream body;
        if (chunk.find(',') == std::string::npos)
            body << "OUTPUT -p tcp --sport " << chunk << " --tcp-flags SYN,RST,ACK,FIN,PSH SYN,ACK -j NFQUEUE --queue-num " << g_geneva443_queue;
        else
            body << "OUTPUT -p tcp -m multiport --sports " << chunk << " --tcp-flags SYN,RST,ACK,FIN,PSH SYN,ACK -j NFQUEUE --queue-num " << g_geneva443_queue;
        IGNORE_RESULT(run_iptables_cmd("-I", body.str()));
    }
    LOG_INFO("[Geneva443] 已添加 iptables 规则, 端口: " << ports);
}

// Geneva443: 删除iptables规则（每批≤15个，超过自动分批）
static void geneva443_del_iptables(const std::string& ports) {
    if (ports.empty()) return;
    std::vector<std::string> port_list;
    port_list.reserve(32);  // 预分配，避免多次扩容
    { std::istringstream iss(ports); std::string p; while (std::getline(iss, p, ',')) if (!p.empty()) port_list.push_back(p); }
    for (size_t i = 0; i < port_list.size(); i += 15) {
        std::string chunk;
        for (size_t j = i; j < std::min(i + (size_t)15, port_list.size()); j++) { if (!chunk.empty()) chunk += ","; chunk += port_list[j]; }
        std::ostringstream body;
        if (chunk.find(',') == std::string::npos)
            body << "OUTPUT -p tcp --sport " << chunk << " --tcp-flags SYN,RST,ACK,FIN,PSH SYN,ACK -j NFQUEUE --queue-num " << g_geneva443_queue;
        else
            body << "OUTPUT -p tcp -m multiport --sports " << chunk << " --tcp-flags SYN,RST,ACK,FIN,PSH SYN,ACK -j NFQUEUE --queue-num " << g_geneva443_queue;
        IGNORE_RESULT(run_iptables_cmd("-D", body.str()));
    }
}

// Geneva443: 线程函数
void geneva443_thread_func() {
    std::string active_ports;
    { std::lock_guard<std::mutex> lock(g_geneva443_ports_mutex); active_ports = g_geneva443_ports; }
    LOG_INFO("[Geneva443] 启动 TCP窗口修改, 端口:" << active_ports << " 队列:" << g_geneva443_queue << " 窗口:" << g_geneva443_window.load(std::memory_order_relaxed));
    // 清理函数：统一清理所有资源
    auto cleanup_on_error = [&]() {
        if (g_geneva443_nfq_qh) { nfq_destroy_queue(g_geneva443_nfq_qh); g_geneva443_nfq_qh = nullptr; }
        if (g_geneva443_nfq_h) { nfq_close(g_geneva443_nfq_h); g_geneva443_nfq_h = nullptr; }
        geneva443_del_iptables(active_ports);
        g_geneva443_running = false;
    };
    geneva443_add_iptables(active_ports);
    g_geneva443_nfq_h = nfq_open();
    if (!g_geneva443_nfq_h) { LOG_ERROR("[Geneva443] 无法打开nfqueue"); cleanup_on_error(); return; }
    nfq_unbind_pf(g_geneva443_nfq_h, AF_INET);
    nfq_bind_pf(g_geneva443_nfq_h, AF_INET);
    g_geneva443_nfq_qh = nfq_create_queue(g_geneva443_nfq_h, g_geneva443_queue, &geneva443_nfq_callback, NULL);
    if (!g_geneva443_nfq_qh) {
        LOG_ERROR("[Geneva443] 无法创建队列 " << g_geneva443_queue);
        cleanup_on_error(); return;
    }
    if (nfq_set_mode(g_geneva443_nfq_qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        LOG_ERROR("[Geneva443] 无法设置复制模式");
        cleanup_on_error(); return;
    }
    {
        int nfq_fd_val = nfq_fd(g_geneva443_nfq_h);
        if (nfq_fd_val < 0) {
            std::cerr << "[Geneva443] nfq_fd() 失败" << std::endl;
            cleanup_on_error(); return;
        }
        g_geneva443_nfq_fd.store(nfq_fd_val, std::memory_order_release);
        struct timeval tv = {1, 0};
        setsockopt(nfq_fd_val, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    alignas(64) char buf[4096];
    while (g_running && g_geneva443_running.load()) {
        int nfq_fd_val = g_geneva443_nfq_fd.load(std::memory_order_acquire);
        int rv = recv(nfq_fd_val, buf, sizeof(buf), 0);
        if (rv >= 0) { nfq_handle_packet(g_geneva443_nfq_h, buf, rv); }
        else {
            if (!g_running || !g_geneva443_running.load()) break;
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (errno == ENOBUFS) { usleep(1000); continue; }
            usleep(10000);
        }
    }
    if (g_geneva443_nfq_qh) { nfq_destroy_queue(g_geneva443_nfq_qh); g_geneva443_nfq_qh = nullptr; }
    if (g_geneva443_nfq_h) { nfq_close(g_geneva443_nfq_h); g_geneva443_nfq_h = nullptr; }
    g_geneva443_nfq_fd.store(-1, std::memory_order_release);
    geneva443_del_iptables(active_ports);
    g_geneva443_running = false;
    LOG_INFO("[Geneva443] 线程已停止");
}

// Geneva443: 启动（指定端口列表）
void start_geneva443(const std::string& ports) {
    if (ports.empty()) return;
    // 互斥：启动Geneva443时停止GYD443
    if (g_gyd443_running.load()) {
        std::cout << "[Geneva443] 停止GYD443（互斥）" << std::endl;
        stop_gyd443();
    }
    if (g_geneva443_running.load()) {
        { std::lock_guard<std::mutex> lock(g_geneva443_ports_mutex); if (g_geneva443_ports == ports) return; }
        stop_geneva443();
    }
    { std::lock_guard<std::mutex> lock(g_geneva443_ports_mutex); g_geneva443_ports = ports; }
    g_geneva443_running = true;
    if (g_geneva443_thread.joinable()) g_geneva443_thread.join();
    g_geneva443_thread = std::thread(geneva443_thread_func);
    // 启动额外端口的HTTPS监听（跟GYD443一样）
    start_extra_listeners(ports);
    LOG_INFO("[Geneva443] 已启动, 端口: " << ports);
}

// Geneva443: 停止
void stop_geneva443() {
    // 先停止额外监听器
    stop_extra_listeners();
    // 无论 running 当前值，统一执行停止：避免线程处于清理尾段时跳过 join
    g_geneva443_running = false;
    { int fd = g_geneva443_nfq_fd.load(std::memory_order_acquire); if (fd >= 0) shutdown(fd, SHUT_RDWR); }
    if (g_geneva443_thread.joinable()) g_geneva443_thread.join();
    { std::lock_guard<std::mutex> lock(g_geneva443_ports_mutex); g_geneva443_ports = ""; }
    LOG_INFO("[Geneva443] 已停止");
}

// ==================== Geneva443 结束 ====================

// 获取服务器本机IP
std::string get_local_ip() {
    struct ifaddrs *ifaddr, *ifa;
    char ip[INET_ADDRSTRLEN];
    std::string result_ip = "127.0.0.1";
    std::string first_ip = "";

    if (getifaddrs(&ifaddr) == -1) {
        return result_ip;
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;

        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);

        std::string ip_str(ip);
        if (ip_str.substr(0, 4) == "127.") continue;

        if (first_ip.empty()) {
            first_ip = ip_str;
        }

        std::string ifname(ifa->ifa_name);
        if (ifname.find("eth") == 0 || ifname.find("ens") == 0 ||
            ifname.find("en") == 0 || ifname.find("wlan") == 0) {
            result_ip = ip_str;
            break;
        }
    }

    freeifaddrs(ifaddr);

    if (result_ip == "127.0.0.1" && !first_ip.empty()) {
        result_ip = first_ip;
    }

    return result_ip;
}

void signal_handler(int signum) {
    // 信号处理函数只调用异步信号安全的函数（避免死锁）
    const char msg[] = "\n[信号] 正在关闭服务器...\n";
    IGNORE_RESULT(write(STDOUT_FILENO, msg, sizeof(msg) - 1));
    g_running.store(false, std::memory_order_release);
    if (!g_is_master) {
        // Worker进程：通知main loop退出
        g_worker_exit_requested.store(true, std::memory_order_release);
    }
    // accept4(SOCK_NONBLOCK) + g_running 检查保证 accept 线程快速退出，无需 shutdown()
}

// ==================== SIGHUP 配置热重载 ====================

// SIGHUP 信号处理：标记热重载请求，由主循环实际执行（避免信号处理函数中调用非async-signal-safe函数）
void reload_handler(int signum) {
    const char msg[] = "\n[信号] 收到 SIGHUP，正在重载配置...\n";
    IGNORE_RESULT(write(STDOUT_FILENO, msg, sizeof(msg) - 1));
    g_reload_requested.store(true, std::memory_order_release);
}

// 执行配置重载（由主循环调用，非信号处理函数）
void do_config_reload() {
    std::cout << "[配置] 开始重载配置..." << std::endl;

    // 重新读取证书配置文件
    if (!g_cert_config.empty() && access(g_cert_config.c_str(), R_OK) == 0) {
        std::ifstream fin(g_cert_config);
        if (fin.is_open()) {
            std::unordered_map<std::string, std::pair<std::string, std::string>> new_certs;
            std::string line;
            while (std::getline(fin, line)) {
                // 跳过注释和空行
                size_t comment_pos = line.find('#');
                if (comment_pos != std::string::npos) line = line.substr(0, comment_pos);
                if (line.find_first_not_of(" \t\r\n") == std::string::npos) continue;

                // 解析 domain = cert, key 格式
                size_t eq_pos = line.find('=');
                if (eq_pos == std::string::npos) continue;
                std::string domain = line.substr(0, eq_pos);
                std::string rest = line.substr(eq_pos + 1);
                size_t comma_pos = rest.find(',');
                if (comma_pos == std::string::npos) continue;
                std::string cert_path = rest.substr(0, comma_pos);
                std::string key_path = rest.substr(comma_pos + 1);
                // 去除空白
                auto trim = [](std::string& s) {
                    size_t start = s.find_first_not_of(" \t");
                    size_t end = s.find_last_not_of(" \t\r\n");
                    if (start == std::string::npos) { s.clear(); return; }
                    s = s.substr(start, end - start + 1);
                };
                trim(domain); trim(cert_path); trim(key_path);
                if (!domain.empty() && !cert_path.empty() && !key_path.empty()) {
                    new_certs[domain] = {cert_path, key_path};
                }
            }
            fin.close();

            // 更新证书映射（加写锁）
            {
                std::unique_lock<std::shared_mutex> lock(g_domain_ssl_ctx_mutex);
                for (auto& [domain, paths] : new_certs) {
                    if (g_domain_ssl_ctx.find(domain) == g_domain_ssl_ctx.end()) {
                        // 仅加载新增域名，避免覆盖已有活跃连接
                        SSL_CTX* new_ctx = create_ssl_ctx(paths.first, paths.second);
                        if (new_ctx) {
                            g_domain_ssl_ctx[domain] = new_ctx;
                            std::cout << "[配置] 热加载新证书: " << domain << std::endl;
                        }
                    }
                }
            }
            std::cout << "[配置] 已重载证书配置，新增 " << new_certs.size() << " 个域名" << std::endl;
        }
    }

    // 重新加载域名列表（从主控）
    if (!g_master_ip.empty()) {
        std::cout << "[配置] 从主控同步域名列表..." << std::endl;
        sync_domains_from_master();
    }

    std::cout << "[配置] 配置重载完成" << std::endl;
}
// ==================== SIGHUP 配置热重载结束 ====================

// 为单个域名创建SSL_CTX
SSL_CTX* create_ssl_ctx(const std::string& cert_file, const std::string& key_file) {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        std::cerr << "无法创建SSL上下文" << std::endl;
        return nullptr;
    }

    // SSL安全加固：仅TLS 1.3（1-RTT握手，比TLS 1.2的2-RTT省一个往返）
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1
                        | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE
                        | SSL_OP_NO_RENEGOTIATION
                        | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
    // 启用Session Ticket允许客户端复用会话，跳过完整握手，降低CPU开销
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
                        | SSL_MODE_RELEASE_BUFFERS);

    // AES-GCM优先（多数VPS有AES-NI硬件加速），ChaCha20备选（无AES-NI场景）
    SSL_CTX_set_cipher_list(ctx, "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4");

    // X25519优先（快30%），P-256兜底（兼容旧客户端）
    SSL_CTX_set_ecdh_auto(ctx, 1);
    int curves[] = { NID_X25519, NID_X9_62_prime256v1, 0 };
    SSL_CTX_set1_curves(ctx, curves, 2);

    // 启用Session Ticket（无状态，不占服务端内存），允许回头客跳过ECDHE握手
    // 即使跳转场景，同一客户端多次连接亦可复用会话，双核下CPU收益显著
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_session_id_context(ctx, (const unsigned char*)"rdr", 3);
    // 不设 SSL_OP_NO_TICKET：默认启用 session ticket

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file.c_str()) <= 0) {
        std::cerr << "无法加载证书文件: " << cert_file << std::endl;
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "无法加载私钥文件: " << key_file << std::endl;
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "私钥与证书不匹配" << std::endl;
        SSL_CTX_free(ctx);
        return nullptr;
    }

    return ctx;
}

// SNI回调函数：根据域名选择证书
int sni_callback(SSL* ssl, int* al, void* arg) {
    const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername) {
        std::shared_lock<std::shared_mutex> lock(g_domain_ssl_ctx_mutex);
        auto it = g_domain_ssl_ctx.find(servername);
        if (it != g_domain_ssl_ctx.end()) {
            SSL_set_SSL_CTX(ssl, it->second);
        }
    }
    return SSL_TLSEXT_ERR_OK;
}

// 加载证书配置文件
// 格式: 域名 = 证书路径 , 私钥路径
void load_cert_config(const std::string& config_file) {
    std::ifstream file(config_file);
    if (!file.is_open()) {
        // 配置文件不存在，创建一个空的
        std::ofstream create_file(config_file);
        if (create_file.is_open()) {
            create_file << "# SSL证书配置文件\n";
            create_file << "# 格式: 域名 = 证书文件, 私钥文件\n";
            create_file << "# 示例: example.com = /opt/ssl/example.com/fullchain.pem, /opt/ssl/example.com/privkey.key\n";
            create_file.close();
            std::cout << "已创建证书配置文件: " << config_file << std::endl;
        } else {
            std::cout << "无法创建证书配置文件: " << config_file << std::endl;
        }
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) continue;

        std::string domain = line.substr(0, eq_pos);
        std::string paths = line.substr(eq_pos + 1);

        // 去除空格
        domain.erase(0, domain.find_first_not_of(" \t"));
        domain.erase(domain.find_last_not_of(" \t") + 1);

        // 解析证书和私钥路径
        size_t comma_pos = paths.find(',');
        if (comma_pos == std::string::npos) continue;

        std::string cert = paths.substr(0, comma_pos);
        std::string key = paths.substr(comma_pos + 1);

        cert.erase(0, cert.find_first_not_of(" \t"));
        cert.erase(cert.find_last_not_of(" \t") + 1);
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);

        SSL_CTX* ctx = create_ssl_ctx(cert, key);
        if (ctx) {
            // 释放已有的旧 SSL_CTX，避免多次调用 load_cert_config 时内存泄漏
            auto it = g_domain_ssl_ctx.find(domain);
            if (it != g_domain_ssl_ctx.end() && it->second) {
                SSL_CTX_free(it->second);
                it->second = ctx;
            } else {
                g_domain_ssl_ctx[domain] = ctx;
            }
            std::cout << "加载证书: " << domain << " -> " << cert << std::endl;
        }
    }
    file.close();
}

// 自动生成自签名证书（如果证书文件不存在）
bool generate_self_signed_cert(const std::string& cert_file, const std::string& key_file) {
    // 检查证书是否已存在
    if (access(cert_file.c_str(), R_OK) == 0 && access(key_file.c_str(), R_OK) == 0) {
        return true;  // 证书已存在
    }

    std::cout << "[SSL] 证书文件不存在，自动生成自签名证书..." << std::endl;

    // 使用 openssl 命令生成ECDSA自签名证书（比RSA快10-50倍）
    std::ostringstream cmd;
    cmd << "openssl req -x509 -nodes -days 365 -newkey ec "
        << "-pkeyopt ec_paramgen_curve:prime256v1 "
        << "-keyout " << key_file << " "
        << "-out " << cert_file << " "
        << "-subj '/CN=localhost/O=CDN/C=CN' "
        << "2>/dev/null";

    int ret = system(cmd.str().c_str());
    if (ret != 0) {
        std::cerr << "[SSL] 自动生成证书失败，请手动创建证书文件" << std::endl;
        std::cerr << "[SSL] 可以使用以下命令生成：" << std::endl;
        std::cerr << "openssl req -x509 -nodes -days 365 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout " << key_file << " -out " << cert_file << " -subj '/CN=localhost'" << std::endl;
        return false;
    }

    std::cout << "[SSL] 自签名证书已生成: " << cert_file << ", " << key_file << std::endl;
    return true;
}

// 初始化SSL
bool init_ssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // 如果证书文件不存在，自动生成自签名证书
    if (!generate_self_signed_cert(g_cert_file, g_key_file)) {
        return false;
    }

    // 创建默认SSL上下文
    g_ssl_ctx = create_ssl_ctx(g_cert_file, g_key_file);
    if (!g_ssl_ctx) {
        return false;
    }

    // 加载多域名证书配置
    if (!g_cert_config.empty()) {
        load_cert_config(g_cert_config);
    }

    // 自动扫描 /opt/ssl/ 目录下的证书
    DIR* dir = opendir("/opt/ssl");
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type == DT_DIR && entry->d_name[0] != '.') {
                std::string domain = entry->d_name;
                std::string cert_file = "/opt/ssl/" + domain + "/fullchain.pem";
                std::string key_file = "/opt/ssl/" + domain + "/privkey.key";

                // 检查证书文件是否存在
                if (access(cert_file.c_str(), R_OK) == 0 && access(key_file.c_str(), R_OK) == 0) {
                    // 如果还没加载过这个域名的证书
                    if (g_domain_ssl_ctx.find(domain) == g_domain_ssl_ctx.end()) {
                        // 先验证证书文件内容是否有效
                        std::ifstream cert_check(cert_file);
                        std::string first_line;
                        if (cert_check.is_open() && std::getline(cert_check, first_line)) {
                            cert_check.close();
                            if (first_line.find("-----BEGIN") != std::string::npos) {
                                // 证书文件内容有效，尝试加载
                                SSL_CTX* ctx = create_ssl_ctx(cert_file, key_file);
                                if (ctx) {
                                    g_domain_ssl_ctx[domain] = ctx;
                                    std::cout << "[SSL] 自动加载证书: " << domain << " -> " << cert_file << std::endl;
                                }
                            } else {
                                std::cout << "[SSL] 跳过无效证书: " << domain << " (内容格式错误)" << std::endl;
                            }
                        }
                    }
                }
            }
        }
        closedir(dir);
    }

    // 设置SNI回调
    if (!g_domain_ssl_ctx.empty()) {
        SSL_CTX_set_tlsext_servername_callback(g_ssl_ctx, sni_callback);
    }

    return true;
}

// 从主控同步域名列表到本地（HTTP明文，走管理端口）
// 成功返回true，失败返回false
static int parse_http_status(const std::string& response);
static int parse_retry_after(const std::string& response);

bool sync_domains_from_master() {
    if (g_master_ip.empty()) return false;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_master_port);

    if (inet_pton(AF_INET, g_master_ip.c_str(), &addr.sin_addr) <= 0) {
        close(sock);
        return false;
    }

    // 增加超时时间到10秒，避免高负载时响应慢导致同步失败
    struct timeval timeout = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        LOG_WARN("[域名同步] 连接主控失败: " << g_master_ip << ":" << g_master_port);
        return false;
    }

    // 请求域名列表
    std::ostringstream req;
    req << "GET /api/node/domains?key=" << g_api_key << " HTTP/1.1\r\n"
        << "Host: " << g_master_ip << "\r\n"
        << "Connection: close\r\n\r\n";
    send(sock, req.str().c_str(), req.str().length(), MSG_NOSIGNAL);

    // 读取响应（使用动态缓冲，支持大域名列表）
    std::string resp;
    resp.reserve(65536);  // 预分配64KB，避免频繁扩容
    char buffer[16384];    // 16KB缓冲
    int bytes;
    while ((bytes = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes] = '\0';
        resp += buffer;
    }
    close(sock);

    // 429频率限制处理
    int http_status = parse_http_status(resp);
    if (http_status == 429) {
        int delay = parse_retry_after(resp);
        if (delay <= 0 || delay > 300) delay = 60;
        LOG_WARN("[域名同步] 主控限流(429)，等待 " << delay << " 秒...");
        sleep(delay);
        return false;
    }

    // 检查响应是否成功
    if (resp.find("\"success\":true") == std::string::npos) {
        LOG_WARN("[域名同步] 主控返回失败: " << (resp.empty() ? "(空响应)" : resp.substr(0, 100)));
        return false;
    }

    // 检查响应是否被截断（检查是否包含完整的数组结尾）
    size_t arr_start = resp.find("\"domains\":[");
    if (arr_start == std::string::npos) {
        LOG_WARN("[域名同步] 响应格式错误（未找到domains数组）");
        return false;
    }
    arr_start += 11; // skip "domains":[
    size_t arr_end = resp.find("]", arr_start);
    if (arr_end == std::string::npos) {
        LOG_WARN("[域名同步] 响应被截断（未找到数组结尾），跳过本次同步");
        return false;
    }

    // 检查是否有尾部内容（如果有说明可能被截断）
    if (arr_end + 1 < resp.size()) {
        std::string after = resp.substr(arr_end + 1);
        // 去掉空白字符后检查是否有实际内容
        size_t non_ws = after.find_first_not_of(" \t\r\n");
        if (non_ws != std::string::npos && after[non_ws] != ',') {
            LOG_WARN("[域名同步] 响应可能被截断，跳过本次同步");
            return false;
        }
    }

    // 解析每个域名
    std::unordered_set<std::string> new_domains;
    std::string arr_content = resp.substr(arr_start, arr_end - arr_start);
    size_t pos = 0;
    while ((pos = arr_content.find("\"", pos)) != std::string::npos) {
        pos++; // skip opening quote
        size_t end = arr_content.find("\"", pos);
        if (end == std::string::npos) break;
        std::string domain = normalize_domain_name(arr_content.substr(pos, end - pos));
        if (!domain.empty()) {
            new_domains.insert(domain);
        }
        pos = end + 1;
    }

    // 解析版本号（如果响应中包含）
    uint64_t server_version = 0;
    size_t ver_pos = resp.find("\"version\":");
    if (ver_pos != std::string::npos) {
        ver_pos += 10;
        try { server_version = std::stoull(resp.substr(ver_pos)); } catch (...) {}
    }

    // 只有成功解析到域名才替换，避免覆盖已有列表
    if (new_domains.empty() && server_version > 0) {
        LOG_WARN("[域名同步] 解析结果为空，跳过本次同步以保留已有列表");
        return false;
    }

    // 原子替换本地域名列表
    {
        std::unique_lock<std::shared_mutex> lock(g_local_domains_mutex);
        g_local_domains = std::move(new_domains);
    }
    g_local_domains_loaded.store(true);
    g_local_domains_sync_time.store(time(nullptr));
    if (server_version > 0) {
        g_local_domain_version.store(server_version);
    }

    LOG_INFO("[域名同步] 已同步 " << g_local_domains.size() << " 个域名 (版本: " << server_version << ")");
    return true;
}


int check_domain_exists(const std::string& domain) {
    std::string normalized_domain = normalize_domain_name(domain);
    if (normalized_domain.empty()) return 0;

    // ===== 优先查本地域名列表（O(1)哈希查找，无网络延迟） =====
    if (g_local_domains_loaded.load()) {
        std::shared_lock<std::shared_mutex> lock(g_local_domains_mutex);
        bool found = (g_local_domains.find(normalized_domain) != g_local_domains.end());
        LOG_DEBUG("[域名查询] " << normalized_domain << " -> " << (found ? "存在(本地)" : "不存在(本地)"));
        return found ? 1 : 0;  // 返回0表示不在列表中，显示错误页面
    }

    // ===== 本地列表未加载时，默认允许盲发，避免主控不可达时全部404 =====
    // 高并发时避免每个请求都去查主控导致阻塞或误判
    LOG_DEBUG("[域名查询] " << normalized_domain << " 本地列表未加载，默认允许盲发");
    return 1;
}

// HTML转义函数前向声明
static std::string html_escape(const std::string& s);

// 生成错误页面（域名不在规则中或检查失败时显示）
std::string generate_error_html(const std::string& domain, bool check_failed = false) {
    std::string title = check_failed ? "服务暂时不可用" : "跳转失败";
    std::string subtitle = check_failed ? "无法连接到服务器，请稍后重试" : "抱歉，您访问的域名尚未配置跳转规则";
    std::string error_code = check_failed ? "503" : "404";

    // 如果有自定义页面HTML，使用自定义的（404和错误页面分别处理）
    const std::string& custom_html = check_failed ? g_custom_error_html : g_custom_404_html;
    if (!custom_html.empty()) {
        std::string result = custom_html;
        // 替换变量（同时支持 {{host}} 和 {{DOMAIN}} 两种占位符）
        size_t pos;
        while ((pos = result.find("{{host}}")) != std::string::npos) {
            result.replace(pos, 8, domain);
        }
        while ((pos = result.find("{{DOMAIN}}")) != std::string::npos) {
            result.replace(pos, 10, domain);
        }
        while ((pos = result.find("{{TITLE}}")) != std::string::npos) {
            result.replace(pos, 9, title);
        }
        while ((pos = result.find("{{SUBTITLE}}")) != std::string::npos) {
            result.replace(pos, 12, subtitle);
        }
        while ((pos = result.find("{{ERROR_CODE}}")) != std::string::npos) {
            result.replace(pos, 14, error_code);
        }
        return result;
    }

    // 默认错误页面 - 简洁白色风格
    std::string err_title = check_failed ? "服务暂时不可用" : "很抱歉，您的访问遇到了一些问题";
    std::string err_subtitle = check_failed ? "我们正在努力恢复服务，请稍后再试" : "抱歉，您访问的域名尚未配置跳转规则";

    std::string html = "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">\n<title>" + error_code + " - " + err_title + "</title>\n<style>\n*{margin:0;padding:0;box-sizing:border-box}\nbody{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#fff;position:relative}\n.card{text-align:center;max-width:440px;width:90%;padding:0 20px}\n.code{font-size:120px;font-weight:800;color:#DC2626;line-height:1;margin-bottom:24px;letter-spacing:-4px}\nh1{font-size:24px;font-weight:600;color:#6B7280;margin-bottom:12px}\n.msg{color:#9CA3AF;font-size:15px;line-height:1.6;margin-bottom:32px}\n.domain-box{background:#F9FAFB;border:1px solid #E5E7EB;padding:16px 20px;border-radius:12px;margin-bottom:32px;text-align:left}\n.domain-label{font-size:11px;color:#9CA3AF;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px;font-weight:600}\n.domain-value{font-size:15px;color:#374151;font-weight:500;word-break:break-all;font-family:'SF Mono',SFMono-Regular,Consolas,monospace}\n.btns{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}\n.btn{display:inline-flex;align-items:center;justify-content:center;padding:14px 32px;border:1px solid #D1D5DB;border-radius:8px;font-size:15px;font-weight:500;color:#6B7280;cursor:pointer;text-decoration:none;transition:all 0.2s}\n.btn:hover{background:#F9FAFB;border-color:#9CA3AF}\n.btn-red{background:#DC2626;color:#fff;border-color:#DC2626}\n.btn-red:hover{background:#B91C1C;border-color:#B91C1C}\n</style>\n</head>\n<body>\n<div class=\"card\">\n<div class=\"code\">" + error_code + "</div>\n<h1>" + err_title + "</h1>\n<p class=\"msg\">" + err_subtitle + "</p>\n<div class=\"domain-box\"><div class=\"domain-label\">访问域名</div><div class=\"domain-value\">" + html_escape(domain) + "</div></div>\n<div class=\"btns\">\n<a href=\"javascript:location.reload()\" class=\"btn btn-red\">刷新页面</a>\n<a href=\"javascript:history.back()\" class=\"btn\">返回上一页</a>\n</div>\n</div>\n</body>\n</html>";
    return html;
}

// HTML转义（防止XSS注入）
static std::string html_escape(const std::string& s) {
    std::string r;
    r.reserve(s.size() + s.size() / 5);  // 预留20%余量，避免转义字符(&→&amp;)触发重新分配
    for (char c : s) {
        switch (c) {
            case '&': r += "&amp;"; break;
            case '<': r += "&lt;"; break;
            case '>': r += "&gt;"; break;
            case '"': r += "&quot;"; break;
            case '\'': r += "&#39;"; break;
            default: r += c; break;
        }
    }
    return r;
}

// 生成盲发的重定向HTML页面
std::string generate_blind_html() {
    // 支持中间域名通配符：*.example.com
    std::string middle_host = g_transfer_server;
    bool wildcard_middle = false;
    std::string wildcard_base;
    if (middle_host.rfind("*.", 0) == 0 && middle_host.size() > 2) {
        wildcard_middle = true;
        wildcard_base = middle_host.substr(2);
    }

    std::string port_suffix = (g_transfer_server_port == 443) ? "" : (":" + std::to_string(g_transfer_server_port));

    // 混淆中间域名：使用 Base64 编码 + 字符串拼接
    // 通配符场景下使用随机的子域，避免所有用户都跳到同一个地址，并对base进行编码隐藏
    std::string target;
    std::string wildcard_base_encoded;
    if (wildcard_middle) {
        // 对通配符base进行Base64编码
        static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string wb_encoded;
        int val = 0, valb = -6;
        for (unsigned char c : wildcard_base) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                wb_encoded.push_back(b64[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) wb_encoded.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
        while (wb_encoded.size() % 4) wb_encoded.push_back('=');
        wildcard_base_encoded = wb_encoded;
        
        // 生成随机子域
        std::string random_sub;
        const char* chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        int len = 5 + rand() % 6;
        for (int i = 0; i < len; i++) {
            random_sub += chars[rand() % strlen(chars)];
        }
        target = "https://" + random_sub + "." + wildcard_base + port_suffix + "/";
    } else {
        target = "https://" + middle_host + port_suffix + "/";
    }

    // Base64 编码
    static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    int val = 0, valb = -6;
    for (unsigned char c : target) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(b64[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) encoded.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
    while (encoded.size() % 4) encoded.push_back('=');

    // 过渡动画已关闭：直接JS跳转，无任何动画，保留 ?u= &p= 参数（优化：预分配 + 字符串拼接）
    if (!g_transition_enabled) {
        if (wildcard_middle) {
            return "<script>function __r(){var c='abcdefghijklmnopqrstuvwxyz0123456789';var l=5+Math.floor(Math.random()*6);var s='';for(var i=0;i<l;i++)s+=c.charAt(Math.floor(Math.random()*c.length));return s;}var b=atob('" + wildcard_base_encoded + "');var t='https://'+__r()+'.'+b+'" + port_suffix + "/'+'?u='+encodeURIComponent(location.hostname)+'&p='+encodeURIComponent(location.pathname+location.search);window.location.replace(t);</script>";
        } else {
            return "<script>var t=atob('" + encoded + "')+'?u='+encodeURIComponent(location.hostname)+'&p='+encodeURIComponent(location.pathname+location.search);window.location.replace(t);</script>";
        }
    }

    // 如果有自定义过渡动画HTML，使用自定义的（包括通配符中间域名场景）
    // 安全：{{ENCODED_TARGET}} 仅在 atob() JS字符串中使用，转义单引号和反斜杠防止注入
    if (!g_custom_transition_html.empty()) {
        std::string result = g_custom_transition_html;
        // 替换变量，并转义encoded中的单引号和反斜杠以防止JS字符串注入
        std::string safe_encoded = encoded;
        for (size_t i = 0; i < safe_encoded.size(); ++i) {
            if (safe_encoded[i] == '\'' || safe_encoded[i] == '\\') {
                safe_encoded.insert(safe_encoded.begin() + i, '\\');
                ++i;
            }
        }
        size_t pos;
        while ((pos = result.find("{{ENCODED_TARGET}}")) != std::string::npos) {
            result.replace(pos, 18, safe_encoded);
        }
        // 通配符中间域名支持：{{WILDCARD_BASE}}、{{WILDCARD_BASE_ENCODED}} 和 {{WILDCARD_TARGET}}
        if (wildcard_middle) {
            // {{WILDCARD_BASE}} - 通配符基础域名（如 cdn1.cdn456.eu.org）
            while ((pos = result.find("{{WILDCARD_BASE}}")) != std::string::npos) {
                result.replace(pos, 16, wildcard_base);
            }
            // {{WILDCARD_BASE_ENCODED}} - Base64编码的通配符基础域名
            while ((pos = result.find("{{WILDCARD_BASE_ENCODED}}")) != std::string::npos) {
                result.replace(pos, 24, wildcard_base_encoded);
            }
            // {{WILDCARD_TARGET}} - 动态生成随机子域的JS代码
            // 参考默认通配符页面的实现
            std::string wildcard_js = "function __r(){var c='abcdefghijklmnopqrstuvwxyz0123456789';var l=5+Math.floor(Math.random()*6);var s='';for(var i=0;i<l;i++)s+=c.charAt(Math.floor(Math.random()*c.length));return s;}var b=atob('" + wildcard_base_encoded + "');var t='https://'+__r()+'.'+b+'" + port_suffix + "/?u='+encodeURIComponent(location.hostname)+'&p='+encodeURIComponent(location.pathname+location.search);window.location.replace(t);";
            std::string safe_wildcard_js;
            for (size_t i = 0; i < wildcard_js.size(); ++i) {
                if (wildcard_js[i] == '\'') {
                    safe_wildcard_js += '\\';
                } else if (wildcard_js[i] == '\\') {
                    safe_wildcard_js += '\\';
                }
                safe_wildcard_js += wildcard_js[i];
            }
            while ((pos = result.find("{{WILDCARD_TARGET}}")) != std::string::npos) {
                result.replace(pos, 19, safe_wildcard_js);
            }
        }
        return result;
    }

    // 通配符中间域名下，使用轻量页并在前端动态随机子域，避免缓存导致子域固定。
    if (wildcard_middle) {
        return "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">\n<title>正在安全跳转</title>\n<style>\n*{margin:0;padding:0;box-sizing:border-box}\nbody{font-family:'Inter','PingFang SC','Microsoft YaHei',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#1a1a2e;position:relative;overflow:hidden}\n.particles{position:absolute;width:100%;height:100%;pointer-events:none}\n.particle{position:absolute;border-radius:50%;background:rgba(255,255,255,0.18);animation:float 7s ease-in-out infinite}\n@keyframes float{0%,100%{transform:translateY(0) scale(1)}50%{transform:translateY(-25px) scale(1.05)}}\n.card{background:rgba(255,255,255,0.95);backdrop-filter:blur(20px);padding:52px 44px;border-radius:26px;text-align:center;box-shadow:0 28px 55px -12px rgba(0,0,0,0.28);max-width:420px;width:90%;animation:slideUp 0.6s cubic-bezier(0.4,0,0.2,1);border:1px solid rgba(255,255,255,0.55)}\n@keyframes slideUp{0%{opacity:0;transform:translateY(35px) scale(0.92)}100%{opacity:1;transform:translateY(0) scale(1)}}\n.shield{width:90px;height:90px;margin:0 auto 28px;animation:floatShield 2.5s ease-in-out infinite}\n@keyframes floatShield{0%,100%{transform:translateY(0) rotate(0deg)}50%{transform:translateY(-8px) rotate(3deg)}}\n.shield svg{width:100%;height:100%}\n.status{font-size:22px;font-weight:700;color:#1a1a2e;margin-bottom:8px;letter-spacing:-0.3px}\n.tip{font-size:13px;color:#64748B;margin-bottom:24px}\n.progress-wrap{width:100%;height:5px;background:rgba(102,126,234,0.12);border-radius:3px;overflow:hidden;margin-bottom:14px}\n.progress{height:100%;background:linear-gradient(90deg,#667eea,#764ba2);border-radius:3px;animation:progressLoad 1s ease-out forwards}\n@keyframes progressLoad{0%{width:0%}100%{width:100%}}\n.dots{animation:dotPulse 1s ease-in-out infinite}\n@keyframes dotPulse{0%,100%{opacity:1}50%{opacity:0.15}}\n</style>\n</head>\n<body>\n<div class=\"particles\">\n<div class=\"particle\" style=\"width:16px;height:16px;top:20%;left:12%;animation-delay:0s\"></div>\n<div class=\"particle\" style=\"width:12px;height:12px;top:60%;left:82%;animation-delay:0.8s\"></div>\n<div class=\"particle\" style=\"width:20px;height:20px;top:40%;left:70%;animation-delay:1.6s\"></div>\n<div class=\"particle\" style=\"width:8px;height:8px;top:70%;left:25%;animation-delay:0.4s\"></div>\n</div>\n<div class=\"card\">\n<div class=\"shield\">\n<svg viewBox=\"0 0 100 100\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n<path d=\"M50 8L12 24V46C12 70 28 90 50 96C72 90 88 70 88 46V24L50 8Z\" fill=\"url(#shieldGrad)\" stroke=\"#667eea\" stroke-width=\"2\"/>\n<path d=\"M50 20L22 32V48C22 66 34 82 50 88C66 82 78 66 78 48V32L50 20Z\" fill=\"rgba(255,255,255,0.3)\"/>\n<path d=\"M35 50L45 60L65 40\" stroke=\"#fff\" stroke-width=\"6\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>\n<defs>\n<linearGradient id=\"shieldGrad\" x1=\"12\" y1=\"8\" x2=\"88\" y2=\"96\">\n<stop offset=\"0%\" stop-color=\"#667eea\"/>\n<stop offset=\"100%\" stop-color=\"#764ba2\"/>\n</linearGradient>\n</defs>\n</svg>\n</div>\n<div class=\"status\">正在安全跳转<span class=\"dots\">...</span></div>\n<div class=\"progress-wrap\"><div class=\"progress\"></div></div>\n<p class=\"tip\">正在建立加密连接，请稍候</p>\n</div>\n<script>\nfunction __r(){var c='abcdefghijklmnopqrstuvwxyz0123456789';var l=5+Math.floor(Math.random()*6);var s='';for(var i=0;i<l;i++)s+=c.charAt(Math.floor(Math.random()*c.length));return s;}\nvar b=atob('" + wildcard_base_encoded + "');\nvar t='https://'+__r()+'.'+b+'" + port_suffix + "/?u='+encodeURIComponent(location.hostname)+'&p='+encodeURIComponent(location.pathname+location.search);\nsetTimeout(function(){window.location.replace(t);},1000);\n</script>\n</body>\n</html>";
    }

    // 默认过渡动画页面 - 现代渐变风格
    return "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">\n<title>正在安全跳转</title>\n<style>\n*{margin:0;padding:0;box-sizing:border-box}\nbody{font-family:'Inter','PingFang SC','Microsoft YaHei',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);position:relative;overflow:hidden}\n.particles{position:absolute;width:100%;height:100%;top:0;left:0;pointer-events:none;overflow:hidden}\n.particle{position:absolute;border-radius:50%;background:rgba(255,255,255,0.2);animation:float 8s ease-in-out infinite}\n@keyframes float{0%,100%{transform:translateY(0) scale(1)}50%{transform:translateY(-30px) scale(1.1)}}\n.container{background:rgba(255,255,255,0.95);backdrop-filter:blur(24px);padding:56px 48px;border-radius:32px;text-align:center;box-shadow:0 30px 60px -15px rgba(0,0,0,0.3);max-width:460px;width:90%;animation:slideUp 0.7s cubic-bezier(0.4,0,0.2,1);position:relative;z-index:1;border:1px solid rgba(255,255,255,0.6)}\n@keyframes slideUp{0%{opacity:0;transform:translateY(50px) scale(0.9)}100%{opacity:1;transform:translateY(0) scale(1)}}\n.rocket{width:100px;height:100px;margin:0 auto 32px;position:relative;animation:floatRocket 2s ease-in-out infinite}\n@keyframes floatRocket{0%,100%{transform:translateY(0)}50%{transform:translateY(-10px)}}\n.rocket svg{width:100%;height:100%}\n.status{font-size:24px;font-weight:700;color:#1a1a2e;margin-bottom:10px;letter-spacing:-0.5px}\n.tip{font-size:14px;color:#64748B;margin-bottom:28px}\n.progress-wrap{width:100%;height:6px;background:rgba(102,126,234,0.15);border-radius:3px;overflow:hidden;margin-bottom:16px}\n.progress{height:100%;background:linear-gradient(90deg,#667eea,#764ba2);border-radius:3px;animation:progressLoad 0.8s ease-out forwards}\n@keyframes progressLoad{0%{width:0%}100%{width:100%}}\n.dots{animation:dotPulse 1.2s ease-in-out infinite}\n@keyframes dotPulse{0%,100%{opacity:1}50%{opacity:0.2}}\n.security-badge{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;background:rgba(102,126,234,0.08);border-radius:20px;font-size:12px;color:#667eea;font-weight:600}\n.security-badge svg{width:14px;height:14px}\n</style>\n</head>\n<body>\n<div class=\"particles\">\n<div class=\"particle\" style=\"width:20px;height:20px;top:15%;left:10%;animation-delay:0s\"></div>\n<div class=\"particle\" style=\"width:14px;height:14px;top:65%;left:85%;animation-delay:1s\"></div>\n<div class=\"particle\" style=\"width:24px;height:24px;top:35%;left:75%;animation-delay:2s\"></div>\n<div class=\"particle\" style=\"width:10px;height:10px;top:75%;left:20%;animation-delay:0.5s\"></div>\n<div class=\"particle\" style=\"width:18px;height:18px;top:25%;left:60%;animation-delay:1.5s\"></div>\n</div>\n<div class=\"container\">\n<div class=\"rocket\">\n<svg viewBox=\"0 0 100 100\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n<path d=\"M50 10C50 10 70 30 70 50C70 70 50 90 50 90C50 90 30 70 30 50C30 30 50 10 50 10Z\" fill=\"url(#rocketGrad)\" stroke=\"#667eea\" stroke-width=\"2\"/>\n<circle cx=\"50\" cy=\"45\" r=\"8\" fill=\"#fff\"/>\n<path d=\"M30 60L20 80L35 70Z\" fill=\"#764ba2\"/>\n<path d=\"M70 60L80 80L65 70Z\" fill=\"#764ba2\"/>\n<path d=\"M40 75L50 95L60 75C60 75 55 80 50 80C45 80 40 75 40 75Z\" fill=\"#f97316\"/>\n<path d=\"M42 78L50 90L58 78\" stroke=\"#fbbf24\" stroke-width=\"2\" stroke-linecap=\"round\"/>\n<defs>\n<linearGradient id=\"rocketGrad\" x1=\"30\" y1=\"10\" x2=\"70\" y2=\"90\">\n<stop offset=\"0%\" stop-color=\"#667eea\"/>\n<stop offset=\"100%\" stop-color=\"#764ba2\"/>\n</linearGradient>\n</defs>\n</svg>\n</div>\n<div class=\"status\">正在安全跳转<span class=\"dots\">...</span></div>\n<div class=\"tip\">正在为您建立安全连接，请稍候</div>\n<div class=\"progress-wrap\"><div class=\"progress\"></div></div>\n<div class=\"security-badge\">\n<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\">\n<path d=\"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\"/>\n</svg>\n安全加密连接\n</div>\n</div>\n<script>\nsetTimeout(function(){var t=atob('" + encoded + "')+'?u='+encodeURIComponent(location.hostname)+'&p='+encodeURIComponent(location.pathname+location.search);window.location.replace(t);},1000);\n</script>\n</body>\n</html>";
}

// 获取缓存的盲发完整HTTP响应（含headers），配置变更时自动重建
const std::string& get_cached_blind_response() {
    std::shared_lock<std::shared_mutex> ts_lock(g_transfer_server_mutex);
    std::string cache_host = g_transfer_server;
    if (cache_host.empty()) {
        cache_host = "127.0.0.1";
    }
    if (cache_host.rfind("*.", 0) == 0 && cache_host.size() > 2) {
        cache_host = cache_host.substr(2);
    }
    std::string current_key = cache_host + ":" + std::to_string(g_transfer_server_port)
                              + "|" + g_custom_transition_html + "|" + g_custom_response_header
                              + "|" + (g_transition_enabled ? "1" : "0");
    // 快速路径：缓存命中时只持锁读取
    {
        std::lock_guard<std::mutex> lock(g_blind_cache_mutex);
        if (g_blind_cache_key == current_key && !g_cached_blind_response.empty()) {
            return g_cached_blind_response;
        }
    }
    // 缓存失效，在锁外生成重量级HTML（避免持锁阻塞其他线程）
    std::string html = generate_blind_html();
    std::string body_len = std::to_string(html.length());
    std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: " + body_len + "\r\n";
    if (!g_custom_response_header.empty()) {
        resp += g_custom_response_header + "\r\n";
    }
    resp += "Content-Type: text/html; charset=UTF-8\r\n";
    resp += "X-Content-Type-Options: nosniff\r\n";
    resp += "X-Frame-Options: SAMEORIGIN\r\n";
    resp += "Referrer-Policy: no-referrer\r\n";
    resp += "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'\r\n";
    resp += "Connection: close\r\n\r\n";
    resp += html;
    // 再次持锁，检查是否已被其他线程抢先缓存，避免重复存储
    {
        std::lock_guard<std::mutex> lock(g_blind_cache_mutex);
        if (g_blind_cache_key == current_key) {
            return g_cached_blind_response;  // 其他线程已完成，直接返回
        }
        g_cached_blind_response = std::move(resp);
        g_blind_cache_key = current_key;
    }
    return g_cached_blind_response;
}

// 获取缓存的错误页面响应（404/503），配置变更时自动重建
// is_503: true=503错误页, false=404错误页
const std::string& get_cached_error_response(bool is_503) {
    std::string current_key = g_custom_error_html + "|" + g_custom_404_html + "|" + g_custom_response_header;
    std::lock_guard<std::mutex> lock(g_error_cache_mutex);  // 独立锁，不跟盲发缓存竞争
    if (g_error_cache_key != current_key) {
        g_error_cache_key = current_key;
        g_cached_404_response.clear();
        g_cached_503_response.clear();
    }
    std::string& cached = is_503 ? g_cached_503_response : g_cached_404_response;
    if (!cached.empty()) return cached;
    // 重建
    std::string html = generate_error_html("placeholder", is_503);
    std::string resp;
    size_t cap = 256 + html.size();
    resp.reserve(cap);
    resp += "HTTP/1.1 ";
    resp += is_503 ? "503 Service Unavailable" : "404 Not Found";
    resp += "\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: ";
    resp += std::to_string(html.size());
    resp += "\r\n";
    if (!g_custom_response_header.empty()) {
        resp += g_custom_response_header + "\r\n";
    }
    resp += "X-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n";
    resp += html;
    cached = resp;
    return cached;
}

// 生成HTTP响应（优化：使用reserve预分配 + 字符串拼接，避免ostringstream开销）
std::string generate_response(const std::string& body) {
    size_t len = body.length();
    size_t cap = 256 + len;  // 固定头部约256字节（含安全headers）
    std::string response;
    response.reserve(cap);
    response += "HTTP/1.1 200 OK\r\nContent-Length: ";
    response += std::to_string(len);
    response += "\r\n";
    if (!g_custom_response_header.empty()) {
        response += g_custom_response_header;
        response += "\r\n";
    }
    response += "Content-Type: text/html; charset=UTF-8\r\n";
    response += "X-Content-Type-Options: nosniff\r\n";
    response += "X-Frame-Options: SAMEORIGIN\r\n";
    response += "Referrer-Policy: no-referrer\r\n";
    response += "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'\r\n";
    response += "Connection: close\r\n\r\n";
    response += body;
    return response;
}

// 转发ACME请求到后端
std::string forward_acme_request(const std::string& request) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(g_acme_backend_port);

    if (inet_pton(AF_INET, g_acme_backend.c_str(), &server_addr.sin_addr) <= 0) {
        close(sock);
        return "";
    }

    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return "";
    }

    send(sock, request.c_str(), request.length(), MSG_NOSIGNAL);
    std::string response;
    char buffer[4096];
    int bytes;
    while ((bytes = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes] = '\0';
        response += buffer;
    }

    close(sock);
    return response;
}

// TCP send 完整发送辅助函数（处理非阻塞socket的EAGAIN重试 + 阻塞socket的部分写入）
static bool tcp_send_all(int fd, const void* buf, int len) {
    const char* ptr = (const char*)buf;
    int remaining = len;
    const int MAX_RETRIES = 100;
    for (int retries = 0; remaining > 0 && retries < MAX_RETRIES; retries++) {
        int sent = send(fd, ptr, remaining, MSG_NOSIGNAL);
        if (sent > 0) {
            ptr += sent;
            remaining -= sent;
            retries = 0;
            continue;
        }
        if (sent == 0) return false;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT;
            poll(&pfd, 1, 10);
        } else if (errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return remaining == 0;
}

// 处理HTTP客户端连接（80端口盲发 + ACME本地验证/转发）
void handle_http_client(int client_socket, struct sockaddr_in client_addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

    // 切回阻塞模式：accept4(SOCK_NONBLOCK) 创建的 socket 是非阻塞的，
    // 但本函数使用 SO_RCVTIMEO/SO_SNDTIMEO 超时机制，因而不需要非阻塞语义。
    // 若不切回，recv/send 均立即返回，导致请求读不完整、响应发不完整。
    int flags = fcntl(client_socket, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(client_socket, F_SETFL, flags & ~O_NONBLOCK);
    }

    int flag = 1;
    setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    // 快速读取（10ms超时）
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 10000;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    char buffer[4096];
    int total_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);

    // 如果第一次没读到完整请求行，检查是否可能是ACME请求
    // ACME请求的特征：路径以 /.well-known/ 开头
    bool need_more_read = (total_read > 0 && strstr(buffer, " HTTP/") == nullptr);
    bool might_be_acme = (total_read > 0 && strstr(buffer, "/.well-known/") != nullptr);

    if (need_more_read || might_be_acme) {
        // 延长超时，多读几次
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        for (int i = 0; i < 3 && strstr(buffer, " HTTP/") == nullptr; i++) {
            int more = recv(client_socket, buffer + total_read, sizeof(buffer) - 1 - total_read, 0);
            if (more > 0) {
                total_read += more;
                buffer[total_read] = '\0';
            } else {
                break;
            }
        }
    }

    std::string request = (total_read > 0) ? std::string(buffer, total_read) : "";
    std::string path = "/";

    if (total_read > 0) {
        size_t path_start = request.find(' ');
        size_t path_end = request.find(' ', path_start + 1);
        if (path_start != std::string::npos && path_end != std::string::npos) {
            path = request.substr(path_start + 1, path_end - path_start - 1);
        }
    }

    // 调试：输出解析的路径
    LOG_DEBUG("[HTTP] " << client_ip << " path=" << path << " len=" << path.length());

    // 检查是否是ACME验证请求（支持带查询参数的情况）
    size_t acme_pos = path.find("/.well-known/acme-challenge/");
    if (acme_pos == 0) {
        // 提取 token（去除可能的查询参数）
        std::string token = path.substr(28);
        size_t query_pos = token.find('?');
        if (query_pos != std::string::npos) {
            token = token.substr(0, query_pos);
        }

        if (!is_valid_token_name(token)) {
            std::string resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request";
            send(client_socket, resp.c_str(), resp.length(), MSG_NOSIGNAL);
            close(client_socket);
            return;
        }

        // 优先从本地 webroot 读取
        std::string file_path = g_acme_webroot + "/.well-known/acme-challenge/" + token;
        if (g_log_level >= 4) std::cout << "[ACME] 尝试读取: " << file_path << std::endl;
        std::ifstream file(file_path);

        if (file.is_open()) {
            std::ostringstream ss;
            ss << file.rdbuf();
            std::string content = ss.str();
            file.close();

            // 优化：直接字符串拼接构建响应，避免ostringstream开销
            std::string resp = "HTTP/1.1 200 OK\r\n"
                               "Content-Type: text/plain\r\n"
                               "Content-Length: " + std::to_string(content.length()) + "\r\n"
                               "\r\n" + content;
            send(client_socket, resp.c_str(), resp.length(), MSG_NOSIGNAL);
            std::cout << "[ACME本地] " << client_ip << " -> " << path << " (成功)" << std::endl;
        } else if (!g_acme_backend.empty() || !g_master_ip.empty()) {
            // 本地没有，转发到后端（优先使用 g_acme_backend，否则使用主控 g_master_ip）
            std::string backend_ip = g_acme_backend.empty() ? g_master_ip : g_acme_backend;
            int backend_port = g_acme_backend.empty() ? 80 : g_acme_backend_port;  // 主控用80端口

            std::cout << "[ACME转发] " << client_ip << " -> " << backend_ip << ":" << backend_port << " " << path << std::endl;

            // 转发请求到后端
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            std::string response_data;

            if (sock >= 0) {
                struct sockaddr_in server_addr;
                memset(&server_addr, 0, sizeof(server_addr));
                server_addr.sin_family = AF_INET;
                server_addr.sin_port = htons(backend_port);

                if (inet_pton(AF_INET, backend_ip.c_str(), &server_addr.sin_addr) > 0) {
                    struct timeval timeout = {10, 0};
                    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

                    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
                        send(sock, request.c_str(), request.length(), MSG_NOSIGNAL);
                        char buffer[4096];
                        int bytes;
                        while ((bytes = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
                            buffer[bytes] = '\0';
                            response_data += buffer;
                        }
                    }
                }
                close(sock);
            }

            if (!response_data.empty()) {
                send(client_socket, response_data.c_str(), response_data.length(), MSG_NOSIGNAL);
                std::cout << "[ACME转发] 成功" << std::endl;
            } else {
                std::string err = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nBad Gateway";
                send(client_socket, err.c_str(), err.length(), MSG_NOSIGNAL);
                std::cout << "[ACME转发] 失败" << std::endl;
            }
        } else {
            // 本地没有，也没配置后端
            std::string err = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
            send(client_socket, err.c_str(), err.length(), MSG_NOSIGNAL);
            std::cout << "[ACME本地] " << client_ip << " -> " << path << " (未找到)" << std::endl;
        }
        close(client_socket);
        return;
    }

    // 检查是否是带 ?u= 参数的跳转请求（CDN反代时可能通过HTTP转发）
    size_t u_param_pos = path.find("?u=");
    if (u_param_pos == std::string::npos) {
        u_param_pos = path.find("&u=");
    }
    if (u_param_pos != std::string::npos && !get_u_forward_ip().empty()) {
        std::string forward_ip = get_u_forward_ip();
        int inflight = g_master_forward_inflight.fetch_add(1, std::memory_order_relaxed) + 1;
        if (inflight > MAX_MASTER_FORWARD_INFLIGHT) {
            g_master_forward_inflight.fetch_sub(1, std::memory_order_relaxed);
            const std::string& response = get_cached_blind_response();
            tcp_send_all(client_socket, response.c_str(), response.length());
            close(client_socket);
            return;
        }

        // 这是一个跳转请求，需要转发到主控处理
        LOG_DEBUG("[HTTP] " << client_ip << " -> 主控 " << forward_ip << ":" << g_transfer_server_port << " path=" << path);

        bool forward_success = false;

        // 使用SSL连接池获取连接
        int master_sock = -1;
        SSL* master_ssl = nullptr;
        if (g_master_ssl_pool) {
            bool pool_success = false;
            master_ssl = g_master_ssl_pool->get_connection(forward_ip, g_transfer_server_port, master_sock, pool_success);
            if (pool_success && master_ssl) {
                // 转发请求到主控
                std::string req;
                req.reserve(64 + path.size() + forward_ip.size());
                req += "GET ";
                req += path;
                req += " HTTP/1.1\r\nHost: ";
                req += forward_ip;
                req += "\r\nConnection: close\r\n\r\n";
                int write_ret = SSL_write(master_ssl, req.c_str(), req.length());
                if (write_ret > 0) {
                    char resp_buf[8192];
                    int resp_len = SSL_read(master_ssl, resp_buf, sizeof(resp_buf));
                    if (resp_len > 0) {
                        int status_code = 0;
                        if (resp_len >= 12 && resp_buf[0] == 'H') {
                            try { status_code = std::stoi(std::string(resp_buf + 9, 3)); } catch (...) {}
                        }
                        // 提取 ?u= 参数值作为域名
                        std::string http_req_u;
                        size_t u_val_pos = path.find("?u=");
                        if (u_val_pos == std::string::npos) u_val_pos = path.find("&u=");
                        if (u_val_pos != std::string::npos) {
                            u_val_pos += 3;
                            size_t u_end = path.find_first_of("&# ", u_val_pos);
                            http_req_u = path.substr(u_val_pos, u_end == std::string::npos ? std::string::npos : u_end - u_val_pos);
                        }
                        if (status_code >= 400) {
                            bool is_404 = (status_code == 404);
                            std::string err_html = generate_error_html(http_req_u.empty() ? "未知域名" : http_req_u, !is_404);
                            std::string err_resp = "HTTP/1.1 " + std::string(is_404 ? "404 Not Found" : "503 Service Unavailable") +
                                "\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: " + std::to_string(err_html.length()) +
                                "\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'\r\nConnection: close\r\n\r\n" + err_html;
                            send(client_socket, err_resp.c_str(), err_resp.length(), MSG_NOSIGNAL);
                            LOG_DEBUG("[HTTP] 主控返回" << status_code << "，替换为自定义页面: " << http_req_u);
                        } else {
                            send(client_socket, resp_buf, resp_len, MSG_NOSIGNAL);
                            while ((resp_len = SSL_read(master_ssl, resp_buf, sizeof(resp_buf))) > 0) {
                                send(client_socket, resp_buf, resp_len, MSG_NOSIGNAL);
                            }
                        }
                        forward_success = true;
                        LOG_DEBUG("[HTTP] 转发完成，状态码: " << status_code << " 域名: " << http_req_u);
                    }
                }
                // 归还连接给连接池
                g_master_ssl_pool->return_connection(master_ssl);
            }
        }

        // 连接池获取失败或未启用时，降级到创建新连接方式
        if (!forward_success && master_sock < 0 && !forward_ip.empty()) {
            int fallback_sock = socket(AF_INET, SOCK_STREAM, 0);
            if (fallback_sock >= 0) {
                struct sockaddr_in master_addr;
                memset(&master_addr, 0, sizeof(master_addr));
                master_addr.sin_family = AF_INET;
                master_addr.sin_port = htons(g_transfer_server_port);

                if (inet_pton(AF_INET, forward_ip.c_str(), &master_addr.sin_addr) > 0) {
                    struct timeval tv = {10, 0};
                    setsockopt(fallback_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                    setsockopt(fallback_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

                    if (connect(fallback_sock, (struct sockaddr*)&master_addr, sizeof(master_addr)) == 0) {
                        std::call_once(g_client_ssl_ctx_init, init_client_ssl_ctx);
                        if (g_client_ssl_ctx) {
                            SSL* fallback_ssl = SSL_new(g_client_ssl_ctx);
                            if (fallback_ssl) {
                                SSL_set_fd(fallback_ssl, fallback_sock);
                                bool ssl_ok = false;
                                int ssl_retry = 0;
                                const int MAX_SSL_SELECT = 10;
                                while (ssl_retry < MAX_SSL_SELECT) {
                                    int ret = SSL_connect(fallback_ssl);
                                    if (ret == 1) {
                                        ssl_ok = true;
                                        break;
                                    }
                                    int err = SSL_get_error(fallback_ssl, ret);
                                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                                        struct pollfd pfd;
                                        pfd.fd = fallback_sock;
                                        pfd.events = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
                                        int sel = poll(&pfd, 1, 3000);  // 3秒=3000毫秒
                                        if (sel > 0) {
                                            ssl_retry++;
                                        } else {
                                            break;
                                        }
                                    } else {
                                        break;
                                    }
                                }
                                if (ssl_ok) {
                                    std::string req;
                                    req.reserve(64 + path.size() + forward_ip.size());
                                    req += "GET ";
                                    req += path;
                                    req += " HTTP/1.1\r\nHost: ";
                                    req += forward_ip;
                                    req += "\r\nConnection: close\r\n\r\n";
                                    SSL_write(fallback_ssl, req.c_str(), req.length());

                                    char resp_buf[8192];
                                    int resp_len = SSL_read(fallback_ssl, resp_buf, sizeof(resp_buf));
                                    if (resp_len > 0) {
                                        int status_code = 0;
                                        if (resp_len >= 12 && resp_buf[0] == 'H') {
                                            try { status_code = std::stoi(std::string(resp_buf + 9, 3)); } catch (...) {}
                                        }
                                        std::string http_req_u;
                                        size_t u_val_pos = path.find("?u=");
                                        if (u_val_pos == std::string::npos) u_val_pos = path.find("&u=");
                                        if (u_val_pos != std::string::npos) {
                                            u_val_pos += 3;
                                            size_t u_end = path.find_first_of("&# ", u_val_pos);
                                            http_req_u = path.substr(u_val_pos, u_end == std::string::npos ? std::string::npos : u_end - u_val_pos);
                                        }
                                        if (status_code >= 400) {
                                            bool is_404 = (status_code == 404);
                                            std::string err_html = generate_error_html(http_req_u.empty() ? "未知域名" : http_req_u, !is_404);
                                            std::string err_resp = "HTTP/1.1 " + std::string(is_404 ? "404 Not Found" : "503 Service Unavailable") +
                                                "\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: " + std::to_string(err_html.length()) +
                                                "\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'\r\nConnection: close\r\n\r\n" + err_html;
                                            send(client_socket, err_resp.c_str(), err_resp.length(), MSG_NOSIGNAL);
                                        } else {
                                            send(client_socket, resp_buf, resp_len, MSG_NOSIGNAL);
                                            while ((resp_len = SSL_read(fallback_ssl, resp_buf, sizeof(resp_buf))) > 0) {
                                                send(client_socket, resp_buf, resp_len, MSG_NOSIGNAL);
                                            }
                                        }
                                        forward_success = true;
                                    }
                                }
                                safe_ssl_shutdown(fallback_ssl);
                                SSL_free(fallback_ssl);
                            }
                        }
                    }
                }
                close(fallback_sock);
            }
        }

        g_master_forward_inflight.fetch_sub(1, std::memory_order_relaxed);

        // 如果转发失败，返回美化错误页面
        if (!forward_success) {
            std::string error_html = generate_error_html("主控服务器", true);
            std::string response = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: " + std::to_string(error_html.length()) + "\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'\r\nConnection: close\r\n\r\n" + error_html;
            send(client_socket, response.c_str(), response.length(), MSG_NOSIGNAL);
        }

        close(client_socket);
        return;
    }

    // 非ACME非?u=请求：301重定向到HTTPS
    std::string host;
    size_t host_pos = request.find("Host: ");
    if (host_pos != std::string::npos) {
        host_pos += 6;
        size_t host_end = request.find("\r\n", host_pos);
        if (host_end != std::string::npos) {
            host = request.substr(host_pos, host_end - host_pos);
            size_t port_colon = host.find(':');
            if (port_colon != std::string::npos) host = host.substr(0, port_colon);
        }
    }
    if (!host.empty()) {
        std::string location = "https://" + host + path;
        std::string resp = "HTTP/1.1 301 Moved Permanently\r\nLocation: " + location +
            "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send(client_socket, resp.c_str(), resp.length(), MSG_NOSIGNAL);
        LOG_DEBUG("[HTTP重定向] " << client_ip << " -> " << location);
    } else {
        const std::string& response = get_cached_blind_response();
        tcp_send_all(client_socket, response.c_str(), response.length());
        LOG_DEBUG("[HTTP盲发] " << client_ip);
    }

    shutdown(client_socket, SHUT_RDWR);
    close(client_socket);
}

// 处理HTTPS客户端连接（443端口盲发模式）
// ==================== ?u= 请求转发到主控（复用已握手的客户端SSL） ====================
// 从epoll路径调用时SSL已握手，避免线程池回退导致的二次TLS握手
// 此函数全权负责 client_ssl 和 client_fd 的生命周期，调用后两者均被释放
static void forward_https_u_request(SSL* client_ssl, int client_fd,
                                     const std::string& request_path,
                                     const std::string& client_ip) {
    // 切回阻塞模式（epoll accept4创建的是非阻塞socket）
    {
        int flags = fcntl(client_fd, F_GETFL, 0);
        if (flags >= 0) fcntl(client_fd, F_SETFL, flags & ~O_NONBLOCK);
    }

    int flag = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    setsockopt(client_fd, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(flag));
    int sndbuf = 65536, rcvbuf = 65536;
    setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    int keepalive = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    struct timeval timeout = {2, 0};
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    std::string forward_ip = get_u_forward_ip();
    if (forward_ip.empty()) {
        const std::string& response = get_cached_blind_response();
        ERR_clear_error();
        SSL_write(client_ssl, response.c_str(), response.length());
        safe_ssl_shutdown(client_ssl);
        SSL_free(client_ssl);
        close(client_fd);
        return;
    }

    int inflight = g_master_forward_inflight.fetch_add(1, std::memory_order_relaxed) + 1;
    if (inflight > MAX_MASTER_FORWARD_INFLIGHT) {
        g_master_forward_inflight.fetch_sub(1, std::memory_order_relaxed);
        const std::string& response = get_cached_blind_response();
        ERR_clear_error();
        SSL_write(client_ssl, response.c_str(), response.length());
        safe_ssl_shutdown(client_ssl);
        SSL_free(client_ssl);
        close(client_fd);
        return;
    }

    bool forward_success = false;
    std::string req_u = extract_u_param_from_path(request_path);
    LOG_DEBUG("[HTTPS] " << client_ip << " -> 转发跳转请求到主控: " << forward_ip << ":" << g_transfer_server_port << " 路径: " << request_path << (req_u.empty() ? "" : (" (u=" + req_u + ")")));

    // 使用SSL连接池获取连接
    int master_sock = -1;
    SSL* master_ssl = nullptr;
    if (g_master_ssl_pool) {
        bool pool_success = false;
        master_ssl = g_master_ssl_pool->get_connection(forward_ip, g_transfer_server_port, master_sock, pool_success);
        if (pool_success && master_ssl) {
            std::string req;
            req.reserve(256 + request_path.size());
            req += "GET ";
            req += request_path;
            req += " HTTP/1.1\r\nHost: ";
            req += forward_ip;
            req += "\r\nConnection: close\r\n\r\n";

            int write_ret = SSL_write(master_ssl, req.c_str(), req.length());
            if (write_ret > 0) {
                char resp_buf[8192];
                int resp_len = SSL_read(master_ssl, resp_buf, sizeof(resp_buf));
                if (resp_len > 0) {
                    int status_code = 0;
                    if (resp_len >= 12 && resp_buf[0] == 'H') {
                        try { status_code = std::stoi(std::string(resp_buf + 9, 3)); } catch (...) {}
                    }
                    if (status_code >= 400) {
                        bool is_404 = (status_code == 404);
                        std::string err_html = generate_error_html(req_u.empty() ? "未知域名" : req_u, !is_404);
                        std::string err_resp = generate_response(err_html);
                        SSL_write(client_ssl, err_resp.c_str(), err_resp.length());
                        LOG_DEBUG("[HTTPS] 主控返回" << status_code << "，替换为自定义页面: " << req_u);
                    } else {
                        SSL_write(client_ssl, resp_buf, resp_len);
                        while ((resp_len = SSL_read(master_ssl, resp_buf, sizeof(resp_buf))) > 0) {
                            SSL_write(client_ssl, resp_buf, resp_len);
                        }
                    }
                    forward_success = true;
                    LOG_DEBUG("[HTTPS] 转发完成，状态码: " << status_code << " 域名: " << req_u);
                }
            }
            g_master_ssl_pool->return_connection(master_ssl);
        }
    }

    // 连接池获取失败或未启用连接池时，降级到创建新连接
    if (!forward_success && master_sock < 0 && !forward_ip.empty()) {
        int fallback_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (fallback_sock >= 0) {
            struct sockaddr_in master_addr;
            memset(&master_addr, 0, sizeof(master_addr));
            master_addr.sin_family = AF_INET;
            master_addr.sin_port = htons(g_transfer_server_port);

            if (inet_pton(AF_INET, forward_ip.c_str(), &master_addr.sin_addr) > 0) {
                struct timeval tv = {10, 0};
                setsockopt(fallback_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                setsockopt(fallback_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

                if (connect(fallback_sock, (struct sockaddr*)&master_addr, sizeof(master_addr)) == 0) {
                    std::call_once(g_client_ssl_ctx_init, init_client_ssl_ctx);
                    if (g_client_ssl_ctx) {
                        SSL* fallback_ssl = SSL_new(g_client_ssl_ctx);
                        if (fallback_ssl) {
                            SSL_set_fd(fallback_ssl, fallback_sock);
                            bool ssl_ok = false;
                            int ssl_retry = 0;
                            const int MAX_SSL_SELECT = 10;
                            while (ssl_retry < MAX_SSL_SELECT) {
                                int ret = SSL_connect(fallback_ssl);
                                if (ret == 1) { ssl_ok = true; break; }
                                int err = SSL_get_error(fallback_ssl, ret);
                                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                                    struct pollfd pfd;
                                    pfd.fd = fallback_sock;
                                    pfd.events = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
                                    int sel = poll(&pfd, 1, 3000);
                                    if (sel > 0) { ssl_retry++; } else { break; }
                                } else { break; }
                            }
                            if (ssl_ok) {
                                std::string req;
                                req.reserve(256 + request_path.size());
                                req += "GET ";
                                req += request_path;
                                req += " HTTP/1.1\r\nHost: ";
                                req += forward_ip;
                                req += "\r\nConnection: close\r\n\r\n";
                                SSL_write(fallback_ssl, req.c_str(), req.length());

                                char resp_buf[8192];
                                int resp_len = SSL_read(fallback_ssl, resp_buf, sizeof(resp_buf));
                                if (resp_len > 0) {
                                    int status_code = 0;
                                    if (resp_len >= 12 && resp_buf[0] == 'H') {
                                        try { status_code = std::stoi(std::string(resp_buf + 9, 3)); } catch (...) {}
                                    }
                                    if (status_code >= 400) {
                                        bool is_404 = (status_code == 404);
                                        std::string err_html = generate_error_html(req_u.empty() ? "未知域名" : req_u, !is_404);
                                        std::string err_resp = generate_response(err_html);
                                        SSL_write(client_ssl, err_resp.c_str(), err_resp.length());
                                    } else {
                                        SSL_write(client_ssl, resp_buf, resp_len);
                                        while ((resp_len = SSL_read(fallback_ssl, resp_buf, sizeof(resp_buf))) > 0) {
                                            SSL_write(client_ssl, resp_buf, resp_len);
                                        }
                                    }
                                    forward_success = true;
                                }
                            }
                            safe_ssl_shutdown(fallback_ssl);
                            SSL_free(fallback_ssl);
                        }
                    }
                }
            }
            close(fallback_sock);
        }
    }

    // 转发失败时尝试走主控管理口解析；再失败则本地盲发
    if (!forward_success) {
        std::string u = extract_param_from_path(request_path, "u");
        std::string p = extract_param_from_path(request_path, "p");
        int api_sock = socket(AF_INET, SOCK_STREAM, 0);
        bool resolved = false;
        std::string location;
        if (api_sock >= 0 && !u.empty()) {
            struct sockaddr_in api_addr;
            memset(&api_addr, 0, sizeof(api_addr));
            api_addr.sin_family = AF_INET;
            api_addr.sin_port = htons(g_master_port);
            if (inet_pton(AF_INET, forward_ip.c_str(), &api_addr.sin_addr) > 0) {
                struct timeval tv = {3, 0};
                setsockopt(api_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                setsockopt(api_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                if (connect(api_sock, (struct sockaddr*)&api_addr, sizeof(api_addr)) == 0) {
                    std::ostringstream req;
                    req << "GET /api/node/resolve?key=" << g_api_key
                        << "&u=" << u
                        << "&p=" << (p.empty() ? "/" : p)
                        << " HTTP/1.1\r\n"
                        << "Host: " << forward_ip << "\r\nConnection: close\r\n\r\n";
                    std::string reqs = req.str();
                    send(api_sock, reqs.c_str(), reqs.length(), 0);
                    std::string resp;
                    char b[4096];
                    int n;
                    while ((n = recv(api_sock, b, sizeof(b) - 1, 0)) > 0) {
                        b[n] = '\0';
                        resp += b;
                    }
                    if (resp.find("\"success\":true") != std::string::npos && parse_location_from_json(resp, location) && !location.empty()) {
                        resolved = true;
                    }
                }
            }
            close(api_sock);
        }

        if (resolved) {
            std::string resp = "HTTP/1.1 302 Found\r\nLocation: " + location + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            SSL_write(client_ssl, resp.c_str(), resp.length());
        } else {
            LOG_WARN("[HTTPS] ?u=请求主控解析失败，降级本地盲发");
            const std::string& response = get_cached_blind_response();
            ERR_clear_error();
            SSL_write(client_ssl, response.c_str(), response.length());
        }
    }

    g_master_forward_inflight.fetch_sub(1, std::memory_order_relaxed);
    safe_ssl_shutdown(client_ssl);
    SSL_free(client_ssl);
    close(client_fd);
}

void handle_https_client(int client_socket, struct sockaddr_in client_addr) {
    SSL* ssl = nullptr;
    try {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

    // 切回阻塞模式：accept4(SOCK_NONBLOCK)创建的socket是非阻塞的，而工作线程使用同步IO
    {
        int flags = fcntl(client_socket, F_GETFL, 0);
        if (flags >= 0) fcntl(client_socket, F_SETFL, flags & ~O_NONBLOCK);
    }

    // 设置socket选项（性能优化 + 防卡死）
    int flag = 1;
    setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    setsockopt(client_socket, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(flag));
    int sndbuf = 65536, rcvbuf = 65536;
    setsockopt(client_socket, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    setsockopt(client_socket, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    // 禁用keepalive，盲发后直接关闭
    int keepalive = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));

    // 设置短超时（阻塞模式下生效，防慢客户端占着worker）
    struct timeval timeout = {2, 0};
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    // 创建SSL连接
    ssl = SSL_new(g_ssl_ctx);
    if (!ssl) {
        std::cerr << "[HTTPS] SSL_new失败: " << client_ip << std::endl;
        close(client_socket);
        return;
    }

    // SSL握手（CTX层已设 SSL_MODE_AUTO_RETRY|ACCEPT_MOVING_WRITE_BUFFER，无需重复设置）
    SSL_set_fd(ssl, client_socket);
    SSL_set_accept_state(ssl);

    bool handshake_ok = false;
    int retry_count = 0;
    const int MAX_SELECT_RETRIES = 2;   // 最多2次

    while (retry_count < MAX_SELECT_RETRIES) {
        ERR_clear_error();
        int ret = SSL_accept(ssl);
        if (ret == 1) {
            handshake_ok = true;
            break;
        }

        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            struct pollfd pfd;
            pfd.fd = client_socket;
            pfd.events = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            int sel = poll(&pfd, 1, 1000);  // 1秒超时（平衡高并发与成功率）
            if (sel <= 0) {
                // 超时或错误，强制关闭连接
                break;
            }
            retry_count++;
        } else {
            // 握手失败（非阻塞原因）
            break;
        }
    }

    if (!handshake_ok) {
        static std::atomic<int> g_ssl_error_count{0};
        static std::atomic<time_t> g_ssl_error_last_time{0};
        time_t now_ts = time(nullptr);
        time_t prev_ts = g_ssl_error_last_time.load(std::memory_order_relaxed);
        if (now_ts > prev_ts) {
            g_ssl_error_last_time.store(now_ts, std::memory_order_relaxed);
            g_ssl_error_count.store(0);
        }
        int count = g_ssl_error_count.fetch_add(1) + 1;
        if (count <= 10) {
            std::cerr << "[HTTPS] SSL握手超时/失败: " << client_ip << " (重试" << retry_count << "次)" << std::endl;
        } else if (count == 11) {
            std::cerr << "[HTTPS] SSL握手失败日志已限流..." << std::endl;
        }
        SSL_free(ssl);
        close(client_socket);
        return;
    }

    // ===== SNI 快速路径：握手完成后直接用SNI判断域名，跳过SSL_read（省1个RTT） =====
    // 主控需放行不在本地列表中的请求（中间域名 ?u= 转发），不能快速404
    if (g_local_domains_loaded.load()) {
        const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (sni && strlen(sni) > 0) {
            std::string snid = normalize_domain_name(std::string(sni));
            std::shared_lock<std::shared_mutex> lock(g_local_domains_mutex);
            if (g_local_domains.find(snid) != g_local_domains.end()) {
                // 域名在规则中，直接盲发，不读请求
                LOG_DEBUG("[HTTPS-SNI] " << client_ip << " -> " << snid << " (快速跳转)");
                const std::string& response = get_cached_blind_response();
                ERR_clear_error();
                SSL_write(ssl, response.c_str(), response.length());
                safe_ssl_shutdown(ssl);
                SSL_free(ssl);
                close(client_socket);
                return;
            }
            // SNI域名不在规则中，节点上可直接快速404；主控需放行以处理 ?u= 转发请求
            if (!g_is_master) {
                LOG_DEBUG("[HTTPS-SNI] " << client_ip << " -> " << snid << " (快速404)");
                const std::string& err_resp = get_cached_error_response(false);
                ERR_clear_error();
                SSL_write(ssl, err_resp.c_str(), err_resp.length());
                safe_ssl_shutdown(ssl);
                SSL_free(ssl);
                close(client_socket);
                return;
            }
        }
    }
    // ===== SNI快速路径结束 =====

    // 读取请求（循环读取直到获取完整HTTP头部）
    char buffer[4096] = {0};
    int total_read = 0;
    bool headers_complete = false;
    ERR_clear_error();
    while (total_read < (int)sizeof(buffer) - 1) {
        int bytes_read = SSL_read(ssl, buffer + total_read, sizeof(buffer) - 1 - total_read);
        if (bytes_read <= 0) break;
        total_read += bytes_read;
        buffer[total_read] = '\0';
        if (strstr(buffer, "\r\n\r\n")) { headers_complete = true; break; }
    }

    // 解析请求
    std::string request_str(buffer, total_read > 0 ? total_read : 0);

    // 检查是否是带 ?u= 参数的跳转请求（中间域名指向节点自身时）
    // 格式: GET /?u=域名&p=路径 HTTP/1.1
    size_t u_param_pos = request_str.find("?u=");
    if (u_param_pos == std::string::npos) {
        u_param_pos = request_str.find("&u=");
    }
    if (u_param_pos != std::string::npos && !get_u_forward_ip().empty()) {
        // 提取请求路径并委托给 forward_https_u_request（不再重复TLS握手）
        size_t path_start = request_str.find("GET ");
        size_t path_end = request_str.find(" HTTP/");
        if (path_start != std::string::npos && path_end != std::string::npos) {
            std::string req_path = request_str.substr(path_start + 4, path_end - path_start - 4);
            forward_https_u_request(ssl, client_socket, req_path, client_ip);
            ssl = nullptr;  // forward_https_u_request 已释放
            return;
        }
        // 无法解析路径，降级盲跳
        const std::string& response = get_cached_blind_response();
        ERR_clear_error();
        SSL_write(ssl, response.c_str(), response.length());
        safe_ssl_shutdown(ssl);
        SSL_free(ssl);
        close(client_socket);
        return;
    }

    // 解析Host头获取域名（用于日志）- 使用大小写不敏感搜索
    std::string domain;
    size_t host_pos = request_str.find("Host:");
    if (host_pos == std::string::npos) {
        host_pos = request_str.find("host:");
    }
    if (host_pos == std::string::npos) {
        host_pos = request_str.find("HOST:");
    }
    if (host_pos != std::string::npos) {
        size_t start = host_pos + 5;  // "Host:" 是5个字符
        // 跳过空格
        while (start < request_str.size() && (request_str[start] == ' ' || request_str[start] == '\t')) {
            start++;
        }
        size_t end = request_str.find("\r\n", start);
        if (end != std::string::npos && end > start) {
            domain = request_str.substr(start, end - start);
            // 移除端口号
            size_t colon = domain.find(':');
            if (colon != std::string::npos) {
                domain = domain.substr(0, colon);
            }
            domain = normalize_domain_name(domain);
        }
    }

    // 如果域名为空且本地列表已加载，尝试从SNI获取域名
    if (domain.empty() && ssl) {
        const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (sni && strlen(sni) > 0) {
            domain = normalize_domain_name(sni);
        }
    }

    // 后端检查域名是否在规则中
    std::string html;

    // 如果域名为空但本地列表已加载，尝试盲发
    if (domain.empty()) {
        if (g_local_domains_loaded.load()) {
            // 本地列表已加载，尝试盲发
            const std::string& response = get_cached_blind_response();
            ERR_clear_error();
            int sent = SSL_write(ssl, response.c_str(), response.length());
            safe_ssl_shutdown(ssl);
            SSL_free(ssl);
            close(client_socket);
            return;
        }
        // 无法获取域名，显示错误页面
        html = generate_error_html("未知域名", true);
        LOG_DEBUG("[HTTPS] " << client_ip << " -> (空域名) (错误)");
    } else {
        int check_result = check_domain_exists(domain);

        if (check_result == 1) {
            // 域名在规则中，直接使用缓存的盲发响应（避免每请求重建）
            LOG_DEBUG("[HTTPS] " << client_ip << " -> " << domain << " (跳转)");
            const std::string& response = get_cached_blind_response();
            ERR_clear_error();
            int sent = SSL_write(ssl, response.c_str(), response.length());
            if (sent <= 0) {
                // 添加速率限制避免日志刷屏
                static std::atomic<int> g_write_error_count{0};
                static std::atomic<time_t> g_write_error_last_time{0};
                int count = g_write_error_count.fetch_add(1) + 1;
                time_t now = time(nullptr);
                time_t prev_wt = g_write_error_last_time.load(std::memory_order_relaxed);
                if (now > prev_wt) {
                    g_write_error_last_time.store(now, std::memory_order_relaxed);
                    g_write_error_count.store(0);
                    count = 1;
                }
                if (count <= 5) {
                    std::cerr << "[HTTPS] SSL_write失败: " << client_ip << std::endl;
                }
            }
            safe_ssl_shutdown(ssl);
            SSL_free(ssl);
            close(client_socket);
            return;
        } else {
            // 域名不在规则中，使用缓存的404响应（避免每请求重建2KB HTML）
            LOG_DEBUG("[HTTPS] " << client_ip << " -> " << domain << " (域名不存在)");
            const std::string& err_resp = get_cached_error_response(false);
            ERR_clear_error();
            SSL_write(ssl, err_resp.c_str(), err_resp.length());
            safe_ssl_shutdown(ssl);
            SSL_free(ssl);
            close(client_socket);
            return;
        }
    }
    std::string response = generate_response(html);

    int sent = SSL_write(ssl, response.c_str(), response.length());
    if (sent <= 0) {
        // 添加速率限制避免日志刷屏
        static std::atomic<int> g_write_error_count2{0};
        static std::atomic<time_t> g_write_error_last_time2{0};
        int count = g_write_error_count2.fetch_add(1) + 1;
        time_t now = time(nullptr);
        time_t prev_wt2 = g_write_error_last_time2.load(std::memory_order_relaxed);
        if (now > prev_wt2) {
            g_write_error_last_time2.store(now, std::memory_order_relaxed);
            g_write_error_count2.store(0);
            count = 1;
        }
        if (count <= 5) {
            std::cerr << "[HTTPS] SSL_write失败: " << client_ip << std::endl;
        }
    }

    // 关闭连接
    safe_ssl_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
    } catch (const std::exception& e) {
        std::cerr << "[异常] handle_https_client: " << e.what() << std::endl;
        if (ssl) { safe_ssl_shutdown(ssl); SSL_free(ssl); }
        close(client_socket);
    } catch (...) {
        std::cerr << "[异常] handle_https_client: 未知异常" << std::endl;
        if (ssl) { safe_ssl_shutdown(ssl); SSL_free(ssl); }
        close(client_socket);
    }
}

// HTTP服务线程（80端口）
void http_server_thread() {
    g_server_socket_http = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_socket_http < 0) {
        std::cerr << "创建HTTP socket失败" << std::endl;
        return;
    }

    int opt = 1;
    setsockopt(g_server_socket_http, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(g_server_socket_http, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(g_server_socket_http, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
    // HTTP 关闭 TCP_DEFER_ACCEPT：非阻塞 accept4 与 defer_accept 组合
    // 在某些内核上会导致 accept4 即使设置 SOCK_NONBLOCK 也阻塞等待数据，
    // 表现为 HTTP 响应延迟 3 秒（defer_accept 超时值）。
    // HTTP 请求抵达后再 recv 已有 SO_RCVTIMEO 保护，不需要 defer_accept。
    // int defer_accept = 0; // 不设置即为关闭
    int sndbuf = 262144, rcvbuf = 262144;
    setsockopt(g_server_socket_http, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    setsockopt(g_server_socket_http, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(g_listen_port_http);

    if (bind(g_server_socket_http, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "绑定HTTP端口 " << g_listen_port_http << " 失败" << std::endl;
        close(g_server_socket_http);
        g_server_socket_http = -1;
        return;
    }

    if (listen(g_server_socket_http, 65535) < 0) {
        std::cerr << "HTTP监听失败" << std::endl;
        close(g_server_socket_http);
        g_server_socket_http = -1;
        return;
    }
    // 注册到shutdown列表
    {
        std::lock_guard<std::mutex> lock(g_listen_fds_mutex);
        g_listen_fds.push_back(g_server_socket_http);
    }

    std::cout << "HTTP服务已启动，端口: " << g_listen_port_http << std::endl;
    if (!g_acme_backend.empty()) {
        std::cout << "ACME转发: " << g_acme_backend << ":" << g_acme_backend_port << std::endl;
    }

    // 多线程 accept，使用 accept4(SOCK_NONBLOCK)
    unsigned int hw = std::thread::hardware_concurrency();
    unsigned int http_accept_threads = std::max(2u, std::min(4u, hw));
    std::cout << "[HTTP] Accept线程数: " << http_accept_threads << std::endl;
    for (unsigned int t = 0; t < http_accept_threads; ++t) {
        std::thread([t]() {
            std::cout << "[HTTP] Accept线程 #" << t << " 已启动" << std::endl;
            while (g_running) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_socket = accept4(g_server_socket_http, (struct sockaddr*)&client_addr, &client_len, SOCK_NONBLOCK);
                if (client_socket < 0) {
                    if (!g_running) break;
                    if (errno == EINTR) continue;
                    if (errno == EMFILE || errno == ENFILE || errno == ENOMEM) {
                        usleep(100000);
                    } else {
                        usleep(10000);
                    }
                    continue;
                }
                if (!check_ip_rate(client_addr.sin_addr.s_addr)) {
                    close(client_socket);
                    continue;
                }
                int flag = 1;
                setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
                setsockopt(client_socket, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(flag));
                if (!g_conn_pool->enqueue([client_socket, client_addr]{ handle_http_client(client_socket, client_addr); })) {
                    close(client_socket);
                }
            }
            std::cout << "[HTTP] Accept线程 #" << t << " 已退出" << std::endl;
        }).detach();
    }

    // 等待关闭信号
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (g_reload_requested.exchange(false, std::memory_order_acq_rel)) {
            do_config_reload();
        }
    }
}

// ACME专用端口服务线程（8080端口，不走Geneva）
// 专门处理ACME验证请求，通过iptables重定向从80端口过来
int g_server_socket_acme = -1;

void handle_acme_client(int client_socket, struct sockaddr_in client_addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

    // 设置较长超时（ACME验证需要足够时间）
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // 读取请求
    char buffer[4096] = {0};
    int total_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);

    std::string request = (total_read > 0) ? std::string(buffer, total_read) : "";
    std::string path = "/";

    if (total_read > 0) {
        size_t path_start = request.find(' ');
        size_t path_end = request.find(' ', path_start + 1);
        if (path_start != std::string::npos && path_end != std::string::npos) {
            path = request.substr(path_start + 1, path_end - path_start - 1);
        }
    }

    std::cout << "[ACME端口] 客户端: " << client_ip << " 路径: " << path << std::endl;

    std::string response;

    // 检查是否是ACME验证请求
    if (path.find("/.well-known/acme-challenge/") == 0) {
        std::string token = path.substr(28);
        size_t query_pos = token.find('?');
        if (query_pos != std::string::npos) {
            token = token.substr(0, query_pos);
        }

        // 优先从本地读取
        std::string file_path = g_acme_webroot + "/.well-known/acme-challenge/" + token;
        std::cout << "[ACME端口] 尝试本地文件: " << file_path << std::endl;
        std::ifstream file(file_path);
        if (file.is_open()) {
            std::stringstream ss;
            ss << file.rdbuf();
            std::string content = ss.str();
            file.close();
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
                       std::to_string(content.length()) + "\r\n\r\n" + content;
            std::cout << "[ACME端口] 本地响应成功: " << token << " 内容长度: " << content.length() << std::endl;
        } else if (!g_master_ip.empty()) {
            // 转发到主控（构造完整HTTP请求）
            std::cout << "[ACME端口] 本地文件不存在，转发到主控: " << g_master_ip << ":80" << std::endl;

            // 连接主控80端口
            int master_sock = socket(AF_INET, SOCK_STREAM, 0);
            if (master_sock >= 0) {
                struct sockaddr_in master_addr;
                master_addr.sin_family = AF_INET;
                master_addr.sin_port = htons(80);

                if (inet_pton(AF_INET, g_master_ip.c_str(), &master_addr.sin_addr) > 0) {
                    struct timeval tv = {3, 0};  // 减少超时避免阻塞
                    setsockopt(master_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                    setsockopt(master_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

                    if (connect(master_sock, (struct sockaddr*)&master_addr, sizeof(master_addr)) == 0) {
                        std::ostringstream req;
                        req << "GET " << path << " HTTP/1.1\r\n";
                        req << "Host: " << g_master_ip << "\r\n";
                        req << "Connection: close\r\n\r\n";
                        std::cout << "[ACME端口] 发送请求到主控..." << std::endl;
                        send(master_sock, req.str().c_str(), req.str().length(), 0);

                        char buf[4096];
                        std::string backend_resp;
                        int n;
                        while ((n = recv(master_sock, buf, sizeof(buf) - 1, 0)) > 0) {
                            buf[n] = '\0';
                            backend_resp += buf;
                        }

                        if (!backend_resp.empty()) {
                            response = backend_resp;
                            std::cout << "[ACME端口] 转发成功，响应长度: " << backend_resp.length() << std::endl;
                        } else {
                            std::cout << "[ACME端口] 主控无响应" << std::endl;
                            response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
                        }
                    } else {
                        std::cout << "[ACME端口] 连接主控失败: " << strerror(errno) << std::endl;
                        response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nBad Gateway";
                    }
                } else {
                    std::cout << "[ACME端口] 主控IP解析失败: " << g_master_ip << std::endl;
                    response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nBad Gateway";
                }
                close(master_sock);
            } else {
                std::cout << "[ACME端口] 创建socket失败" << std::endl;
                response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 21\r\n\r\nInternal Server Error";
            }
        } else {
            std::cout << "[ACME端口] 本地文件不存在且未配置主控IP" << std::endl;
            response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
        }
    } else {
        // 非ACME请求，返回盲发页面（使用缓存）
        response = get_cached_blind_response();
    }

    send(client_socket, response.c_str(), response.length(), MSG_NOSIGNAL);
    close(client_socket);
}

void acme_server_thread() {
    std::cout << "[ACME] 正在启动8080端口..." << std::endl;

    g_server_socket_acme = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_socket_acme < 0) {
        std::cerr << "[ACME] 创建socket失败: " << strerror(errno) << std::endl;
        return;
    }

    int opt = 1;
    setsockopt(g_server_socket_acme, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(g_server_socket_acme, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(8080);  // ACME专用端口

    if (bind(g_server_socket_acme, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "[ACME] 绑定8080端口失败: " << strerror(errno) << std::endl;
        close(g_server_socket_acme);
        g_server_socket_acme = -1;
        return;
    }

    if (listen(g_server_socket_acme, 2048) < 0) {
        std::cerr << "[ACME] 监听失败: " << strerror(errno) << std::endl;
        close(g_server_socket_acme);
        g_server_socket_acme = -1;
        return;
    }
    // 注册到shutdown列表
    {
        std::lock_guard<std::mutex> lock(g_listen_fds_mutex);
        g_listen_fds.push_back(g_server_socket_acme);
    }

    std::cout << "[ACME] 专用端口已启动: 8080（不走Geneva）" << std::endl;

    while (g_running) {
        // 处理 SIGHUP 配置重载请求
        if (g_reload_requested.exchange(false, std::memory_order_acq_rel)) {
            do_config_reload();
        }

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_socket = accept(g_server_socket_acme, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            if (g_running) {
                if (!g_is_master) poll_reload_flag();
                continue;
            }
            break;
        }

        if (!g_conn_pool->enqueue([client_socket, client_addr]{ handle_acme_client(client_socket, client_addr); })) {
            close(client_socket);
        }
    }

    if (g_server_socket_acme >= 0) {
        close(g_server_socket_acme);
        g_server_socket_acme = -1;
    }
}

// 执行系统命令并获取输出
std::string exec_command(const std::string& cmd) {
    std::string result;
    char buffer[128];
    FILE* pipe = popen(cmd.c_str(), "r");
    if (pipe) {
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        pclose(pipe);
    }
    return result;
}

// 从主控下载单个证书
// 解析HTTP响应状态码，失败返回0
static int parse_http_status(const std::string& response) {
    if (response.size() < 13) return 0;
    size_t space1 = response.find(' ');
    if (space1 == std::string::npos) return 0;
    size_t space2 = response.find(' ', space1 + 1);
    if (space2 == std::string::npos) return 0;
    try { return std::stoi(response.substr(space1 + 1, space2 - space1 - 1)); }
    catch (...) { return 0; }
}

// 解析Retry-After响应头，返回等待秒数，失败返回0
static int parse_retry_after(const std::string& response) {
    for (const auto& header : {"Retry-After:", "retry-after:"}) {
        size_t pos = response.find(header);
        if (pos != std::string::npos) {
            pos += strlen(header);
            while (pos < response.size() && response[pos] == ' ') pos++;
            size_t end = response.find("\r", pos);
            if (end == std::string::npos) end = response.find('\n', pos);
            if (end == std::string::npos) end = response.size();
            try { return std::stoi(response.substr(pos, end - pos)); }
            catch (...) { return 0; }
        }
    }
    return 0;
}

bool download_cert_from_master(const std::string& domain) {
    if (g_master_ip.empty()) return false;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_master_port);

    if (inet_pton(AF_INET, g_master_ip.c_str(), &addr.sin_addr) <= 0) {
        close(sock);
        return false;
    }

    struct timeval timeout = {30, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return false;
    }

    // 请求证书（主控管理端口是普通HTTP）
    std::ostringstream req;
    req << "GET /api/get_cert?key=" << g_api_key << "&domain=" << domain << " HTTP/1.1\r\n";
    req << "Host: " << g_master_ip << "\r\nConnection: close\r\n\r\n";
    send(sock, req.str().c_str(), req.str().length(), 0);

    // 读取响应
    char buffer[65536];
    std::string resp;
    int bytes;
    while ((bytes = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes] = '\0';
        resp += buffer;
    }

    close(sock);

    // 429频率限制处理
    int http_status = parse_http_status(resp);
    if (http_status == 429) {
        int delay = parse_retry_after(resp);
        if (delay <= 0 || delay > 300) delay = 60;
        std::cerr << "[证书同步] 主控限流(429)，等待 " << delay << " 秒..." << std::endl;
        sleep(delay);
        return false;
    }

    // 解析响应
    if (resp.find("\"success\":true") == std::string::npos) return false;

    size_t cert_pos = resp.find("\"cert\":\"");
    size_t key_pos = resp.find("\"key\":\"");
    if (cert_pos == std::string::npos || key_pos == std::string::npos) return false;

    cert_pos += 8;
    size_t cert_end = resp.find("\",", cert_pos);
    if (cert_end == std::string::npos) cert_end = resp.find("\"}", cert_pos);

    key_pos += 7;
    size_t key_end = resp.find("\",", key_pos);
    if (key_end == std::string::npos) key_end = resp.find("\"}", key_pos);

    if (cert_end == std::string::npos || key_end == std::string::npos) return false;

    std::string cert_escaped = resp.substr(cert_pos, cert_end - cert_pos);
    std::string key_escaped = resp.substr(key_pos, key_end - key_pos);

    // 反转义
    std::string cert_content, key_content;
    for (size_t i = 0; i < cert_escaped.length(); i++) {
        if (cert_escaped[i] == '\\' && i + 1 < cert_escaped.length() && cert_escaped[i+1] == 'n') {
            cert_content += '\n'; i++;
        } else {
            cert_content += cert_escaped[i];
        }
    }
    for (size_t i = 0; i < key_escaped.length(); i++) {
        if (key_escaped[i] == '\\' && i + 1 < key_escaped.length() && key_escaped[i+1] == 'n') {
            key_content += '\n'; i++;
        } else {
            key_content += key_escaped[i];
        }
    }

    // 保存到本地（按域名分目录存放）
    std::string domain_dir = "/opt/ssl/" + domain;
    safe_mkdir_p(domain_dir);
    std::string cert_file = domain_dir + "/fullchain.pem";
    std::string key_file = domain_dir + "/privkey.key";

    std::ofstream cert_out(cert_file, std::ios::out | std::ios::trunc);
    std::ofstream key_out(key_file, std::ios::out | std::ios::trunc);
    if (!cert_out.is_open() || !key_out.is_open()) {
        std::cerr << "[证书同步] 无法创建证书文件: " << domain << std::endl;
        return false;
    }

    cert_out << cert_content;
    key_out << key_content;
    cert_out.flush();
    key_out.flush();
    cert_out.close();
    key_out.close();

    // 设置文件权限
    chmod(cert_file.c_str(), 0644);
    chmod(key_file.c_str(), 0600);

    // 验证证书文件是否有效
    if (cert_content.find("-----BEGIN CERTIFICATE-----") == std::string::npos) {
        std::cerr << "[证书同步] 证书内容无效（缺少BEGIN CERTIFICATE）: " << domain << std::endl;
        return false;
    }
    if (key_content.find("-----BEGIN") == std::string::npos) {
        std::cerr << "[证书同步] 私钥内容无效（缺少BEGIN标记）: " << domain << std::endl;
        return false;
    }

    std::cout << "[证书同步] 证书已保存: " << cert_file << " (" << cert_content.length() << " bytes)" << std::endl;

    // 热加载到内存
    SSL_CTX* new_ctx = create_ssl_ctx(cert_file, key_file);
    if (new_ctx) {
        {
            std::unique_lock<std::shared_mutex> lock(g_domain_ssl_ctx_mutex);
            auto it = g_domain_ssl_ctx.find(domain);
            if (it != g_domain_ssl_ctx.end() && it->second) {
                SSL_CTX_free(it->second);
            }
            g_domain_ssl_ctx[domain] = new_ctx;
        }
        SSL_CTX_set_tlsext_servername_callback(g_ssl_ctx, sni_callback);
        std::cout << "[证书同步] 已加载: " << domain << std::endl;
        return true;
    } else {
        std::cerr << "[证书同步] SSL_CTX创建失败: " << domain << std::endl;
        // 输出OpenSSL错误信息
        unsigned long err;
        while ((err = ERR_get_error()) != 0) {
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            std::cerr << "[证书同步] OpenSSL错误: " << err_buf << std::endl;
        }
    }
    return false;
}

// 从主控同步所有证书
void sync_certs_from_master() {
    if (g_master_ip.empty()) {
        std::cout << "[证书同步] 未配置主控服务器，跳过同步" << std::endl;
        return;
    }

    std::cout << "[证书同步] 开始从主控同步证书..." << std::endl;

    // 获取证书列表
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cout << "[证书同步] 创建socket失败" << std::endl;
        return;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_master_port);

    if (inet_pton(AF_INET, g_master_ip.c_str(), &addr.sin_addr) <= 0) {
        close(sock);
        std::cout << "[证书同步] 无效的主控IP" << std::endl;
        return;
    }

    struct timeval timeout = {30, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        std::cout << "[证书同步] 无法连接主控: " << g_master_ip << ":" << g_master_port << " errno=" << errno << std::endl;
        return;
    }

    std::cout << "[证书同步] 已连接主控: " << g_master_ip << ":" << g_master_port << std::endl;

    // 请求证书列表（主控管理端口是普通HTTP）
    std::ostringstream req;
    req << "GET /api/list_certs?key=" << g_api_key << " HTTP/1.1\r\n";
    req << "Host: " << g_master_ip << "\r\nConnection: close\r\n\r\n";
    ssize_t sent = send(sock, req.str().c_str(), req.str().length(), 0);
    std::cout << "[证书同步] 发送请求 " << sent << " 字节" << std::endl;

    // 读取响应
    char buffer[65536];
    std::string resp;
    int bytes;
    while ((bytes = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes] = '\0';
        resp += buffer;
    }

    close(sock);

    // 429频率限制处理
    int http_status = parse_http_status(resp);
    if (http_status == 429) {
        int delay = parse_retry_after(resp);
        if (delay <= 0 || delay > 300) delay = 60;
        std::cout << "[证书同步] 主控限流(429)，等待 " << delay << " 秒后重试..." << std::endl;
        sleep(delay);
        return;
    }

    // 解析证书列表
    if (resp.find("\"success\":true") == std::string::npos) {
        std::cout << "[证书同步] 获取证书列表失败: " << (resp.empty() ? "(空响应)" : resp.substr(0, 200)) << std::endl;
        return;
    }

    // 解析 [{"domain":"xxx","mtime":123}, ...]
    size_t start = resp.find("[");
    size_t end = resp.rfind("]");
    if (start == std::string::npos || end == std::string::npos) return;

    std::string certs_str = resp.substr(start + 1, end - start - 1);
    std::vector<std::pair<std::string, long>> remote_certs; // domain, mtime
    remote_certs.reserve(128);  // 预分配，假设主控证书数量不超过128个

    // 解析每个证书对象
    size_t pos = 0;
    while ((pos = certs_str.find("{", pos)) != std::string::npos) {
        size_t obj_end = certs_str.find("}", pos);
        if (obj_end == std::string::npos) break;

        std::string obj = certs_str.substr(pos, obj_end - pos + 1);

        // 解析 domain
        size_t domain_pos = obj.find("\"domain\":\"");
        if (domain_pos != std::string::npos) {
            domain_pos += 10;
            size_t domain_end = obj.find("\"", domain_pos);
            if (domain_end != std::string::npos) {
                std::string domain = obj.substr(domain_pos, domain_end - domain_pos);

                // 解析 mtime
                long mtime = 0;
                size_t mtime_pos = obj.find("\"mtime\":");
                if (mtime_pos != std::string::npos) {
                    mtime_pos += 8;
                    mtime = std::stol(obj.substr(mtime_pos));
                }

                remote_certs.push_back({domain, mtime});
            }
        }
        pos = obj_end + 1;
    }

    std::cout << "[证书同步] 主控共有 " << remote_certs.size() << " 个证书" << std::endl;

    // 下载每个证书（检查本地是否需要更新）
    int success_count = 0;
    int skip_count = 0;

    // ── 第一遍：分类 ──
    // 已有本地文件且 mtime 足够新的 → 只需加载或跳过（无需网络）
    // 需要下载的 → 收集到列表，后续并行下载
    std::vector<std::string> need_download;
    need_download.reserve(remote_certs.size());
    for (const auto& cert : remote_certs) {
        const std::string& domain = cert.first;
        long remote_mtime = cert.second;

        std::string local_cert = "/opt/ssl/" + domain + "/fullchain.pem";
        struct stat st;
        long local_mtime = 0;
        if (stat(local_cert.c_str(), &st) == 0) {
            local_mtime = st.st_mtime;
        }

        if (local_mtime > 0 && local_mtime >= remote_mtime) {
            bool need_load = false;
            { std::shared_lock<std::shared_mutex> rl(g_domain_ssl_ctx_mutex); need_load = (g_domain_ssl_ctx.find(domain) == g_domain_ssl_ctx.end()); }
            if (need_load) {
                std::string cert_file = "/opt/ssl/" + domain + "/fullchain.pem";
                std::string key_file = "/opt/ssl/" + domain + "/privkey.key";
                SSL_CTX* new_ctx = create_ssl_ctx(cert_file, key_file);
                if (new_ctx) {
                    { std::unique_lock<std::shared_mutex> wl(g_domain_ssl_ctx_mutex); g_domain_ssl_ctx[domain] = new_ctx; }
                    SSL_CTX_set_tlsext_servername_callback(g_ssl_ctx, sni_callback);
                    std::cout << "[证书同步] 已加载本地证书: " << domain << std::endl;
                    success_count++;
                }
            } else {
                skip_count++;
            }
        } else {
            need_download.push_back(domain);
        }
    }

    // ── 第二遍：并行下载 ──
    if (!need_download.empty()) {
        int total = (int)need_download.size();
        // 并发度：根据本机CPU核数自适应，低配机器避免内存/CPU过载导致超时
        unsigned int hw = std::thread::hardware_concurrency();
        if (hw == 0) hw = 2;
        unsigned int max_threads;
        if (hw <= 2)      max_threads = 2;   // 双核及以下：防止内存耗尽
        else if (hw <= 4) max_threads = 4;   // 四核
        else              max_threads = 8;   // 八核及以上
        unsigned int nw = std::max(1u, std::min(max_threads, (unsigned int)(total / 200 + 1) * 2));
        std::cout << "[证书同步] 需要下载 " << total << " 个证书，使用 " << nw << " 个并行线程" << std::endl;

        std::atomic<int> dl_idx{0};
        std::atomic<int> dl_ok{0};
        std::atomic<int> dl_fail{0};

        auto worker = [&]() {
            while (true) {
                int i = dl_idx.fetch_add(1);
                if (i >= total) break;
                // 最多重试2次，重试间隔递增
                for (int retry = 0; retry < 3; retry++) {
                    if (download_cert_from_master(need_download[i])) {
                        dl_ok++;
                        break;
                    }
                    if (retry < 2) {
                        usleep(50000 * (retry + 1));  // 50ms, 100ms
                    } else {
                        dl_fail++;
                    }
                }
                // 线程内间隔，避免单线程连续请求触发主控瞬时压力
                usleep(10000);  // 10ms
            }
        };

        std::vector<std::thread> threads;
        for (unsigned int t = 0; t < nw; t++) {
            threads.emplace_back(worker);
        }
        for (auto& t : threads) t.join();

        success_count += dl_ok;
        std::cout << "[证书同步] 下载完成: 成功 " << dl_ok << ", 失败 " << dl_fail << std::endl;
    }

    std::cout << "[证书同步] 同步完成，下载 " << success_count << "，跳过 " << skip_count << std::endl;
}

// 定时同步线程函数
void cert_sync_thread_func() {
    std::cout << "[证书同步] 定时同步线程已启动，间隔: " << g_sync_interval << " 秒" << std::endl;

    while (g_running) {
        // 等待指定间隔
        for (int i = 0; i < g_sync_interval && g_running; i++) {
            sleep(1);
        }

        if (!g_running) break;

        // 执行同步
        std::cout << "[证书同步] 开始定时同步..." << std::endl;
        sync_certs_from_master();
    }

    std::cout << "[证书同步] 定时同步线程已停止" << std::endl;
}

// 申请证书（申请期间暂停Geneva以确保ACME验证正常）
std::string renew_certificate(const std::string& domain) {
    std::ostringstream result;
    result << "{\"domain\":\"" << domain << "\",";

    std::cout << "[证书申请] 开始为 " << domain << " 申请证书..." << std::endl;

    // 暂停 Geneva（确保 ACME HTTP 验证正常工作）
    bool geneva_was_enabled = g_geneva_enabled;
    if (geneva_was_enabled) {
        std::cout << "[证书申请] 停止 Geneva..." << std::endl;
        stop_geneva();
    }

    // 申请证书（尝试多个可能的 acme.sh 路径）
    std::cout << "[证书申请] 调用 acme.sh..." << std::endl;
    std::string acme_cmd;
    // 优先使用用户指定的路径
    if (!g_acme_path.empty() && access(g_acme_path.c_str(), X_OK) == 0) {
        acme_cmd = g_acme_path;
    } else if (access("/root/.acme.sh/acme.sh", X_OK) == 0) {
        acme_cmd = "/root/.acme.sh/acme.sh";
    } else if (access("/usr/local/bin/acme.sh", X_OK) == 0) {
        acme_cmd = "/usr/local/bin/acme.sh";
    } else {
        // 尝试展开 ~ 路径
        const char* home = getenv("HOME");
        if (home) {
            std::string home_path = std::string(home) + "/.acme.sh/acme.sh";
            if (access(home_path.c_str(), X_OK) == 0) {
                acme_cmd = home_path;
            }
        }
        if (acme_cmd.empty()) {
            acme_cmd = "/root/.acme.sh/acme.sh";  // 最后默认
        }
    }
    std::cout << "[证书申请] 使用 acme.sh: " << acme_cmd << std::endl;
    acme_cmd += " --issue -d " + domain + " -w " + g_acme_webroot + " --server letsencrypt 2>&1";
    std::string acme_output = exec_command(acme_cmd);

    bool success = (acme_output.find("Cert success") != std::string::npos ||
                    acme_output.find("Skip, Next renewal time") != std::string::npos ||
                    acme_output.find("already issued") != std::string::npos);

    if (success) {
        std::cout << "[证书申请] " << domain << " 证书申请成功!" << std::endl;

        // 6. 自动安装证书到 /opt/ssl/{domain}/
        std::string domain_dir = "/opt/ssl/" + domain;
        std::cout << "[证书申请] 安装证书到 " << domain_dir << "..." << std::endl;
        safe_mkdir_p(domain_dir);

        std::string acme_base;
        if (!g_acme_path.empty()) {
            acme_base = g_acme_path;
        } else {
            acme_base = "/root/.acme.sh/acme.sh";
        }

        std::string cert_file = domain_dir + "/fullchain.pem";
        std::string key_file = domain_dir + "/privkey.key";

        // 检测是否使用 ECC 证书（检查 _ecc 目录是否存在）
        std::string ecc_dir = "/root/.acme.sh/" + domain + "_ecc";
        std::string rsa_dir = "/root/.acme.sh/" + domain;
        bool use_ecc = (access(ecc_dir.c_str(), F_OK) == 0);

        std::ostringstream install_cmd;
        install_cmd << acme_base << " --install-cert -d " << domain;
        if (use_ecc) {
            install_cmd << " --ecc";
            std::cout << "[证书申请] 检测到 ECC 证书，使用 --ecc 参数" << std::endl;
        }
        install_cmd << " --key-file " << key_file
                    << " --fullchain-file " << cert_file
                    << " 2>&1";
        std::string install_output = exec_command(install_cmd.str());
        std::cout << "[证书申请] 安装输出: " << install_output << std::endl;

        // 7. 更新证书配置文件
        if (!g_cert_config.empty()) {
            std::cout << "[证书申请] 更新证书配置文件: " << g_cert_config << std::endl;

            // 读取现有配置
            std::ifstream config_in(g_cert_config);
            std::string config_content;
            bool domain_exists = false;
            std::string new_line = domain + " = " + cert_file + ", " + key_file;

            if (config_in.is_open()) {
                std::string line;
                while (std::getline(config_in, line)) {
                    // 检查是否已有该域名配置
                    if (line.find(domain + " ") == 0 || line.find(domain + "=") == 0) {
                        config_content += new_line + "\n";  // 替换旧配置
                        domain_exists = true;
                    } else {
                        config_content += line + "\n";
                    }
                }
                config_in.close();
            }

            // 如果域名不存在，追加
            if (!domain_exists) {
                config_content += new_line + "\n";
            }

            // 写回配置文件
            std::ofstream config_out(g_cert_config);
            if (config_out.is_open()) {
                config_out << config_content;
                config_out.close();
                std::cout << "[证书申请] 配置文件已更新" << std::endl;
            }
        }

        // 8. 热加载证书到内存
        std::cout << "[证书申请] 热加载证书..." << std::endl;

        // 等待文件系统同步
        usleep(500000);  // 500ms

        std::cout << "[证书申请] 检查证书文件: " << cert_file << std::endl;
        std::cout << "[证书申请] 检查私钥文件: " << key_file << std::endl;

        if (access(cert_file.c_str(), R_OK) != 0) {
            std::cout << "[证书申请] 错误: 证书文件不存在或不可读" << std::endl;
        } else if (access(key_file.c_str(), R_OK) != 0) {
            std::cout << "[证书申请] 错误: 私钥文件不存在或不可读" << std::endl;
        } else {
            SSL_CTX* new_ctx = create_ssl_ctx(cert_file, key_file);
            if (new_ctx) {
                // 加载成功，添加到域名证书映射
                {
                    std::unique_lock<std::shared_mutex> lock(g_domain_ssl_ctx_mutex);
                    auto it = g_domain_ssl_ctx.find(domain);
                    if (it != g_domain_ssl_ctx.end() && it->second) {
                        SSL_CTX_free(it->second);
                    }
                    g_domain_ssl_ctx[domain] = new_ctx;
                }

                // 同时更新默认 SNI 回调（如果尚未设置）
                SSL_CTX_set_tlsext_servername_callback(g_ssl_ctx, sni_callback);

                std::cout << "[证书申请] 证书已热加载: " << domain << std::endl;
            } else {
                std::cout << "[证书申请] 证书加载失败，请检查证书格式" << std::endl;
            }
        }

        result << "\"success\":true,\"message\":\"证书申请成功并已自动安装\"}";
    } else {
        // 转义 JSON 中的特殊字符
        std::string escaped_output;
        for (char c : acme_output) {
            if (c == '"') escaped_output += "\\\"";
            else if (c == '\\') escaped_output += "\\\\";
            else if (c == '\n') escaped_output += "\\n";
            else if (c == '\r') escaped_output += "\\r";
            else if (c == '\t') escaped_output += "\\t";
            else escaped_output += c;
        }
        result << "\"success\":false,\"message\":\"" << escaped_output << "\"}";
        std::cout << "[证书申请] " << domain << " 证书申请失败: " << acme_output << std::endl;
    }

    // 恢复 Geneva
    if (geneva_was_enabled) {
        std::cout << "[证书申请] 重启 Geneva..." << std::endl;
        restart_geneva();
    }

    return result.str();
}

// 解析URL参数
std::string get_param(const std::string& query, const std::string& name) {
    std::string search = name + "=";
    size_t pos = query.find(search);
    if (pos == std::string::npos) return "";
    pos += search.length();
    size_t end = query.find('&', pos);
    if (end == std::string::npos) end = query.length();
    return url_decode_component(query.substr(pos, end - pos));
}

// 处理管理API请求
void handle_api_client(int client_socket) {
    char buffer[4096] = {0};
    int bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);

    if (bytes_read <= 0) {
        close(client_socket);
        return;
    }

    std::string request(buffer);
    std::string response;

    // 解析请求方法、路径和参数
    std::string method = "GET";
    size_t method_end = request.find(' ');
    if (method_end != std::string::npos) method = request.substr(0, method_end);

    // 解析请求路径和参数
    size_t path_start = request.find(' ');
    size_t path_end = request.find(' ', path_start + 1);
    std::string full_path = "/";
    if (path_start != std::string::npos && path_end != std::string::npos) {
        full_path = request.substr(path_start + 1, path_end - path_start - 1);
    }

    // 分离路径和查询参数
    std::string path = full_path;
    std::string query = "";
    size_t query_pos = full_path.find('?');
    if (query_pos != std::string::npos) {
        path = full_path.substr(0, query_pos);
        query = full_path.substr(query_pos + 1);
    }

    // API: 申请证书 - 转发到主控（B+C方案：节点不申请，由主控统一申请）
    if (path == "/api/renew_cert" && (method == "POST" || method == "GET")) {
        std::string key = get_param(query, "key");
        std::string domain = get_param(query, "domain");

        // URL解码 domain
        std::string decoded_domain;
        for (size_t i = 0; i < domain.length(); i++) {
            if (domain[i] == '%' && i + 2 < domain.length()) {
                int value;
                std::istringstream iss(domain.substr(i + 1, 2));
                if (iss >> std::hex >> value) {
                    decoded_domain += static_cast<char>(value);
                    i += 2;
                } else {
                    decoded_domain += domain[i];
                }
            } else if (domain[i] == '+') {
                decoded_domain += ' ';
            } else {
                decoded_domain += domain[i];
            }
        }
        domain = decoded_domain;

        if (key != g_api_key) {
            response = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid API key\"}";
        } else if (!is_valid_cert_domain(domain)) {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid domain\"}";
        } else if (domain.empty()) {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Missing domain parameter\"}";
        } else if (g_master_ip.empty()) {
            // 没有配置主控，本地申请（单节点模式）
            std::string result = renew_certificate(domain);
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(result.length()) + "\r\n\r\n" + result;
        } else {
            // 转发到主控申请（多节点模式）
            std::cout << "[证书申请] 转发到主控: " << g_master_ip << ":" << g_master_port << " 域名: " << domain << std::endl;

            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Failed to create socket\"}";
            } else {
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons(g_master_port);

                if (inet_pton(AF_INET, g_master_ip.c_str(), &addr.sin_addr) <= 0) {
                    close(sock);
                    response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid master IP\"}";
                } else {
                    struct timeval timeout = {180, 0};  // 3分钟超时（证书申请需要时间）
                    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

                    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                        close(sock);
                        response = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Cannot connect to master\"}";
                    } else {
                        // 转发请求到主控（主控本地申请证书）
                        std::ostringstream req;
                        req << "POST /api/master_renew_cert?key=" << g_api_key << "&domain=" << domain << " HTTP/1.1\r\n";
                        req << "Host: " << g_master_ip << "\r\nConnection: close\r\n\r\n";
                        send(sock, req.str().c_str(), req.str().length(), 0);

                        // 读取主控响应
                        char buffer[8192];
                        std::string resp;
                        int bytes;
                        while ((bytes = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
                            buffer[bytes] = '\0';
                            resp += buffer;
                        }
                        close(sock);

                        // 提取响应体
                        size_t body_pos = resp.find("\r\n\r\n");
                        if (body_pos != std::string::npos) {
                            std::string body = resp.substr(body_pos + 4);
                            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.length()) + "\r\n\r\n" + body;

                            // 如果主控申请成功，等待同步证书
                            if (body.find("\"success\":true") != std::string::npos) {
                                std::cout << "[证书申请] 主控申请成功，等待证书同步..." << std::endl;
                                sleep(2);  // 等待2秒让主控保存证书
                                download_cert_from_master(domain);  // 立即从主控下载证书
                            }
                        } else {
                            response = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid response from master\"}";
                        }
                    }
                }
            }
        }
    }
    // API: 健康检查
    else if (path == "/api/health") {
        std::ostringstream hs;
        hs << "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
           << "{\"status\":\"ok\""
           << ",\"version\":\"" << VERSION << "\""
           << ",\"uptime\":" << (time(nullptr) - g_server_start_time);
        if (g_master_ssl_pool) {
            hs << ",\"ssl_pool\":{"
               << "\"total\":" << g_master_ssl_pool->total_conn()
               << ",\"in_use\":" << g_master_ssl_pool->in_use_conn()
               << ",\"max\":" << g_master_ssl_pool->max_conn()
               << ",\"hits\":" << g_master_ssl_pool->pool_hits()
               << ",\"misses\":" << g_master_ssl_pool->pool_misses()
               << ",\"full_events\":" << g_master_ssl_pool->pool_full()
               << "}";
        }
        hs << "}";
        response = hs.str();
    }
    // API: 切换ACME模式（用iptables重定向绕过Geneva，不停止Geneva）
    else if (path == "/api/acme_mode") {
        std::string key = get_param(query, "key");
        std::string action = get_param(query, "action");

        if (key != g_api_key) {
            response = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid API key\"}";
        } else if (action == "start") {
            // ACME模式：智能过滤，只对Let's Encrypt IP跳过窗口修改，其他流量继续抢答
            // 可选参数 ips: 逗号分隔的IP列表，添加到动态白名单
            // 可选参数 cidrs: 逗号分隔的CIDR列表（如 23.32.0.0/11,64.118.0.0/16），添加到动态段白名单
            std::string ips_param = get_param(query, "ips");
            std::string cidrs_param = get_param(query, "cidrs");
            int ip_count = 0;
            int cidr_count = 0;
            {
                std::lock_guard<std::mutex> lock(g_acme_ips_mutex);
                g_acme_whitelist_ips.clear();  // 先清空旧的
                g_acme_whitelist_cidrs.clear();
                if (!ips_param.empty()) {
                    std::istringstream iss(ips_param);
                    std::string ip_str;
                    while (std::getline(iss, ip_str, ',')) {
                        if (!ip_str.empty()) {
                            struct in_addr addr;
                            if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
                                g_acme_whitelist_ips.insert(addr.s_addr);
                                ip_count++;
                            }
                        }
                    }
                }
                if (!cidrs_param.empty()) {
                    std::istringstream iss(cidrs_param);
                    std::string cidr;
                    while (std::getline(iss, cidr, ',')) {
                        if (cidr.empty()) continue;
                        size_t slash = cidr.find('/');
                        if (slash == std::string::npos) continue;
                        std::string ip_part = cidr.substr(0, slash);
                        int prefix_len = atoi(cidr.substr(slash + 1).c_str());
                        if (prefix_len < 0 || prefix_len > 32) continue;
                        struct in_addr a;
                        if (inet_pton(AF_INET, ip_part.c_str(), &a) != 1) continue;
                        uint32_t ip = ntohl(a.s_addr);
                        uint32_t mask = (prefix_len == 0) ? 0u : (prefix_len == 32 ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - prefix_len)));
                        uint32_t start = ip & mask;
                        uint32_t end = (prefix_len == 0) ? 0xFFFFFFFFu : (start | (~mask));
                        g_acme_whitelist_cidrs.push_back({start, end});
                        cidr_count++;
                    }
                    // 排序+合并（提升查找效率）
                    std::sort(g_acme_whitelist_cidrs.begin(), g_acme_whitelist_cidrs.end(),
                              [](const CidrRange& a, const CidrRange& b){ return a.start < b.start; });
                    std::vector<CidrRange> merged;
                    for (const auto& r : g_acme_whitelist_cidrs) {
                        if (!merged.empty() && r.start <= merged.back().end + 1) {
                            merged.back().end = std::max(merged.back().end, r.end);
                        } else {
                            merged.push_back(r);
                        }
                    }
                    g_acme_whitelist_cidrs.swap(merged);
                }
            }
            std::cout << "[ACME模式] 启用ACME模式（智能过滤：Let's Encrypt IP跳过，其他流量继续抢答）" << std::endl;
            if (ip_count > 0) {
                std::cout << "[ACME模式] 已添加 " << ip_count << " 个动态白名单IP" << std::endl;
            }
            if (cidr_count > 0) {
                std::cout << "[ACME模式] 已添加 " << cidr_count << " 个动态CIDR段（合并为 " << g_acme_whitelist_cidrs.size() << " 个区间）" << std::endl;
            }
            g_acme_mode_active.store(true);
            std::cout << "[ACME模式] 已启用，抢答功能保持正常" << std::endl;
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"message\":\"ACME mode started\"}";
        } else if (action == "stop") {
            // 停用ACME模式：恢复正常窗口大小（0），清空动态白名单
            std::cout << "[ACME模式] 停用ACME模式（恢复窗口大小为" << g_geneva_window << "）..." << std::endl;
            g_acme_mode_active.store(false);
            {
                std::lock_guard<std::mutex> lock(g_acme_ips_mutex);
                g_acme_whitelist_ips.clear();
                g_acme_whitelist_cidrs.clear();
            }
            std::cout << "[ACME模式] Geneva窗口已恢复，动态白名单已清空" << std::endl;
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"message\":\"ACME mode stopped\"}";
        } else {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid action, use start or stop\"}";
        }
    }
    // API: 接收主控推送的ACME验证文件
    else if (path == "/api/acme_challenge" && method == "POST") {
        std::string key = get_param(query, "key");
        std::string token = get_param(query, "token");

        if (key != g_api_key) {
            response = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid API key\"}";
        } else if (!is_valid_token_name(token)) {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid token\"}";
        } else if (token.empty()) {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Missing token\"}";
        } else {
            // 从POST body中获取验证内容
            std::string content;
            size_t body_start = request.find("\r\n\r\n");
            if (body_start != std::string::npos) {
                content = request.substr(body_start + 4);
            }

            if (content.empty()) {
                response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Missing content\"}";
            } else {
                // 保存验证文件到本地
                std::string challenge_dir = g_acme_webroot + "/.well-known/acme-challenge";
                safe_mkdir_p(challenge_dir);

                std::string file_path = challenge_dir + "/" + token;
                std::ofstream file(file_path);
                if (file.is_open()) {
                    file << content;
                    file.close();
                    std::cout << "[ACME验证] 收到验证文件: " << token << " 内容长度: " << content.length() << std::endl;
                    response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"message\":\"Challenge saved\"}";
                } else {
                    std::cout << "[ACME验证] 保存验证文件失败: " << file_path << std::endl;
                    response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Failed to save challenge\"}";
                }
            }
        }
    }
    // API: 控制Geneva状态（备用方案）
    else if (path == "/api/geneva") {
        std::string key = get_param(query, "key");
        std::string action = get_param(query, "action");

        if (key != g_api_key) {
            response = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid API key\"}";
        } else if (action == "stop") {
            std::cout << "[Geneva] 收到主控通知，暂停Geneva..." << std::endl;
            stop_geneva();
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"message\":\"Geneva stopped\"}";
        } else if (action == "start") {
            std::cout << "[Geneva] 收到主控通知，启动Geneva..." << std::endl;
            restart_geneva();
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"message\":\"Geneva started\"}";
        } else {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid action, use stop or start\"}";
        }
    }
    // API: 控制GYD443状态（主控远程开启/关闭多端口窗口修改）
    else if (path == "/api/gyd443") {
        std::string key = get_param(query, "key");
        std::string action = get_param(query, "action");
        std::string ports = get_param(query, "ports");

        if (key != g_api_key) {
            response = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid API key\"}";
        } else if (action == "start" && !is_valid_port_list(ports)) {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid ports\"}";
        } else if (action == "start" && !ports.empty()) {
            std::cout << "[GYD443] 收到主控通知，启动GYD443, 端口: " << ports << std::endl;
            start_gyd443(ports);
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"message\":\"GYD443 started\",\"ports\":\"" + ports + "\"}";
        } else if (action == "stop") {
            std::cout << "[GYD443] 收到主控通知，停止GYD443..." << std::endl;
            stop_gyd443();
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"message\":\"GYD443 stopped\"}";
        } else if (action == "status") {
            std::string cur_ports;
            { std::lock_guard<std::mutex> lock(g_gyd443_ports_mutex); cur_ports = g_gyd443_ports; }
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"running\":" + std::string(g_gyd443_running.load() ? "true" : "false") + ",\"ports\":\"" + cur_ports + "\"}";
        } else {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid action, use start/stop/status (start requires ports param)\"}";
        }
    }
    // API: 控制Geneva443状态（主控远程开启/关闭简单窗口修改）
    else if (path == "/api/geneva443") {
        std::string key = get_param(query, "key");
        std::string action = get_param(query, "action");
        std::string ports = get_param(query, "ports");
        std::string window_str = get_param(query, "window");

        if (key != g_api_key) {
            response = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid API key\"}";
        } else if (action == "start" && !is_valid_port_list(ports)) {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid ports\"}";
        } else if (action == "start" && !ports.empty()) {
            if (!window_str.empty()) {
                try { g_geneva443_window.store((uint16_t)std::stoi(window_str), std::memory_order_release); } catch (...) {}
            }
            std::cout << "[Geneva443] 收到主控通知，启动Geneva443, 端口: " << ports << " 窗口: " << g_geneva443_window.load(std::memory_order_relaxed) << std::endl;
            start_geneva443(ports);
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"message\":\"Geneva443 started\",\"ports\":\"" + ports + "\"}";
        } else if (action == "stop") {
            std::cout << "[Geneva443] 收到主控通知，停止Geneva443..." << std::endl;
            stop_geneva443();
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"message\":\"Geneva443 stopped\"}";
        } else if (action == "status") {
            std::string cur_ports;
            { std::lock_guard<std::mutex> lock(g_geneva443_ports_mutex); cur_ports = g_geneva443_ports; }
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"running\":" + std::string(g_geneva443_running.load() ? "true" : "false") + ",\"ports\":\"" + cur_ports + "\",\"window\":" + std::to_string(g_geneva443_window.load(std::memory_order_relaxed)) + "}";
        } else {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid action, use start/stop/status\"}";
        }
    }
    // API: 删除证书
    else if (path == "/api/delete_cert") {
        std::string key = get_param(query, "key");
        std::string domain = get_param(query, "domain");

        if (key != g_api_key) {
            response = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid API key\"}";
        } else if (!is_valid_cert_domain(domain)) {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid domain\"}";
        } else if (domain.empty()) {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Missing domain\"}";
        } else {
            std::string domain_dir = "/opt/ssl/" + domain;
            bool deleted = safe_rmdir(domain_dir);

            if (deleted) {
                // 从SSL上下文缓存中移除
                {
                    std::unique_lock<std::shared_mutex> lock(g_domain_ssl_ctx_mutex);
                    auto it = g_domain_ssl_ctx.find(domain);
                    if (it != g_domain_ssl_ctx.end()) {
                        if (it->second) SSL_CTX_free(it->second);
                        g_domain_ssl_ctx.erase(it);
                    }
                }
                std::cout << "[证书删除] 已删除证书: " << domain << std::endl;
                response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"message\":\"Cert deleted: " + domain + "\"}";
            } else {
                response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Failed to delete cert\"}";
            }
        }
    }
    // API: 主控通知更新配置（中间域名、端口等）
    else if (path == "/api/update_config") {
        std::string key = get_param(query, "key");

        if (key != g_api_key) {
            response = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid API key\"}";
        } else {
            std::string new_middle_domain = get_param(query, "middle_domain");
            std::string new_port = get_param(query, "port");

            bool changed = false;
            std::ostringstream changes;

            if (!new_middle_domain.empty() || !new_port.empty()) {
                std::unique_lock<std::shared_mutex> ts_lock(g_transfer_server_mutex);
                if (!new_middle_domain.empty() && new_middle_domain != g_transfer_server) {
                    std::string old_domain = g_transfer_server;
                    g_transfer_server = new_middle_domain;
                    changes << "中间域名: " << old_domain << " -> " << new_middle_domain << " ";
                    changed = true;
                    std::cout << "[配置同步] 中间域名已更新: " << old_domain << " -> " << new_middle_domain << std::endl;
                }

                if (!new_port.empty()) {
                    int port = std::stoi(new_port);
                    if (port > 0 && port != g_transfer_server_port) {
                        int old_port = g_transfer_server_port;
                        g_transfer_server_port = port;
                        changes << "端口: " << old_port << " -> " << port << " ";
                        changed = true;
                        std::cout << "[配置同步] 中转端口已更新: " << old_port << " -> " << port << std::endl;
                    }
                }
            }

            // 检查是否需要立即重新拉取配置（如主控更新了过渡动画/错误页面）
            std::string do_fetch = get_param(query, "fetch_config");
            if (do_fetch == "1") {
                if (!g_config_fetch_inflight.exchange(true, std::memory_order_acq_rel)) {
                    enqueue_bg([]() {
                        fetch_config_from_master();
                        g_config_fetch_inflight.store(false, std::memory_order_release);
                    });
                }
                changes << "已触发配置重新拉取 ";
                changed = true;
            }

            if (changed) {
                response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"message\":\"Config updated: " + changes.str() + "\"}";
            } else {
                response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"message\":\"No changes needed\"}";
            }
        }
    }
    // API: 主控通知同步证书（主动推送）
    else if (path == "/api/sync_cert") {
        std::string key = get_param(query, "key");
        std::string domain = get_param(query, "domain");

        if (key != g_api_key) {
            response = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid API key\"}";
        } else if (!domain.empty() && !is_valid_cert_domain(domain)) {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Invalid domain\"}";
        } else if (domain.empty()) {
            // 没有指定域名，同步所有证书
            std::cout << "[证书同步] 收到主控通知，同步所有证书..." << std::endl;
            sync_certs_from_master();
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"message\":\"All certs synced\"}";
        } else {
            // 指定域名，只同步该域名的证书
            std::cout << "[证书同步] 收到主控通知，同步证书: " << domain << std::endl;
            if (download_cert_from_master(domain)) {
                response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"message\":\"Cert synced: " + domain + "\"}";
            } else {
                response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"message\":\"Failed to sync cert: " + domain + "\"}";
            }
        }
    }
    else {
        response = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Not found\"}";
    }

    send(client_socket, response.c_str(), response.length(), MSG_NOSIGNAL);
    close(client_socket);
}

// 管理API服务线程
void api_server_thread() {
    g_server_socket_api = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_socket_api < 0) {
        std::cerr << "创建API socket失败" << std::endl;
        return;
    }

    int opt = 1;
    setsockopt(g_server_socket_api, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(g_server_socket_api, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(g_api_port);

    if (bind(g_server_socket_api, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "绑定API端口 " << g_api_port << " 失败" << std::endl;
        close(g_server_socket_api);
        g_server_socket_api = -1;
        return;
    }

    if (listen(g_server_socket_api, 1024) < 0) {
        std::cerr << "API监听失败" << std::endl;
        close(g_server_socket_api);
        g_server_socket_api = -1;
        return;
    }
    // 注册到shutdown列表
    {
        std::lock_guard<std::mutex> lock(g_listen_fds_mutex);
        g_listen_fds.push_back(g_server_socket_api);
    }

    std::cout << "管理API已启动，端口: " << g_api_port << std::endl;

    while (g_running) {
        // 处理 SIGHUP 配置重载请求
        if (g_reload_requested.exchange(false, std::memory_order_acq_rel)) {
            do_config_reload();
        }

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_socket = accept(g_server_socket_api, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            if (g_running) {
                if (!g_is_master) poll_reload_flag();
                continue;
            }
            break;
        }

        // 设置超时
        struct timeval timeout;
        timeout.tv_sec = 120;  // 证书申请可能需要较长时间
        timeout.tv_usec = 0;
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        if (!g_conn_pool->enqueue([client_socket]{ handle_api_client(client_socket); })) {
            close(client_socket);
        }
    }
}

// ==================== 心跳上报功能 ====================

// 获取CPU使用率
double get_cpu_usage() {
    static std::atomic<long> prev_idle{0}, prev_total{0};
    std::ifstream stat("/proc/stat");
    std::string line;
    if (std::getline(stat, line)) {
        std::istringstream iss(line);
        std::string cpu;
        long user, nice, system, idle, iowait, irq, softirq, steal;
        iss >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;
        long idle_time = idle + iowait;
        long total_time = user + nice + system + idle + iowait + irq + softirq + steal;
        long diff_idle = idle_time - prev_idle.load();
        long diff_total = total_time - prev_total.load();
        prev_idle.store(idle_time);
        prev_total.store(total_time);
        if (diff_total > 0) {
            return 100.0 * (1.0 - (double)diff_idle / diff_total);
        }
    }
    return 0.0;
}

// 获取内存使用率
double get_mem_usage() {
    std::ifstream meminfo("/proc/meminfo");
    std::string line;
    long mem_total = 0, mem_available = 0;
    while (std::getline(meminfo, line)) {
        if (line.find("MemTotal:") == 0) {
            std::istringstream iss(line);
            std::string key;
            iss >> key >> mem_total;
        } else if (line.find("MemAvailable:") == 0) {
            std::istringstream iss(line);
            std::string key;
            iss >> key >> mem_available;
        }
    }
    if (mem_total > 0) {
        return 100.0 * (1.0 - (double)mem_available / mem_total);
    }
    return 0.0;
}

// 获取网络带宽（MB/s）
void get_bandwidth(double& in_mbps, double& out_mbps) {
    static std::atomic<long> prev_rx{0}, prev_tx{0};
    static std::atomic<time_t> prev_time{0};
    long rx_bytes = 0, tx_bytes = 0;

    std::ifstream netdev("/proc/net/dev");
    std::string line;
    while (std::getline(netdev, line)) {
        // 跳过lo接口
        if (line.find("lo:") != std::string::npos) continue;
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::istringstream iss(line.substr(colon + 1));
            long rx, tx;
            long dummy;
            iss >> rx >> dummy >> dummy >> dummy >> dummy >> dummy >> dummy >> dummy >> tx;
            rx_bytes += rx;
            tx_bytes += tx;
        }
    }

    time_t now = time(nullptr);
    time_t pt = prev_time.load();
    if (pt > 0 && now > pt) {
        double elapsed = now - pt;
        in_mbps = (rx_bytes - prev_rx.load()) / elapsed / 1024.0 / 1024.0;
        out_mbps = (tx_bytes - prev_tx.load()) / elapsed / 1024.0 / 1024.0;
    } else {
        in_mbps = 0.0;
        out_mbps = 0.0;
    }
    prev_rx.store(rx_bytes);
    prev_tx.store(tx_bytes);
    prev_time.store(now);
}

// 从主控获取配置（过渡动画HTML和HTTP响应头）
void fetch_config_from_master() {
    if (g_master_ip.empty()) return;

    // 构建HTTP请求（包含节点名称以获取节点特定配置）
    std::ostringstream req;
    req << "GET /api/node/config HTTP/1.1\r\n"
        << "Host: " << g_master_ip << ":" << g_master_port << "\r\n"
        << "X-API-Key: " << g_api_key << "\r\n";
    if (!g_node_name.empty()) {
        req << "X-Node-Name: " << g_node_name << "\r\n";
    }
    req << "Connection: close\r\n\r\n";

    // 发送请求
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_master_port);
    inet_pton(AF_INET, g_master_ip.c_str(), &addr.sin_addr);

    struct timeval tv;
    tv.tv_sec = 3;  // 减少超时时间，避免阻塞心跳线程
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        std::string request = req.str();
        send(sock, request.c_str(), request.length(), MSG_NOSIGNAL);
        // 接收响应
        char buffer[65536];
        std::string response;
        int n;
        while ((n = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[n] = '\0';
            response += buffer;
        }

        // 解析JSON响应
        if (response.find("\"success\":true") != std::string::npos) {
            // 解析transition_html
            size_t pos = response.find("\"transition_html\":\"");
            if (pos != std::string::npos) {
                pos += 19;
                std::string html;
                while (pos < response.length()) {
                    if (response[pos] == '\\' && pos + 1 < response.length()) {
                        char next = response[pos + 1];
                        if (next == 'n') { html += '\n'; pos += 2; }
                        else if (next == 'r') { html += '\r'; pos += 2; }
                        else if (next == 't') { html += '\t'; pos += 2; }
                        else if (next == '"') { html += '"'; pos += 2; }
                        else if (next == '\\') { html += '\\'; pos += 2; }
                        else { html += response[pos]; pos++; }
                    } else if (response[pos] == '"') {
                        break;
                    } else {
                        html += response[pos];
                        pos++;
                    }
                }
                g_custom_transition_html = html;
            }

            // 解析error_html
            pos = response.find("\"error_html\":\"");
            if (pos != std::string::npos) {
                pos += 14;
                std::string html;
                while (pos < response.length()) {
                    if (response[pos] == '\\' && pos + 1 < response.length()) {
                        char next = response[pos + 1];
                        if (next == 'n') html += '\n';
                        else if (next == 'r') html += '\r';
                        else if (next == 't') html += '\t';
                        else html += next;
                        pos += 2;
                    } else if (response[pos] == '"') {
                        break;
                    } else {
                        html += response[pos];
                        pos++;
                    }
                }
                g_custom_error_html = html;
            }

            // 解析404_html
            pos = response.find("\"404_html\":\"");
            if (pos != std::string::npos) {
                pos += 12;
                std::string html;
                while (pos < response.length()) {
                    if (response[pos] == '\\' && pos + 1 < response.length()) {
                        char next = response[pos + 1];
                        if (next == 'n') { html += '\n'; pos += 2; }
                        else if (next == 'r') { html += '\r'; pos += 2; }
                        else if (next == 't') { html += '\t'; pos += 2; }
                        else { html += next; pos += 2; }
                    } else if (response[pos] == '"') {
                        break;
                    } else {
                        html += response[pos];
                        pos++;
                    }
                }
                g_custom_404_html = html;
            }

            // 解析response_header
            pos = response.find("\"response_header\":\"");
            if (pos != std::string::npos) {
                pos += 19;
                std::string header;
                while (pos < response.length() && response[pos] != '"') {
                    if (response[pos] == '\\' && pos + 1 < response.length()) {
                        header += response[pos + 1];
                        pos += 2;
                    } else {
                        header += response[pos];
                        pos++;
                    }
                }
                g_custom_response_header = header;
            }

            // 解析transition_enabled
            if (response.find("\"transition_enabled\":false") != std::string::npos) {
                g_transition_enabled = false;
            } else {
                g_transition_enabled = true;
            }

            LOG_INFO("已从主控获取配置: 过渡动画=" << (!g_transition_enabled ? "已关闭" : g_custom_transition_html.empty() ? "默认" : "自定义") << ", 错误页面=" << (g_custom_error_html.empty() ? "默认" : "自定义") << ", 404页面=" << (g_custom_404_html.empty() ? "默认" : "自定义") << ", 响应头=" << g_custom_response_header);
            std::lock_guard<std::mutex> lock(g_blind_cache_mutex);
            g_blind_cache_key.clear();
        }
    }
    close(sock);
}

// 发送心跳到主控
void send_heartbeat() {
    if (g_master_ip.empty()) return;

    // 兜底：避免节点名为空导致完全不上报心跳
    std::string heartbeat_node_name = g_node_name;
    if (heartbeat_node_name.empty()) {
        heartbeat_node_name = get_local_ip();
        if (heartbeat_node_name.empty()) heartbeat_node_name = "node-unknown";
    }

    double cpu = get_cpu_usage();
    double mem = get_mem_usage();
    double bw_in, bw_out;
    get_bandwidth(bw_in, bw_out);

    // 构建JSON请求体（优化：直接字符串拼接，避免ostringstream开销）
    std::string gyd_ports_copy, geneva_ports_copy;
    { std::lock_guard<std::mutex> lock(g_gyd443_ports_mutex); gyd_ports_copy = g_gyd443_ports; }
    { std::lock_guard<std::mutex> lock(g_geneva443_ports_mutex); geneva_ports_copy = g_geneva443_ports; }
    std::string body = "{\"node_name\":\"" + heartbeat_node_name + "\"," 
                     + "\"api_key\":\"" + g_api_key + "\","
                     + "\"api_port\":" + std::to_string(g_api_port) + ","
                     + "\"cpu_usage\":" + std::to_string(cpu) + ","
                     + "\"mem_usage\":" + std::to_string(mem) + ","
                     + "\"bandwidth_in\":" + std::to_string(bw_in) + ","
                     + "\"bandwidth_out\":" + std::to_string(bw_out) + ","
                     + "\"gyd443_ports\":\"" + gyd_ports_copy + "\","
                     + "\"geneva443_ports\":\"" + geneva_ports_copy + "\","
                     + "\"geneva443_window\":" + std::to_string(g_geneva443_window.load(std::memory_order_relaxed)) + "}";

    // 构建HTTP请求（优化：直接字符串拼接）
    std::string req = "POST /api/node/heartbeat HTTP/1.1\r\n"
                      "Host: " + g_master_ip + ":" + std::to_string(g_master_port) + "\r\n"
                      "Content-Type: application/json\r\n"
                      "Content-Length: " + std::to_string(body.length()) + "\r\n"
                      "Connection: close\r\n\r\n" + body;

    // 发送请求
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cout << "[心跳] 创建socket失败" << std::endl;
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_master_port);
    inet_pton(AF_INET, g_master_ip.c_str(), &addr.sin_addr);

    struct timeval tv;
    tv.tv_sec = 3;  // 减少超时时间，避免阻塞心跳线程
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        std::string request = req;
        ssize_t sent = send(sock, request.c_str(), request.length(), 0);
        if (sent > 0) {
            // 读取响应
            char buf[1024] = {0};
            ssize_t received = recv(sock, buf, sizeof(buf) - 1, 0);
            LOG_INFO("[心跳] 发送成功: CPU=" << std::fixed << std::setprecision(1) << cpu << "%, MEM=" << mem << "%");
            if (received > 0) {
                std::string resp(buf);
                LOG_DEBUG("心跳响应: " << resp);

                // 解析心跳响应中的中间域名，自动同步主控最新配置
                if (resp.find("\"success\":true") != std::string::npos) {
                    // 提取 middle_domain
                    size_t md_pos = resp.find("\"middle_domain\":\"");
                    if (md_pos != std::string::npos) {
                        md_pos += 17; // strlen("\"middle_domain\":\"")
                        size_t md_end = resp.find("\"", md_pos);
                        if (md_end != std::string::npos) {
                            std::string new_domain = resp.substr(md_pos, md_end - md_pos);
                            if (!new_domain.empty()) {
                                std::unique_lock<std::shared_mutex> ts_lock(g_transfer_server_mutex);
                                if (new_domain != g_transfer_server) {
                                    std::cout << "[配置同步] 从主控同步中间域名: " << g_transfer_server << " -> " << new_domain << std::endl;
                                    g_transfer_server = new_domain;
                                }
                            }
                        }
                    }
                    // 提取 port
                    size_t port_pos = resp.find("\"port\":");
                    if (port_pos != std::string::npos) {
                        port_pos += 7;
                        size_t port_end = port_pos;
                        while (port_end < resp.length() && isdigit(resp[port_end])) port_end++;
                        if (port_end > port_pos) {
                            int new_port = std::stoi(resp.substr(port_pos, port_end - port_pos));
                            if (new_port > 0) {
                                std::unique_lock<std::shared_mutex> ts_lock(g_transfer_server_mutex);
                                if (new_port != g_transfer_server_port) {
                                    std::cout << "[配置同步] 从主控同步中转端口: " << g_transfer_server_port << " -> " << new_port << std::endl;
                                    g_transfer_server_port = new_port;
                                }
                            }
                        }
                    }
                    // 同步GYD443端口列表
                    size_t gp_pos = resp.find("\"gyd443_ports\":\"");
                    if (gp_pos != std::string::npos) {
                        gp_pos += 16; // strlen("\"gyd443_ports\":\"")
                        size_t gp_end = resp.find("\"", gp_pos);
                        if (gp_end != std::string::npos) {
                            std::string new_ports = resp.substr(gp_pos, gp_end - gp_pos);
                            std::string cur_ports;
                            { std::lock_guard<std::mutex> lock(g_gyd443_ports_mutex); cur_ports = g_gyd443_ports; }
                            if (new_ports != cur_ports) {
                                if (new_ports.empty()) {
                                    if (g_gyd443_running.load()) {
                                        std::cout << "[配置同步] 主控要求停止GYD443" << std::endl;
                                        stop_gyd443();
                                    }
                                } else {
                                    std::cout << "[配置同步] 主控同步GYD443端口: " << (cur_ports.empty() ? "无" : cur_ports) << " -> " << new_ports << std::endl;
                                    start_gyd443(new_ports);
                                }
                            }
                        }
                    }
                    // 同步Geneva443端口列表和窗口大小
                    size_t gv_pos = resp.find("\"geneva443_ports\":\"");
                    if (gv_pos != std::string::npos) {
                        gv_pos += 19; // strlen("\"geneva443_ports\":\"")
                        size_t gv_end = resp.find("\"", gv_pos);
                        if (gv_end != std::string::npos) {
                            std::string new_ports = resp.substr(gv_pos, gv_end - gv_pos);
                            // 同步窗口大小
                            size_t gw_pos = resp.find("\"geneva443_window\":");
                            if (gw_pos != std::string::npos) {
                                gw_pos += 19;
                                try { g_geneva443_window.store((uint16_t)std::stoi(resp.substr(gw_pos)), std::memory_order_release); } catch (...) {}
                            }
                            std::string cur_ports;
                            { std::lock_guard<std::mutex> lock(g_geneva443_ports_mutex); cur_ports = g_geneva443_ports; }
                            if (new_ports != cur_ports) {
                                if (new_ports.empty()) {
                                    if (g_geneva443_running.load()) {
                                        std::cout << "[配置同步] 主控要求停止Geneva443" << std::endl;
                                        stop_geneva443();
                                    }
                                } else {
                                    std::cout << "[配置同步] 主控同步Geneva443端口: " << (cur_ports.empty() ? "无" : cur_ports) << " -> " << new_ports << " 窗口: " << g_geneva443_window.load(std::memory_order_relaxed) << std::endl;
                                    start_geneva443(new_ports);
                                }
                            }
                        }
                    }
                    // 检测域名版本变更，触发即时同步（无需等待定时同步间隔）
                    size_t dv_pos = resp.find("\"domain_version\":");
                    if (dv_pos != std::string::npos) {
                        dv_pos += 18; // strlen("\"domain_version\":")
                        try {
                            uint64_t master_version = std::stoull(resp.substr(dv_pos));
                            uint64_t local_version = g_local_domain_version.load();
                            if (master_version > 0 && master_version > local_version) {
                                LOG_INFO("[域名同步] 检测到版本变更 (本地:" << local_version << " -> 主控:" << master_version << ")，触发即时同步");
                                if (!g_domain_sync_inflight.exchange(true, std::memory_order_acq_rel)) {
                                    enqueue_bg([]() {
                                        // 首次同步失败时重试最多2次
                                        if (!sync_domains_from_master()) {
                                            std::this_thread::sleep_for(std::chrono::milliseconds(2000));
                                            if (!sync_domains_from_master()) {
                                                std::this_thread::sleep_for(std::chrono::milliseconds(4000));
                                                sync_domains_from_master();
                                            }
                                        }
                                        g_domain_sync_inflight.store(false, std::memory_order_release);
                                    });
                                }
                            }
                        } catch (...) {}
                    }
                } else {
                    std::string msg = "未知错误";
                    size_t mpos = resp.find("\"message\":\"");
                    if (mpos != std::string::npos) {
                        mpos += 11;
                        size_t mend = resp.find('"', mpos);
                        if (mend != std::string::npos) msg = resp.substr(mpos, mend - mpos);
                    }
                    std::cout << "[心跳] 主控已响应但未接收心跳: " << msg << std::endl;
                }
            } else {
                std::cout << "[心跳] 未读取到主控响应" << std::endl;
            }
        } else {
            std::cout << "[心跳] 发送失败: errno=" << errno << std::endl;
        }
    } else {
        std::cout << "[心跳] 连接主控失败: " << g_master_ip << ":" << g_master_port << " errno=" << errno << std::endl;
    }
    close(sock);
}

// 心跳线程函数
void heartbeat_thread_func() {
    LOG_INFO("心跳线程已启动，间隔: " << g_heartbeat_interval << "秒");
    // 初始化带宽统计
    double dummy_in, dummy_out;
    get_bandwidth(dummy_in, dummy_out);
    get_cpu_usage();
    sleep(1);

    // 启动时获取一次配置
    fetch_config_from_master();

    // 启动时立即同步域名列表（关键：确保首次请求就能用本地查询）
    if (!g_master_ip.empty()) {
        LOG_INFO("[域名同步] 启动时同步域名列表...");
        try { sync_domains_from_master(); } catch (...) { LOG_WARN("[域名同步] 启动同步异常"); }
    }

    while (g_running) {
        send_heartbeat();

        // 异步获取配置，不阻塞心跳发送
        if (!g_config_fetch_inflight.exchange(true, std::memory_order_acq_rel)) {
            enqueue_bg([]() {
                fetch_config_from_master();
                g_config_fetch_inflight.store(false, std::memory_order_release);
            });
        }

        // 定期同步域名列表（按独立间隔，不依赖心跳间隔）
        if (!g_master_ip.empty()) {
            time_t now = time(nullptr);
            time_t last_sync = g_local_domains_sync_time.load();
            if (now - last_sync >= g_domain_sync_interval) {
                if (!g_domain_sync_inflight.exchange(true, std::memory_order_acq_rel)) {
                    enqueue_bg([]() {
                        // 同步失败时重试最多2次
                        if (!sync_domains_from_master()) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(500));
                            if (!sync_domains_from_master()) {
                                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                                sync_domains_from_master();
                            }
                        }
                        g_domain_sync_inflight.store(false, std::memory_order_release);
                    });
                }
            }
        }

        for (int i = 0; i < g_heartbeat_interval && g_running; i++) {
            sleep(1);
        }
    }
    LOG_INFO("心跳线程已停止");
}

void print_usage(const char* program) {
    std::cout << "域名跳转系统边缘节点 v" << VERSION << "\n"
              << "用法: " << program << " [选项]\n"
              << "\n主控连接:\n"
              << "  -s <地址>         中转服务器地址 (IP或域名)\n"
              << "  -t <端口>         中转服务器端口 (默认: 3600)\n"
              << "  --master-ip <IP>  主控服务器IP，用于同步证书和心跳\n"
              << "  --master-port <端口> 主控管理端口 (默认: 8080)\n"
              << "  --api-key <密钥>  管理API认证密钥 (默认: change_me_secret)\n"
              << "  --node-name <名称> 节点名称，用于心跳上报\n"
              << "\n监听端口:\n"
              << "  -p <端口>         HTTPS 监听端口 (默认: 443)\n"
              << "  -P <端口>         HTTP 监听端口 (默认: 80)\n"
              << "  -n                禁用 HTTP 服务\n"
              << "  --api-port <端口>  管理 API 端口 (默认: 9999)\n"
              << "\n证书:\n"
              << "  -c <文件>         默认 SSL 证书 (默认: server.crt)\n"
              << "  -k <文件>         默认 SSL 私钥 (默认: server.key)\n"
              << "  -m <文件>         多域名证书配置\n"
              << "\nACME:\n"
              << "  -a <IP>           ACME 后端 IP\n"
              << "  -A <端口>         ACME 后端端口 (默认: 80)\n"
              << "  --acme-webroot <路径> 验证目录 (默认: /var/www/acme)\n"
              << "  --acme-path <路径>    acme.sh 路径 (默认: 自动检测)\n"
              << "\n性能:\n"
              << "  --geneva-queue <N>   Geneva 队列号 (默认: 80)\n"
              << "  --geneva-window <N>  Geneva 窗口大小 (默认: 0)\n"
              << "  --no-geneva          禁用 Geneva\n"
              << "  --heartbeat <秒>     心跳间隔 (默认: 10)\n"
              << "  --sync-interval <秒> 证书同步间隔 (默认: 300)\n"
              << "  --domain-sync <秒>   域名同步间隔 (默认: 30)\n"
              << "\n运行控制:\n"
              << "  --log-level <N>      日志级别 0-4 (默认: 3)\n"
              << "  --no-daemon          前台运行（调试模式）\n"
              << "  --install-service    安装 systemd 服务\n"
              << "  --allow-auto-install 允许自动安装依赖\n"
              << "\n诊断:\n"
              << "  -v <级别>           日志级别: 0=静默 1=错误 2=警告 3=信息(默认) 4=调试\n"
              << "  --log-file <路径>    同时输出日志到文件\n"
              << "  -V, --version        显示版本信息\n"
              << "  -h, --help           显示此帮助信息\n"
              << "\n示例:\n"
              << "  # 基本用法\n"
              << "  sudo ./redirect_server_https -s mf.example.com -t 3600\n"
              << "  # 启用 ACME 转发\n"
              << "  sudo ./redirect_server_https -s mf.example.com -t 3600 -a 192.168.1.0\n"
              << "  # 启用管理 API\n"
              << "  sudo ./redirect_server_https -s mf.example.com -t 3600 --api-key YOUR_KEY\n"
              << std::endl;
}

// 安全写入 /proc/sys 内核参数（替代 system("sysctl -w ...")，无需 shell）
static void write_proc_sys(const char* proc_path, const std::string& value) {
    int fd = open(proc_path, O_WRONLY);
    if (fd >= 0) {
        if (write(fd, value.c_str(), value.size()) < 0) { /* best effort */ }
        close(fd);
    }
}

int main(int argc, char* argv[]) {
    g_server_start_time = time(nullptr);

    // ══════════════════════════════════════════════════════════════
    // 授权验证（最先检查）
    // ══════════════════════════════════════════════════════════════
    if (!verify_license()) {
        return 1;
    }
    // ══════════════════════════════════════════════════════════════
    
    // 保存命令行参数
    g_saved_argc = argc;
    g_saved_argv = argv;

    // 检查是否需要安装服务
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--install-service") == 0) {
            g_need_install_service = true;
            break;
        }
    }

    // 解析 --workers 参数（需要提前解析，以便在main开头决定是否spawn）
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) {
            g_num_workers = std::stoi(argv[++i]);
            if (g_num_workers < 1) g_num_workers = 1;
        }
    }

    // 多进程模式：Master fork workers，自身进入supervision loop
    // 注意：g_num_workers=0表示自动检测CPU核心数；--workers N可覆盖此行为
    if (!spawn_workers(argc, argv)) {
        // 如果返回false表示：
        //   1. g_num_workers <= 1（单进程模式），继续单进程执行
        //   2. fork失败，返回值未定义（此处直接继续）
    }

    // 解析命令行参数（worker和单进程模式都走这里）
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "-i") == 0) && i + 1 < argc) {
            g_transfer_server = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            g_transfer_server_port = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            g_listen_port_https = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "-P") == 0 && i + 1 < argc) {
            g_listen_port_http = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "-n") == 0) {
            g_enable_http = false;
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            g_cert_file = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            g_key_file = argv[++i];
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            g_cert_config = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            g_acme_backend = argv[++i];
        } else if (strcmp(argv[i], "-A") == 0 && i + 1 < argc) {
            g_acme_backend_port = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--api-port") == 0 && i + 1 < argc) {
            g_api_port = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--api-key") == 0 && i + 1 < argc) {
            g_api_key = argv[++i];
        } else if (strcmp(argv[i], "--acme-webroot") == 0 && i + 1 < argc) {
            g_acme_webroot = argv[++i];
        } else if (strcmp(argv[i], "--acme-path") == 0 && i + 1 < argc) {
            g_acme_path = argv[++i];
        } else if (strcmp(argv[i], "--geneva-queue") == 0 && i + 1 < argc) {
            g_geneva_queue = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--geneva-window") == 0 && i + 1 < argc) {
            g_geneva_window = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--no-geneva") == 0) {
            g_geneva_enabled = false;
        } else if (strcmp(argv[i], "--master-ip") == 0 && i + 1 < argc) {
            g_master_ip = argv[++i];
        } else if (strcmp(argv[i], "--master-port") == 0 && i + 1 < argc) {
            g_master_port = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--sync-interval") == 0 && i + 1 < argc) {
            g_sync_interval = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--node-name") == 0 && i + 1 < argc) {
            g_node_name = argv[++i];
        } else if (strcmp(argv[i], "--domain-sync") == 0 && i + 1 < argc) {
            g_domain_sync_interval = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--heartbeat") == 0 && i + 1 < argc) {
            g_heartbeat_interval = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--log-level") == 0 && i + 1 < argc) {
            g_log_level = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--daemon") == 0) {
            g_auto_daemonize = true;
        } else if (strcmp(argv[i], "--no-daemon") == 0) {
            g_auto_daemonize = false;
        } else if (strcmp(argv[i], "--install-service") == 0) {
            // 已在main函数开头处理，这里跳过
            continue;
        } else if (strcmp(argv[i], "--allow-auto-install") == 0) {
            g_allow_auto_install = true;
        } else if (strcmp(argv[i], "-v") == 0 && i + 1 < argc) {
            g_log_level = std::stoi(argv[++i]);
            if (g_log_level < 0) g_log_level = 0;
            if (g_log_level > 4) g_log_level = 4;
        } else if (strcmp(argv[i], "--log-file") == 0 && i + 1 < argc) {
            g_log_file = argv[++i];
        } else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
            std::cout << "域名跳转系统边缘节点 v" << VERSION << "\n";
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    // 初始化日志文件
    if (!g_log_file.empty()) {
        log_open_file();
    }

    // 环境检测和依赖安装（默认关闭自动安装，需显式 --allow-auto-install）
    check_and_install_dependencies();

    // 初始化随机数种子（用于盲发HTML子域名生成、Geneva混淆等场景）
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        srand(ts.tv_nsec ^ (getpid() * 131531) ^ (time(nullptr) * 9973));
    }

    // 自动安装/更新 systemd 服务（仅在非 --no-daemon 模式下）
    if (g_need_install_service && g_auto_daemonize) {
        if (create_systemd_service(argc, argv)) {
            // 服务安装并启动成功，当前进程退出，由 systemd 管理
            std::cout << "[系统] 服务已由 systemd 接管，当前进程退出" << std::endl;
            return 0;
        } else {
            std::cerr << "[系统] 服务安装失败，继续以前台模式运行" << std::endl;
        }
    }

    // 自动后台化（仅在 main 早期单线程阶段执行，避免多线程 fork 风险）
    if (g_auto_daemonize && g_is_master && !g_daemonized) {
        if (!daemonize()) {
            std::cerr << "[系统] 后台化失败，继续以前台模式运行" << std::endl;
        }
        // daemonize() 会将 SIGHUP 设为 SIG_IGN，需要恢复为 reload_handler
        signal(SIGHUP, reload_handler);
    }

    // 如果没有指定中转服务器地址，自动获取本机IP
    if (g_transfer_server.empty()) {
        g_transfer_server = get_local_ip();
        std::cout << "自动检测本机IP: " << g_transfer_server << std::endl;
        std::cout << "提示: 请用 -s 参数指定中转服务器域名或外网IP" << std::endl;
    } else {
        std::cout << "中转服务器: " << g_transfer_server << ":" << g_transfer_server_port << std::endl;
    }

    // 注册信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);  // 忽略SIGPIPE，防止写入关闭的socket导致程序退出
    signal(SIGUSR1, [](int){  // 用于打印连接统计
        std::cout << "[统计] accepted=" << g_conn_accepted.load()
                  << " handled=" << g_conn_handled.load()
                  << " failed=" << g_conn_failed.load()
                  << " diff=" << (g_conn_accepted.load() - g_conn_handled.load() - g_conn_failed.load())
                  << std::endl;
    });

    // 确保ACME目录存在并设置权限
    std::string acme_challenge_dir = g_acme_webroot + "/.well-known/acme-challenge";
    safe_mkdir_p(acme_challenge_dir);
    chmod(g_acme_webroot.c_str(), 0755);
    chmod((g_acme_webroot + "/.well-known").c_str(), 0755);
    chmod(acme_challenge_dir.c_str(), 0755);

    // 提升文件描述符限制（生产环境高并发必需）
    {
        struct rlimit rl;
        getrlimit(RLIMIT_NOFILE, &rl);
        rlim_t target = 65536;
        if (rl.rlim_cur < target) {
            rl.rlim_cur = target;
            if (rl.rlim_max < target) rl.rlim_max = target;
            if (setrlimit(RLIMIT_NOFILE, &rl) == 0) {
                std::cout << "[系统] 文件描述符限制已提升到 " << target << std::endl;
            } else {
                std::cout << "[警告] 无法提升文件描述符限制 (当前: " << rl.rlim_cur << ")，建议用root运行" << std::endl;
            }
        }
    }

    // 自动优化内核网络参数（减少高并发下的 connect 错误）
    if (getuid() == 0) {  // 需要root权限
        std::cout << "[系统] 正在优化内核网络参数..." << std::endl;
        // 提升半连接队列和全连接队列上限
        write_proc_sys("/proc/sys/net/core/somaxconn", "65535");
        write_proc_sys("/proc/sys/net/ipv4/tcp_max_syn_backlog", "65535");
        // 扩大端口范围，减少客户端连接时的本地端口耗尽
        write_proc_sys("/proc/sys/net/ipv4/ip_local_port_range", "1024\t65535");
        // 启用TIME_WAIT快速回收（仅用于客户端连接测试场景）
        write_proc_sys("/proc/sys/net/ipv4/tcp_tw_reuse", "1");
        // 减少FIN_WAIT超时
        write_proc_sys("/proc/sys/net/ipv4/tcp_fin_timeout", "10");
        // 增加最大孤儿socket数量
        write_proc_sys("/proc/sys/net/ipv4/tcp_max_orphans", "65535");
        std::cout << "[系统] 内核网络参数已优化（可能需要重启生效）" << std::endl;
    } else {
        std::cout << "[系统] 非root运行，跳过内核参数优化（建议用root运行以获得更好性能）" << std::endl;
        std::cout << "[提示] 可手动执行: sysctl -w net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535" << std::endl;
    }

    // 初始化线程池
    unsigned int hw = std::thread::hardware_concurrency();
    if (hw == 0) hw = 4;
    // 根据CPU核心数自动调整线程池大小：核心数*128，上限2048，下限256
    // 盲发模式连接短，线程周转快，核心数*128是合理起始值
    unsigned int conn_threads = std::min(1024u, std::max(128u, hw * 16));
    std::cout << "[系统] 线程池大小: " << conn_threads << " (核心数: " << hw << ")" << std::endl;
    unsigned int bg_threads = std::max(4u, hw / 2);
    g_conn_pool = std::make_unique<ThreadPool>(conn_threads, 262144);
    g_bg_pool = std::make_unique<ThreadPool>(bg_threads, 4096);

    // 初始化 epoll worker 线程池（SO_REUSEPORT：每个worker持有独立listen socket）
    unsigned int worker_count = std::max(2u, hw);
    std::cout << "[系统] Epoll worker数量: " << worker_count << " (SO_REUSEPORT模式，无accept线程)" << std::endl;
    g_epoll_workers.reserve(worker_count);
    for (unsigned int i = 0; i < worker_count; ++i) {
        g_epoll_workers.emplace_back(std::make_unique<EpollWorker>(i, g_listen_port_https, 65536));
    }
    // 注册所有worker的listen fd（用于shutdown），然后启动worker线程
    {
        std::lock_guard<std::mutex> lock(g_listen_fds_mutex);
        for (auto& w : g_epoll_workers) {
            if (w->listen_fd() >= 0) {
                g_listen_fds.push_back(w->listen_fd());
            }
            w->start();
        }
    }
    std::cout << "[系统] Epoll workers已启动: " << worker_count << " 个\n";

    // 启动限速清理线程（不再在请求路径上持锁清理）
    std::thread ratelimit_cleanup_thread([]() {
        while (g_running.load()) {
            cleanup_ip_rate_entries();
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    });
    ratelimit_cleanup_thread.detach();
    std::cout << "[系统] 限速清理线程已启动\n";

    // 初始化SSL
    if (!init_ssl()) {
        std::cerr << "SSL初始化失败" << std::endl;
        return 1;
    }

    // 初始化主控SSL连接池
    g_master_ssl_pool = new MasterSSLPool(64, 30);  // 最多64个连接，空闲30秒

    // 证书同步（如果配置了主控）
    if (!g_master_ip.empty()) {
        // 从主控同步所有证书（证书统一存放在主控，节点只需下载）
        sync_certs_from_master();

        // 注意：不再需要定时同步，主控在证书变化时会主动推送到节点
    }

    // 启动 Geneva (TCP窗口修改) 线程
    if (g_geneva_enabled) {
        g_geneva_thread = std::thread(geneva_thread_func);
    }

    // 启动HTTP服务线程（如果启用）
    std::thread http_thread;
    if (g_enable_http) {
        http_thread = std::thread(http_server_thread);
    }

    // 启动ACME专用端口服务线程（8080端口，不走Geneva）
    std::thread acme_thread(acme_server_thread);

    // 启动管理API服务线程
    std::thread api_thread(api_server_thread);

    // 启动心跳上报线程（只要配置了主控就启动；节点名为空时自动兜底）
    if (!g_master_ip.empty()) {
        if (g_node_name.empty()) {
            g_node_name = get_local_ip();
            if (g_node_name.empty()) g_node_name = "node-unknown";
            std::cout << "[心跳] 节点名称为空，已自动使用: " << g_node_name << std::endl;
        }
        std::cout << "[心跳] 启动心跳线程: 主控=" << g_master_ip << ":" << g_master_port << " 节点=" << g_node_name << std::endl;
        g_heartbeat_thread = std::thread(heartbeat_thread_func);
    } else {
        std::cout << "[心跳] 未启动心跳线程: master_ip=" << (g_master_ip.empty() ? "空" : g_master_ip) << " node_name=" << (g_node_name.empty() ? "空" : g_node_name) << std::endl;
        // 即使没有心跳线程，也尝试同步域名列表（只要配置了主控IP）
        if (!g_master_ip.empty()) {
            std::cout << "[域名同步] 无心跳线程，独立同步域名列表..." << std::endl;
            sync_domains_from_master();
        }
    }

    // HTTPS监听由各EpollWorker独立管理（SO_REUSEPORT内核分发），无需单独accept线程

    // API Key安全检查
    if (g_api_key == "your_secret_key") {
        // 自动生成随机API Key
        std::string new_key;
        new_key.reserve(32);
        std::ifstream urandom("/dev/urandom", std::ios::binary);
        if (urandom.is_open()) {
            unsigned char buf[32];
            urandom.read(reinterpret_cast<char*>(buf), sizeof(buf));
            static const char chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            for (int i = 0; i < 32; i++) new_key += chars[buf[i] % (sizeof(chars) - 1)];
            urandom.close();
        } else {
            // /dev/urandom失败时的备选：使用clock_gettime+getpid+gettid组合种子
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            srand(ts.tv_nsec ^ (getpid() * 131531) ^ (gettid() * 1315313));
            static const char chars[] = "0123456789abcdefghijklmnopqrstuvwxyz";
            for (int i = 0; i < 32; i++) new_key += chars[rand() % (sizeof(chars) - 1)];
        }
        g_api_key = new_key;
        std::cerr << "╔══════════════════════════════════════════════════╗" << std::endl;
        std::cerr << "║  ⚠️  安全警告: 检测到使用默认API Key!            ║" << std::endl;
        std::cerr << "║  已自动生成随机Key: " << g_api_key << "  ║" << std::endl;
        std::cerr << "║  建议通过 --api-key 参数指定自定义Key            ║" << std::endl;
        std::cerr << "╚══════════════════════════════════════════════════╝" << std::endl;
    }

    std::cout << "========================================" << std::endl;
    if (!g_is_master) {
        std::cout << "Worker进程 PID=" << getpid() << std::endl;
    }
    std::cout << "重定向服务器已启动 [盲发模式]" << std::endl;
    std::cout << "HTTPS端口: " << g_listen_port_https << std::endl;
    if (g_enable_http) {
        std::cout << "HTTP端口: " << g_listen_port_http << std::endl;
    }
    std::cout << "管理API端口: " << g_api_port << std::endl;
    std::cout << "中转服务器: https://" << g_transfer_server << ":" << g_transfer_server_port << std::endl;
    if (!g_acme_backend.empty()) {
        std::cout << "ACME转发: " << g_acme_backend << ":" << g_acme_backend_port << std::endl;
    }
    if (g_geneva_enabled) {
        std::cout << "Geneva: 队列=" << g_geneva_queue << ", 窗口=" << g_geneva_window << std::endl;
    }
    std::cout << "GYD443: 关闭（等待主控指令同步端口）" << std::endl;
    if (!g_master_ip.empty()) {
        size_t domain_count = 0;
        {
            std::shared_lock<std::shared_mutex> lock(g_local_domains_mutex);
            domain_count = g_local_domains.size();
        }
        std::cout << "域名同步: 间隔=" << g_domain_sync_interval << "秒, 心跳版本检测已启用" << (g_local_domains_loaded.load() ? " (已加载" + std::to_string(domain_count) + "个域名, 版本:" + std::to_string(g_local_domain_version.load()) + ")" : " (等待首次同步)") << std::endl;
    }
    std::cout << "========================================" << std::endl;

    // 主线程等待关闭信号，不再自己 accept（已由多线程处理）
    while (g_running) {
        // 处理 SIGHUP 配置重载请求
        if (g_reload_requested.exchange(false, std::memory_order_acq_rel)) {
            do_config_reload();
        }
        // Worker进程：检测master的reload标志
        if (!g_is_master) poll_reload_flag();
        // Worker进程：检测退出信号，避免1秒延迟
        if (!g_is_master && g_worker_exit_requested.load(std::memory_order_acquire)) {
            g_running = false;
        }
        sleep(1);
    }

    // 先shutdown所有accept socket以中断阻塞的accept()
    {
        std::lock_guard<std::mutex> lock(g_listen_fds_mutex);
        for (int lfd : g_listen_fds) {
            if (lfd >= 0) shutdown(lfd, SHUT_RDWR);
        }
    }
    // 等待所有accept线程退出
    // (已移除多accept线程，现在只有一个https_accept_thread是detached的)

    // 停止 Geneva（stop_geneva内部会等待线程结束）
    stop_geneva();

    // 停止 GYD443
    stop_gyd443();

    // 停止 Geneva443
    stop_geneva443();

    // 等待证书同步线程结束
    if (g_sync_thread.joinable()) {
        g_sync_thread.join();
    }

    // 等待HTTP线程结束
    if (g_enable_http && http_thread.joinable()) {
        http_thread.join();
    }

    // 等待API线程结束
    if (api_thread.joinable()) {
        api_thread.join();
    }

    // 等待ACME线程结束
    if (acme_thread.joinable()) {
        acme_thread.join();
    }

    // 等待心跳线程结束
    if (g_heartbeat_thread.joinable()) {
        g_heartbeat_thread.join();
    }

    // 停止 epoll workers
    for (auto& w : g_epoll_workers) {
        w->stop();
    }
    g_epoll_workers.clear();

    // 销毁线程池（等待所有任务完成）
    g_conn_pool.reset();
    g_bg_pool.reset();

    // 清理主控SSL连接池
    if (g_master_ssl_pool) {
        delete g_master_ssl_pool;
        g_master_ssl_pool = nullptr;
    }

    if (g_server_socket_https >= 0) {
        close(g_server_socket_https);
    }
    if (g_server_socket_http >= 0) {
        close(g_server_socket_http);
    }
    if (g_server_socket_api >= 0) {
        close(g_server_socket_api);
    }

    if (g_ssl_ctx) {
        SSL_CTX_free(g_ssl_ctx);
    }

    // 释放所有域名SSL上下文
    {
        std::unique_lock<std::shared_mutex> lock(g_domain_ssl_ctx_mutex);
        for (auto& pair : g_domain_ssl_ctx) {
            if (pair.second) SSL_CTX_free(pair.second);
        }
        g_domain_ssl_ctx.clear();
    }

    std::cout << "服务器已关闭" << std::endl;
    return 0;
}
