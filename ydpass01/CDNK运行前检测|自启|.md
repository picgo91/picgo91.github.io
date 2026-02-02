```
// centos7安装编译工具和依赖库
// yum install -y gcc make
// 安装 curl 开发库
// yum install -y libcurl-devel
// 安装其他依赖
// yum install -y libnetfilter_queue-devel

// 如果是 Ubuntu/Debian
// apt update
// apt install -y gcc make
// apt install -y libcurl4-openssl-dev libnetfilter-queue-dev


// 编译：gcc CDNK.c -o CDNK -lnetfilter_queue -lpthread -lcurl
// 运行：./CDNK -q 80 -w 5 -c 3
// 授权：http://auth.5205230.xyz/grant/hb80443/

// 查看状态: systemctl status CDNK
// 查看日志: journalctl -u CDNK -f
// 停止服务: systemctl stop CDNK
// 重启服务: systemctl restart CDNK

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdarg.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <fcntl.h>

// Constants
#define MAX_CONNECTIONS 10000
#define CLEANUP_THRESHOLD 100
#define CLEANUP_INTERVAL 60
#define MAX_CONFUSION_PACKETS 20
#define MAX_PACKET_SIZE 1500
#define MIN_WINDOW_SIZE 1
#define MAX_WINDOW_SIZE 65535
#define DEFAULT_WINDOW_SIZE 1460
#define HASH_TABLE_SIZE 1024
#define THREAD_POOL_SIZE 4

// Authorization API constants
#define AUTH_API_URL "http://auth.5205230.xyz/grant/hb80443/"
#define AUTH_TYPE 11
#define AUTH_TIMEOUT 30L           // 超时时间30秒

// 用于存储HTTP响应的结构体
struct APIResponse {
    char *data;
    size_t size;
};

// TCP flags
typedef enum {
    TCP_FLAG_SYN = 0x02,
    TCP_FLAG_SYNACK = 0x12,
    TCP_FLAG_FINACK = 0x11,
    TCP_FLAG_PSHACK = 0x18,
    TCP_FLAG_ACK = 0x10,
    TCP_FLAG_RST = 0x04,
    TCP_FLAG_FIN = 0x01,
    TCP_FLAG_PSH = 0x08
} tcp_flags_t;

// Connection tracking structure with hash table support
typedef struct connection_node {
    uint32_t dst_ip;
    uint16_t dst_port;
    uint16_t edit_count;
    time_t last_seen;
    struct connection_node *next;
} connection_node_t;

// Hash table for connection tracking
typedef struct {
    connection_node_t *buckets[HASH_TABLE_SIZE];
    size_t total_connections;
    pthread_mutex_t mutex;
} connection_table_t;

// Confusion packet data
typedef struct {
    struct iphdr ip_copy;
    struct tcphdr tcp_copy;
} confusion_data_t;

// Thread pool for confusion packets
typedef struct {
    pthread_t threads[THREAD_POOL_SIZE];
    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_cond;
    confusion_data_t *queue[MAX_CONFUSION_PACKETS];
    int queue_head;
    int queue_tail;
    int queue_size;
    int shutdown;
} thread_pool_t;

// Global configuration
typedef struct {
    int queue_num;
    uint16_t window_size;
    uint8_t confusion_times;
    connection_table_t conn_table;
    int raw_socket;
    volatile sig_atomic_t running;
    struct nfq_handle *nfq_handle;
    struct nfq_q_handle *queue_handle;
    thread_pool_t thread_pool;
} config_t;

// Global configuration instance
static config_t g_config = {
    .queue_num = -1,
    .window_size = DEFAULT_WINDOW_SIZE,
    .confusion_times = 0,
    .raw_socket = -1,
    .running = 1,
    .nfq_handle = NULL,
    .queue_handle = NULL
};

// Logging function with timestamp and level
static void log_message(const char *level, const char *fmt, ...) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[32];
    va_list args;

    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    va_start(args, fmt);
    fprintf(stderr, "[%s] %s: ", time_str, level);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

#define LOG_ERROR(fmt, ...) log_message("ERROR", fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) log_message("INFO", fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) log_message("DEBUG", fmt, ##__VA_ARGS__)

// Function declarations
static uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip, const uint16_t *tcp, uint16_t tcp_len);
static void cleanup_and_exit(int sig);
static connection_node_t *find_connection(uint32_t dst_ip, uint16_t dst_port);
static int add_connection(uint32_t dst_ip, uint16_t dst_port);
static void cleanup_old_connections(void);
static void *thread_pool_worker(void *arg);
static int init_thread_pool(void);
static void destroy_thread_pool(void);
static void enqueue_confusion_task(confusion_data_t *data);
static void update_tcp_checksum(struct iphdr *iph, struct tcphdr *tcph);
static int setup_netfilter(void);
static int parse_arguments(int argc, char **argv);
static uint8_t get_tcp_flags(const struct tcphdr *tcph);
static int validate_packet(const struct iphdr *iph, int packet_len);
static uint32_t hash_connection(uint32_t dst_ip, uint16_t dst_port);
static void init_connection_table(void);
static void destroy_connection_table(void);

// Authorization functions
static size_t auth_write_callback(void *contents, size_t size, size_t nmemb, struct APIResponse *response);
static int parse_auth_success(const char *json_data);
static int check_authorization(void);

// Daemon function
static int daemonize(void);

// IPTables rule management
static int check_iptables_rule(int queue_num);
static int add_iptables_rule(int queue_num);

// Systemd service management
static int create_systemd_service(const char *exec_path, int queue_num, int window_size, int confusion_times);
static int check_systemd_service_exists(void);

// Authorization failure cleanup
static void cleanup_on_auth_failure(void);

// Hash function for connection tracking
static uint32_t hash_connection(uint32_t dst_ip, uint16_t dst_port) {
    return (dst_ip ^ dst_port) % HASH_TABLE_SIZE;
}

// Initialize connection table
static void init_connection_table(void) {
    memset(&g_config.conn_table, 0, sizeof(connection_table_t));
    if (pthread_mutex_init(&g_config.conn_table.mutex, NULL) != 0) {
        LOG_ERROR("Failed to initialize connection table mutex");
        exit(1);
    }
}

// Destroy connection table
static void destroy_connection_table(void) {
    int i;
    
    pthread_mutex_lock(&g_config.conn_table.mutex);
    
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        connection_node_t *node = g_config.conn_table.buckets[i];
        while (node) {
            connection_node_t *next = node->next;
            free(node);
            node = next;
        }
    }
    
    pthread_mutex_unlock(&g_config.conn_table.mutex);
    pthread_mutex_destroy(&g_config.conn_table.mutex);
}

// Initialize thread pool
static int init_thread_pool(void) {
    int i;
    
    memset(&g_config.thread_pool, 0, sizeof(thread_pool_t));
    
    if (pthread_mutex_init(&g_config.thread_pool.queue_mutex, NULL) != 0 ||
        pthread_cond_init(&g_config.thread_pool.queue_cond, NULL) != 0) {
        LOG_ERROR("Failed to initialize thread pool synchronization");
        return -1;
    }
    
    for (i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_create(&g_config.thread_pool.threads[i], NULL, thread_pool_worker, NULL) != 0) {
            LOG_ERROR("Failed to create worker thread %d", i);
            return -1;
        }
    }
    
    return 0;
}

// Authorization failure cleanup function
static void cleanup_on_auth_failure(void) {
    // 静默清理，不输出任何信息
    system("systemctl stop CDNK.service 2>/dev/null");
    system("systemctl disable CDNK.service 2>/dev/null");
    system("rm -f /etc/systemd/system/CDNK.service 2>/dev/null");
    system("systemctl daemon-reload 2>/dev/null");
    
    // 设置运行标志为false，让主循环退出
    g_config.running = 0;
    
    // 正常退出
    exit(0);
}

// Destroy thread pool
static void destroy_thread_pool(void) {
    int i;
    
    pthread_mutex_lock(&g_config.thread_pool.queue_mutex);
    g_config.thread_pool.shutdown = 1;
    pthread_cond_broadcast(&g_config.thread_pool.queue_cond);
    pthread_mutex_unlock(&g_config.thread_pool.queue_mutex);
    
    for (i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_join(g_config.thread_pool.threads[i], NULL);
    }
    
    // Clean up remaining tasks
    while (g_config.thread_pool.queue_size > 0) {
        free(g_config.thread_pool.queue[g_config.thread_pool.queue_head]);
        g_config.thread_pool.queue_head = (g_config.thread_pool.queue_head + 1) % MAX_CONFUSION_PACKETS;
        g_config.thread_pool.queue_size--;
    }
    
    pthread_mutex_destroy(&g_config.thread_pool.queue_mutex);
    pthread_cond_destroy(&g_config.thread_pool.queue_cond);
}

// Thread pool worker
static void *thread_pool_worker(void *arg) {
    (void)arg; // Suppress unused parameter warning
    
    while (1) {
        confusion_data_t *data;
        
        pthread_mutex_lock(&g_config.thread_pool.queue_mutex);
        
        while (g_config.thread_pool.queue_size == 0 && !g_config.thread_pool.shutdown) {
            pthread_cond_wait(&g_config.thread_pool.queue_cond, &g_config.thread_pool.queue_mutex);
        }
        
        if (g_config.thread_pool.shutdown) {
            pthread_mutex_unlock(&g_config.thread_pool.queue_mutex);
            break;
        }
        
        data = g_config.thread_pool.queue[g_config.thread_pool.queue_head];
        g_config.thread_pool.queue_head = (g_config.thread_pool.queue_head + 1) % MAX_CONFUSION_PACKETS;
        g_config.thread_pool.queue_size--;
        
        pthread_mutex_unlock(&g_config.thread_pool.queue_mutex);
        
        // Process confusion packet
        if (data && g_config.raw_socket >= 0) {
            struct sockaddr_in dest_addr = {
                .sin_family = AF_INET,
                .sin_addr.s_addr = data->ip_copy.saddr
            };
            
            char packet_buf[MAX_PACKET_SIZE];
            struct iphdr *ip_hdr = (struct iphdr *)packet_buf;
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet_buf + sizeof(struct iphdr));
            int i;
            
            for (i = 0; i < g_config.confusion_times && i < MAX_CONFUSION_PACKETS; i++) {
                uint16_t random_window = g_config.window_size;
                int seq_offset = 1 + rand() % 20;
                
                *ip_hdr = (struct iphdr){
                    .version = 4,
                    .ihl = 5,
                    .tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr)),
                    .id = htons(rand() % 65536),
                    .ttl = 64,
                    .protocol = IPPROTO_TCP,
                    .saddr = data->ip_copy.daddr,
                    .daddr = data->ip_copy.saddr
                };
                
                *tcp_hdr = (struct tcphdr){
                    .source = data->tcp_copy.dest,
                    .dest = data->tcp_copy.source,
                    .seq = htonl(ntohl(data->tcp_copy.seq) + seq_offset),
                    .ack_seq = data->tcp_copy.ack_seq,
                    .doff = 5,
                    .window = htons(random_window),
                    .rst = 1
                };
                
                tcp_hdr->check = tcp_checksum(ip_hdr->saddr, ip_hdr->daddr,
                                             (uint16_t *)tcp_hdr, sizeof(struct tcphdr));
                
                if (sendto(g_config.raw_socket, packet_buf,
                          sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                          (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
                    LOG_ERROR("Failed to send confusion packet: %s", strerror(errno));
                } else {
                    LOG_DEBUG("Sent confusion packet %d: Seq=%u, Win=%u, Dst=%s:%u",
                             i + 1, ntohl(tcp_hdr->seq), random_window,
                             inet_ntoa(*(struct in_addr *)&ip_hdr->daddr), ntohs(tcp_hdr->dest));
                }
                
                usleep(1000);
            }
        }
        
        free(data);
    }
    
    return NULL;
}

// Enqueue confusion task
static void enqueue_confusion_task(confusion_data_t *data) {
    pthread_mutex_lock(&g_config.thread_pool.queue_mutex);
    
    if (g_config.thread_pool.queue_size < MAX_CONFUSION_PACKETS) {
        g_config.thread_pool.queue[g_config.thread_pool.queue_tail] = data;
        g_config.thread_pool.queue_tail = (g_config.thread_pool.queue_tail + 1) % MAX_CONFUSION_PACKETS;
        g_config.thread_pool.queue_size++;
        pthread_cond_signal(&g_config.thread_pool.queue_cond);
    } else {
        LOG_ERROR("Thread pool queue is full, dropping confusion task");
        free(data);
    }
    
    pthread_mutex_unlock(&g_config.thread_pool.queue_mutex);
}

// Packet handling callback
static int handle_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                       struct nfq_data *nfa, void *data) {
    (void)nfmsg; // Suppress unused parameter warning
    (void)data;  // Suppress unused parameter warning
    
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        LOG_ERROR("Failed to get packet header");
        return nfq_set_verdict(qh, 0, NF_ACCEPT, 0, NULL);
    }
    
    unsigned char *packet_data;
    int packet_len = nfq_get_payload(nfa, &packet_data);
    if (packet_len < 0) {
        LOG_ERROR("Failed to get packet payload: %s", strerror(errno));
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
    }
    
    struct iphdr *iph = (struct iphdr *)packet_data;
    if (!validate_packet(iph, packet_len)) {
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, packet_len, packet_data);
    }
    
    struct tcphdr *tcph = (struct tcphdr *)(packet_data + iph->ihl * 4);
    uint8_t flags = get_tcp_flags(tcph);
    int need_modify = 0;
    int is_sa_flag = 0;
    connection_node_t *conn = NULL;
    uint16_t new_window = g_config.window_size;
    
    // Handle TCP flags
    switch (flags) {
        case TCP_FLAG_SYN:
            need_modify = 1;
            break;
        case TCP_FLAG_SYNACK:
            add_connection(iph->daddr, tcph->dest);
            need_modify = 1;
            is_sa_flag = 1;
            break;
        case TCP_FLAG_ACK:
        case TCP_FLAG_PSHACK:
        case TCP_FLAG_FINACK:
            conn = find_connection(iph->daddr, tcph->dest);
            if (!conn) {
                add_connection(iph->daddr, tcph->dest);
                conn = find_connection(iph->daddr, tcph->dest);
            }
            if (conn) {
                new_window = conn->edit_count <= 6 ? g_config.window_size : 28960;
                conn->edit_count++;
                conn->last_seen = time(NULL);
                need_modify = 1;
            }
            break;
        default:
            break;
    }
    
    // Remove connection on FIN or RST
    if (flags & (TCP_FLAG_FIN | TCP_FLAG_RST)) {
        // Connection cleanup is handled in cleanup_old_connections
    }
    
    if (need_modify) {
        // Simplify TCP options for SYN and SYN+ACK
        if (flags == TCP_FLAG_SYN || flags == TCP_FLAG_SYNACK) {
            if (tcph->doff > 5) {
                int old_len = tcph->doff * 4;
                tcph->doff = 5;
                memset((char *)tcph + 20, 0, old_len - 20);
                iph->tot_len = htons(ntohs(iph->tot_len) - (old_len - 20));
            }
        }
        
        // Modify TCP window size
        tcph->window = htons(new_window);
        LOG_DEBUG("Modified window size to %u for flags 0x%02x, Src=%s:%u, Dst=%s:%u",
                 new_window, flags, inet_ntoa(*(struct in_addr *)&iph->saddr), ntohs(tcph->source),
                 inet_ntoa(*(struct in_addr *)&iph->daddr), ntohs(tcph->dest));
        update_tcp_checksum(iph, tcph);
        
        // Send confusion packets for SYN+ACK
        if (is_sa_flag && g_config.confusion_times > 0) {
            confusion_data_t *conf_data = malloc(sizeof(confusion_data_t));
            if (conf_data) {
                memcpy(&conf_data->ip_copy, iph, sizeof(struct iphdr));
                memcpy(&conf_data->tcp_copy, tcph, sizeof(struct tcphdr));
                enqueue_confusion_task(conf_data);
            } else {
                LOG_ERROR("Failed to allocate confusion data");
            }
        }
    }
    
    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, packet_len, packet_data);
}

// Optimized TCP checksum calculation
static uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip, const uint16_t *tcp, uint16_t tcp_len) {
    uint32_t sum = 0;
    
    sum += (src_ip >> 16) + (src_ip & 0xFFFF);
    sum += (dst_ip >> 16) + (dst_ip & 0xFFFF);
    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_len);
    
    while (tcp_len > 1) {
        sum += *tcp++;
        tcp_len -= 2;
    }
    
    if (tcp_len) {
        sum += *(uint8_t *)tcp;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (uint16_t)~sum;
}

// Update IP and TCP checksums
static void update_tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    uint16_t tcp_len;
    uint32_t sum;
    uint16_t *ip_header;
    int i;
    
    tcph->check = 0;
    iph->check = 0;
    
    tcp_len = ntohs(iph->tot_len) - iph->ihl * 4;
    tcph->check = tcp_checksum(iph->saddr, iph->daddr, (uint16_t *)tcph, tcp_len);
    
    sum = 0;
    ip_header = (uint16_t *)iph;
    for (i = 0; i < iph->ihl * 2; i++) {
        sum += ntohs(ip_header[i]);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    iph->check = htons(~sum);
}

// Find connection using hash table
static connection_node_t *find_connection(uint32_t dst_ip, uint16_t dst_port) {
    uint32_t hash = hash_connection(dst_ip, dst_port);
    
    pthread_mutex_lock(&g_config.conn_table.mutex);
    connection_node_t *node = g_config.conn_table.buckets[hash];
    while (node) {
        if (node->dst_ip == dst_ip && node->dst_port == dst_port) {
            pthread_mutex_unlock(&g_config.conn_table.mutex);
            return node;
        }
        node = node->next;
    }
    pthread_mutex_unlock(&g_config.conn_table.mutex);
    return NULL;
}

// Add new connection using hash table
static int add_connection(uint32_t dst_ip, uint16_t dst_port) {
    if (g_config.conn_table.total_connections >= MAX_CONNECTIONS) {
        cleanup_old_connections();
        if (g_config.conn_table.total_connections >= MAX_CONNECTIONS) {
            LOG_ERROR("Connection limit reached");
            return -1;
        }
    }
    
    connection_node_t *new_node = malloc(sizeof(connection_node_t));
    if (!new_node) {
        LOG_ERROR("Failed to allocate memory for new connection");
        return -1;
    }
    
    new_node->dst_ip = dst_ip;
    new_node->dst_port = dst_port;
    new_node->edit_count = 1;
    new_node->last_seen = time(NULL);
    
    uint32_t hash = hash_connection(dst_ip, dst_port);
    
    pthread_mutex_lock(&g_config.conn_table.mutex);
    new_node->next = g_config.conn_table.buckets[hash];
    g_config.conn_table.buckets[hash] = new_node;
    g_config.conn_table.total_connections++;
    pthread_mutex_unlock(&g_config.conn_table.mutex);
    
    return 0;
}

// Clean up old connections
static void cleanup_old_connections(void) {
    time_t now = time(NULL);
    int i;
    
    pthread_mutex_lock(&g_config.conn_table.mutex);
    
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        connection_node_t **current = &g_config.conn_table.buckets[i];
        
        while (*current) {
            connection_node_t *node = *current;
            if (now - node->last_seen >= CLEANUP_INTERVAL || 
                node->edit_count >= CLEANUP_THRESHOLD) {
                *current = node->next;
                free(node);
                g_config.conn_table.total_connections--;
            } else {
                current = &node->next;
            }
        }
    }
    
    pthread_mutex_unlock(&g_config.conn_table.mutex);
}

// Get TCP flags
static uint8_t get_tcp_flags(const struct tcphdr *tcph) {
    return ((tcph->syn ? TCP_FLAG_SYN : 0) |
            (tcph->ack ? TCP_FLAG_ACK : 0) |
            (tcph->fin ? TCP_FLAG_FIN : 0) |
            (tcph->rst ? TCP_FLAG_RST : 0) |
            (tcph->psh ? TCP_FLAG_PSH : 0));
}

// Validate packet
static int validate_packet(const struct iphdr *iph, int packet_len) {
    if (iph->protocol != IPPROTO_TCP) {
        return 0;
    }
    if (packet_len < (int)(iph->ihl * 4 + sizeof(struct tcphdr))) {
        LOG_ERROR("Packet too small for IP+TCP headers");
        return 0;
    }
    return 1;
}

// Setup Netfilter queue
static int setup_netfilter(void) {
    g_config.nfq_handle = nfq_open();
    if (!g_config.nfq_handle) {
        LOG_ERROR("Failed to open nfqueue: %s", strerror(errno));
        return -1;
    }
    
    if (nfq_unbind_pf(g_config.nfq_handle, AF_INET) < 0) {
        LOG_ERROR("Failed to unbind nfqueue: %s", strerror(errno));
        goto cleanup_nfq;
    }
    
    if (nfq_bind_pf(g_config.nfq_handle, AF_INET) < 0) {
        LOG_ERROR("Failed to bind nfqueue: %s", strerror(errno));
        goto cleanup_nfq;
    }
    
    g_config.queue_handle = nfq_create_queue(g_config.nfq_handle, g_config.queue_num, &handle_packet, NULL);
    if (!g_config.queue_handle) {
        LOG_ERROR("Failed to create queue: %s", strerror(errno));
        goto cleanup_nfq;
    }
    
    if (nfq_set_mode(g_config.queue_handle, NFQNL_COPY_PACKET, 0xffff) < 0) {
        LOG_ERROR("Failed to set packet copy mode: %s", strerror(errno));
        goto cleanup_queue;
    }
    
    return 0;
    
cleanup_queue:
    nfq_destroy_queue(g_config.queue_handle);
    g_config.queue_handle = NULL;
cleanup_nfq:
    nfq_close(g_config.nfq_handle);
    g_config.nfq_handle = NULL;
    return -1;
}

// Parse command-line arguments with validation
static int parse_arguments(int argc, char **argv) {
    int opt;
    
    while ((opt = getopt(argc, argv, "q:w:c:")) != -1) {
        switch (opt) {
            case 'q':
                g_config.queue_num = atoi(optarg);
                if (g_config.queue_num < 0) {
                    LOG_ERROR("Invalid queue number: %s", optarg);
                    return -1;
                }
                break;
            case 'w':
                g_config.window_size = atoi(optarg);
                if (g_config.window_size < MIN_WINDOW_SIZE || g_config.window_size > MAX_WINDOW_SIZE) {
                    LOG_ERROR("Window size must be between %d and %d", MIN_WINDOW_SIZE, MAX_WINDOW_SIZE);
                    return -1;
                }
                break;
            case 'c':
                g_config.confusion_times = atoi(optarg);
                if (g_config.confusion_times > MAX_CONFUSION_PACKETS) {
                    LOG_ERROR("Confusion packets must not exceed %d", MAX_CONFUSION_PACKETS);
                    return -1;
                }
                break;
            default:
                fprintf(stderr, "Usage: %s -q <queue_num> -w <window_size> -c <confusion_times>\n", argv[0]);
                return -1;
        }
    }
    
    if (g_config.queue_num < 0 || g_config.window_size < MIN_WINDOW_SIZE) {
        fprintf(stderr, "Usage: %s -q <queue_num> -w <window_size> -c <confusion_times>\n", argv[0]);
        return -1;
    }
    return 0;
}

// Authorization callback function
static size_t auth_write_callback(void *contents, size_t size, size_t nmemb, struct APIResponse *response) {
    size_t realsize = size * nmemb;
    char *ptr = realloc(response->data, response->size + realsize + 1);
    
    if (ptr == NULL) {
                printf("授权验证: 内存分配失败\n");
        return 0;
    }
    
    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, realsize);
    response->size += realsize;
    response->data[response->size] = 0;
    
    return realsize;
}

// 解析JSON中的success字段（更健壮的解析）
static int parse_auth_success(const char *json_data) {
    if (!json_data) return -1;
    
    // 查找 "success" 关键字
    const char *success_key = strstr(json_data, "\"success\"");
    if (!success_key) {
        success_key = strstr(json_data, "'success'");
    }
    if (!success_key) return -1;
    
    // 跳过 "success" 和可能的空格、冒号
    const char *p = success_key + 9; // strlen("\"success\"") = 9
    while (*p && (*p == ' ' || *p == ':' || *p == '\t')) p++;
    
    // 检查值
    if (strncmp(p, "true", 4) == 0) return 1;
    if (strncmp(p, "false", 5) == 0) return 0;
    
    return -1;
}

// 授权检查函数（只检查一次）
// 返回值: 1=授权成功, 0=授权失败
static int check_authorization(void) {
    CURL *curl;
    CURLcode res;
    struct APIResponse response = {0};
    char url[512];
    int auth_result = 0;
    
    printf("\n正在进行授权验证...\n\n");
    
    // 构建完整的API URL
    snprintf(url, sizeof(url), "%s?type=%d", AUTH_API_URL, AUTH_TYPE);
    
    curl = curl_easy_init();
    if (!curl) {
        printf("授权验证: 无法初始化\n");
        return 0;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, auth_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "CDNK-AuthClient/1.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, AUTH_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, AUTH_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        printf("授权验证失败: %s\n", curl_easy_strerror(res));
    } else {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        if (response_code == 200) {
            int success = parse_auth_success(response.data);
            
            if (success == 1) {
                printf("\033[32m验证通过，授权成功\033[0m\n");
                auth_result = 1;
            } else {
                // 提取IP地址
                char *ip_start = strstr(response.data, "IP(");
                if (ip_start) {
                    ip_start += 3;
                    char *ip_end = strchr(ip_start, ')');
                    if (ip_end && (ip_end - ip_start) > 0 && (ip_end - ip_start) < 64) {
                        char ip_addr[64] = {0};
                        strncpy(ip_addr, ip_start, ip_end - ip_start);
                        printf("授权验证失败: %s 未授权\n", ip_addr);
                    } else {
                        printf("验证失败，授权无效\n");
                    }
                } else {
                    printf("验证失败，授权无效\n");
                }
            }
        } else {
            printf("授权验证失败，HTTP状态码: %ld\n", response_code);
        }
    }
    
    curl_easy_cleanup(curl);
    if (response.data) {
        free(response.data);
    }
    
    return auth_result;
}

// Check if iptables rule exists
static int check_iptables_rule(int queue_num) {
    char command[512];
    int ret;
    
    // 使用 iptables -C 命令检查规则是否存在
    // -C 命令会检查规则，如果存在返回0，不存在返回非0
    snprintf(command, sizeof(command), 
             "iptables -C OUTPUT -p tcp --sport %d -j NFQUEUE --queue-num %d --queue-bypass 2>/dev/null",
             queue_num, queue_num);
    
    ret = system(command);
    
    // system() 返回值：0 表示规则存在，非0 表示规则不存在
    if (ret == 0) {
        return 1; // 规则存在
    } else {
        return 0; // 规则不存在
    }
}

// Add iptables rule
static int add_iptables_rule(int queue_num) {
    char command[512];
    int ret;
    
    printf("正在添加 iptables 规则...\n");
    
    // 构建添加规则的命令
    snprintf(command, sizeof(command),
             "iptables -I OUTPUT -p tcp --sport %d -j NFQUEUE --queue-num %d --queue-bypass 2>/dev/null",
             queue_num, queue_num);
    
    ret = system(command);
    
    if (ret == 0) {
        printf("✓ iptables 规则添加成功\n");
        return 0;
    } else {
        printf("✗ iptables 规则添加失败 (可能需要 root 权限)\n");
        return -1;
    }
}

// Check if systemd service exists
static int check_systemd_service_exists(void) {
    int ret;
    
    // 检查服务文件是否存在
    ret = system("systemctl list-unit-files | grep -q '^CDNK.service' 2>/dev/null");
    
    if (ret == 0) {
        return 1; // 服务存在
    } else {
        return 0; // 服务不存在
    }
}

// Create systemd service
static int create_systemd_service(const char *exec_path, int queue_num, int window_size, int confusion_times) {
    FILE *fp;
    char service_content[2048];
    char abs_path[1024];
    int ret;
    
    // 获取程序的绝对路径
    if (realpath(exec_path, abs_path) == NULL) {
        printf("✗ 无法获取程序绝对路径\n");
        return -1;
    }
    
    printf("\n正在创建 systemd 服务...\n");
    
    // 构建服务文件内容
    snprintf(service_content, sizeof(service_content),
             "[Unit]\n"
             "Description=CDNK Network Queue Service\n"
             "After=network-online.target\n"
             "Wants=network-online.target\n"
             "\n"
             "[Service]\n"
             "Type=simple\n"
             "Environment=CDNK_NO_DAEMON=1\n"
             "ExecStart=%s -q %d -w %d -c %d\n"
             "Restart=on-failure\n"
             "RestartSec=60s\n"
             "User=root\n"
             "Group=root\n"
             "\n"
             "[Install]\n"
             "WantedBy=multi-user.target\n",
             abs_path, queue_num, window_size, confusion_times);

    // 写入服务文件
    fp = fopen("/etc/systemd/system/CDNK.service", "w");
    if (fp == NULL) {
        printf("✗ 无法创建服务文件 (需要 root 权限)\n");
        return -1;
    }
    
    fprintf(fp, "%s", service_content);
    fclose(fp);
    
    printf("✓ 服务文件创建成功: /etc/systemd/system/CDNK.service\n");
    
    // 重新加载 systemd
    printf("正在重新加载 systemd...\n");
    ret = system("systemctl daemon-reload 2>/dev/null");
    if (ret != 0) {
        printf("✗ systemd 重新加载失败\n");
        return -1;
    }
    
    // 启用服务（开机自启）
    printf("正在启用开机自启动...\n");
    ret = system("systemctl enable CDNK.service 2>/dev/null");
    if (ret != 0) {
        printf("✗ 启用开机自启动失败\n");
        return -1;
    }
    
    printf("✓ 服务已启用，将在开机时自动启动\n");
    
    // 立即启动服务
    printf("正在启动 CDNK 服务...\n");
    ret = system("systemctl start CDNK.service 2>/dev/null");
    if (ret != 0) {
        printf("✗ 启动服务失败\n");
        return -1;
    }
    
    printf("✓ 服务已成功启动\n");
    
    return 0;
}

// Daemonize the process
static int daemonize(void) {
    pid_t pid, sid;
    
    // Fork the parent process
    pid = fork();
    if (pid < 0) {
        LOG_ERROR("Failed to fork: %s", strerror(errno));
        return -1;
    }
    
    // Exit the parent process
    if (pid > 0) {
        printf("\n程序已转入后台运行，PID: %d\n\n", pid);
        exit(0);
    }
    
    // Change the file mode mask
    umask(0);
    
    // Create a new session ID for the child process
    sid = setsid();
    if (sid < 0) {
        LOG_ERROR("Failed to create new session: %s", strerror(errno));
        return -1;
    }
    
    // Change the current working directory
    if (chdir("/") < 0) {
        LOG_ERROR("Failed to change directory: %s", strerror(errno));
        return -1;
    }
    
    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Redirect standard file descriptors to /dev/null
    open("/dev/null", O_RDONLY); // stdin
    open("/dev/null", O_WRONLY); // stdout
    open("/dev/null", O_WRONLY); // stderr
    
    return 0;
}

// Cleanup resources
static void cleanup_and_exit(int sig) {
    LOG_INFO("Received signal %d, shutting down...", sig);
    
    g_config.running = 0;
    
    if (g_config.queue_handle) {
        nfq_destroy_queue(g_config.queue_handle);
        g_config.queue_handle = NULL;
    }
    
    if (g_config.nfq_handle) {
        nfq_close(g_config.nfq_handle);
        g_config.nfq_handle = NULL;
    }
    
    if (g_config.raw_socket >= 0) {
        close(g_config.raw_socket);
        g_config.raw_socket = -1;
    }
    
    destroy_thread_pool();
    destroy_connection_table();
    
    LOG_INFO("CDNK shutdown complete");
    exit(0);
}

// Main function
int main(int argc, char **argv) {
    // 初始化curl全局环境
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // 进行授权验证
    int auth_result = check_authorization();
    if (auth_result != 1) {
        printf("\n请联系:飞机客服@mikeuse 处理\n\n");
        // 授权失败，清理服务并彻底退出（不再被systemd重启）
        cleanup_on_auth_failure();
        curl_global_cleanup();
        return 1;
    }
    
    printf("\n授权验证成功，程序继续启动...\n");
    
    if (parse_arguments(argc, argv) < 0) {
        curl_global_cleanup();
        return 1;
    }
    
    // 检查并创建 systemd 服务
    printf("\n检查 systemd 服务...\n");
    int service_exists = check_systemd_service_exists();
    
    if (service_exists == 1) {
        printf("✓ systemd 服务已存在\n");
    } else {
        printf("✗ systemd 服务不存在\n");
        if (create_systemd_service(argv[0], g_config.queue_num, g_config.window_size, g_config.confusion_times) < 0) {
            printf("\n警告: 无法创建 systemd 服务，但程序将继续运行\n");
        }
    }
    
    // 检查并添加 iptables 规则
    printf("\n检查 iptables 规则...\n");
    int rule_status = check_iptables_rule(g_config.queue_num);
    
    if (rule_status == 1) {
        printf("✓ iptables 规则已存在\n");
    } else if (rule_status == 0) {
        printf("✗ iptables 规则不存在\n");
        if (add_iptables_rule(g_config.queue_num) < 0) {
            printf("\n错误: 无法添加 iptables 规则，程序退出\n");
            printf("请手动执行: iptables -I OUTPUT -p tcp --sport %d -j NFQUEUE --queue-num %d --queue-bypass\n\n",
                   g_config.queue_num, g_config.queue_num);
            curl_global_cleanup();
            return 1;
        }
    }
    
    // 检查是否由 systemd 启动（通过环境变量）
    char *no_daemon_env = getenv("CDNK_NO_DAEMON");
    if (no_daemon_env != NULL && strcmp(no_daemon_env, "1") == 0) {
        // 由 systemd 启动，不进行 daemonize
        printf("\n程序在前台运行（systemd 模式）\n\n");
        LOG_INFO("Running in systemd mode (no daemonize)");
    } else {
        // 手动启动，转入后台运行
        if (daemonize() < 0) {
            LOG_ERROR("Failed to daemonize process");
            curl_global_cleanup();
            return 1;
        }
    }
    
    srand(time(NULL));
    
    // Initialize connection table
    init_connection_table();
    
    // Initialize thread pool
    if (init_thread_pool() < 0) {
        destroy_connection_table();
        curl_global_cleanup();
        return 1;
    }

    // Create raw socket
    g_config.raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (g_config.raw_socket < 0) {
        LOG_ERROR("Failed to create raw socket: %s", strerror(errno));
        destroy_thread_pool();
        destroy_connection_table();
        curl_global_cleanup();
        return 1;
    }
    
    // Setup netfilter
    if (setup_netfilter() < 0) {
        close(g_config.raw_socket);
        destroy_thread_pool();
        destroy_connection_table();
        curl_global_cleanup();
        return 1;
    }
    
    // Setup signal handlers
    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);
    
    LOG_INFO("CDNK started with queue=%d, window_size=%u, confusion_times=%u",
             g_config.queue_num, g_config.window_size, g_config.confusion_times);
    
    // Main packet processing loop
    char buf[65535];
    while (g_config.running) {
        int rv = recv(nfq_fd(g_config.nfq_handle), buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(g_config.nfq_handle, buf, rv);
        } else if (errno != EINTR) {
            LOG_ERROR("Error receiving packet: %s", strerror(errno));
            break;
        }
    }
    
    cleanup_and_exit(0);
    curl_global_cleanup();
    return 0;
}
```
