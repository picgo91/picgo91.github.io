//特殊线路： ./GYD443 -q 443 -w 7 -c 0
//普通线路： ./GYD443 -q 443 -w 3 -c 3
//编译：gcc -o GYD443 gyd80.c -lnetfilter_queue -lnfnetlink -lpthread -lcurl -ljson-c -lssl -lcrypto
//外网IP验证
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#ifdef __linux__
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#endif
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <curl/curl.h>

// Constants for connection tracking and packet handling
#define MAX_CONNECTIONS 10000
#define CLEANUP_THRESHOLD 100
#define CLEANUP_INTERVAL 60
#define MAX_CONFUSION_PACKETS 10
#define MAX_PACKET_SIZE 1500
#define MIN_WINDOW_SIZE 1
#define MAX_WINDOW_SIZE 65535
#define HASH_TABLE_SIZE 4096  // 哈希表大小，必须是2的幂
#define HASH_MASK (HASH_TABLE_SIZE - 1)
#define PERIODIC_CLEANUP_INTERVAL 30  // 定期清理间隔（秒）

// 优化后的连接信息结构
// 优化后的连接节点结构 - 减少内存占用和改善对齐
typedef struct connection_node {
    uint32_t dst_ip;                    // 4字节
    uint16_t dst_port;                  // 2字节
    uint16_t edit_count;                // 2字节 (与dst_port组成4字节对齐)
    uint32_t last_seen;                 // 4字节 - 使用uint32_t替代time_t减少内存
    struct connection_node *next;       // 8字节 (64位系统)
} __attribute__((packed)) connection_node_t;  // 总共20字节，紧凑排列

// 哈希表结构 - 优化字段顺序
typedef struct {
    connection_node_t *buckets[HASH_TABLE_SIZE];  // 指针数组
    connection_node_t *free_nodes;      // 空闲节点池
    uint32_t total_connections;         // 使用uint32_t替代size_t
    uint32_t free_count;                // 使用uint32_t替代size_t
} connection_hash_table_t;

// Global configuration structure
typedef struct {
int queue_num; // Netfilter queue number
uint16_t window_size;// TCP window size to set
uint8_t confusion_times;// Number of confusion packets to send
connection_hash_table_t conn_table;// 哈希表替代数组
int raw_socket; // Raw socket for sending confusion packets
pthread_mutex_t conn_mutex;// Mutex for thread-safe connection access
volatile sig_atomic_t running;// Flag to control program execution
time_t last_cleanup_time;  // 上次清理时间
#ifdef __linux__
struct nfq_handle *nfq_handle;// Netfilter queue handle
struct nfq_q_handle *queue_handle;// Netfilter queue handle
#endif
} config_t;

// Initialize global configuration
static config_t g_config = {
.queue_num = -1,
.window_size = 0,
.confusion_times = 0,
.conn_table = {.buckets = {NULL}, .free_nodes = NULL, .total_connections = 0, .free_count = 0},
.raw_socket = -1,
.running = 1,
.last_cleanup_time = 0,
#ifdef __linux__
.nfq_handle = NULL,
.queue_handle = NULL
#endif
};

// Structure for confusion packet data
typedef struct {
struct iphdr ip_copy; // Copy of IP header
struct tcphdr tcp_copy; // Copy of TCP header
} confusion_data_t;

// Function prototypes
static uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip, const uint16_t *tcp, uint16_t tcp_len);
static void cleanup_and_exit(int sig);
static uint32_t hash_connection(uint32_t dst_ip, uint16_t dst_port);
static connection_node_t* find_connection(uint32_t dst_ip, uint16_t dst_port);
static connection_node_t* add_connection(uint32_t dst_ip, uint16_t dst_port);
static void cleanup_old_connections(void);
static void periodic_cleanup_check(void);
static void init_connection_table(void);
static void destroy_connection_table(void);
static connection_node_t* get_free_node(void);
static void return_free_node(connection_node_t* node);
static void *send_confusion_packets_async(void *arg);
static void update_tcp_checksum(struct iphdr *iph, struct tcphdr *tcph);
static int setup_netfilter(void);
static int parse_arguments(int argc, char **argv);
static void log_error(const char *msg, int errnum);
static uint8_t get_tcp_flags(const struct tcphdr *tcph);
static int validate_packet(const struct iphdr *iph, int packet_len);
static int check_and_add_iptables_rule(void);

// Authorization function prototypes
typedef struct {
    char *memory;
    size_t size;
} http_response_t;

static size_t write_callback(void *contents, size_t size, size_t nmemb, http_response_t *response);
static int verify_license_key(const char *license_key);
static char* get_external_ip(void);

// Authorization implementation


#ifdef __linux__
// Packet handling callback for Netfilter queue
static int handle_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
struct nfq_data *nfa, void *data) {
struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
if (!ph) {
log_error("Failed to get packet header", 0);
return nfq_set_verdict(qh, 0, NF_ACCEPT, 0, NULL);
}

unsigned char *packet_data;
int packet_len = nfq_get_payload(nfa, &packet_data);
if (packet_len < 0) {
log_error("Failed to get packet payload", errno);
return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}

struct iphdr *iph = (struct iphdr *)packet_data;
if (!validate_packet(iph, packet_len)) {
return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, packet_len, packet_data);
}
#endif

struct tcphdr *tcph = (struct tcphdr *)(packet_data + iph->ihl * 4);
uint8_t flags = get_tcp_flags(tcph);
int need_modify = 0, is_sa_flag = 0, conn_idx = -1;
uint16_t new_window = g_config.window_size;

pthread_mutex_lock(&g_config.conn_mutex);

// 定期清理检查
periodic_cleanup_check();

connection_node_t *conn = NULL;

// Handle different TCP flags
switch (flags) {
case 0x02: // SYN
need_modify = 1;
break;
case 0x12: // SYN+ACK
conn = add_connection(iph->daddr, tcph->dest);
need_modify = 1;
is_sa_flag = 1;
break;
case 0x11: // FIN+ACK
case 0x18: // PSH+ACK
case 0x10: // ACK
conn = find_connection(iph->daddr, tcph->dest);
if (!conn) {
conn = add_connection(iph->daddr, tcph->dest);
}
if (conn) {
new_window = conn->edit_count <= 6 ? g_config.window_size : 28960;
conn->edit_count++;
conn->last_seen = time(NULL);
need_modify = 1;
}
break;
}

// Remove connection on FIN or RST - 优化删除逻辑
if ((flags & (0x01 | 0x04)) && conn) {
uint32_t hash = hash_connection(conn->dst_ip, conn->dst_port);
connection_node_t **bucket = &g_config.conn_table.buckets[hash];
connection_node_t *prev = NULL;
connection_node_t *current = *bucket;

while (current) {
if (current == conn) {
if (prev) {
prev->next = current->next;
} else {
*bucket = current->next;
}
return_free_node(current);
g_config.conn_table.total_connections--;
break;
}
prev = current;
current = current->next;
}
}

pthread_mutex_unlock(&g_config.conn_mutex);

if (need_modify) {
// Remove TCP options for SYN and SYN+ACK to simplify packet
if (flags == 0x02 || flags == 0x12) {
if (tcph->doff > 5) {
int old_len = tcph->doff * 4;
tcph->doff = 5;
memset((char *)tcph + 20, 0, old_len - 20);
iph->tot_len = htons(ntohs(iph->tot_len) - (old_len - 20));
}
}

// Modify TCP window size
        tcph->window = htons(new_window);
        // 减少printf调用频率，只在调试模式或特定条件下输出
        #ifdef DEBUG
        printf("Modified window size to %u for flags 0x%02x, Src=%s:%u, Dst=%s:%u\n",
        new_window, flags, inet_ntoa(*(struct in_addr *)&iph->saddr), ntohs(tcph->source),
        inet_ntoa(*(struct in_addr *)&iph->daddr), ntohs(tcph->dest));
        #endif
        update_tcp_checksum(iph, tcph);

// Send confusion packets for SYN+ACK - 优化内存分配
if (is_sa_flag && g_config.confusion_times > 0) {
// 使用栈分配替代堆分配，避免malloc/free开销
confusion_data_t conf_data;
memcpy(&conf_data.ip_copy, iph, sizeof(struct iphdr));
memcpy(&conf_data.tcp_copy, tcph, sizeof(struct tcphdr));

pthread_t thread;
if (pthread_create(&thread, NULL, send_confusion_packets_async, &conf_data) != 0) {
log_error("Failed to create confusion thread", errno);
} else {
pthread_detach(thread);
// 短暂等待确保线程能够复制数据
usleep(100);
}
}
}

return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, packet_len, packet_data);
}

// Calculate TCP checksum
static uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip, const uint16_t *tcp, uint16_t tcp_len) {
uint32_t sum = 0;
sum += (src_ip >> 16) + (src_ip & 0xFFFF);
sum += (dst_ip >> 16) + (dst_ip & 0xFFFF);
sum += htons(IPPROTO_TCP);
sum += htons(tcp_len);

uint16_t i; // Moved loop variable declaration outside for C89 compatibility
for (i = 0; i < tcp_len / 2; i++) {
sum += *tcp++;
}

if (tcp_len % 2) {
sum += *(uint8_t *)tcp;
}

while (sum >> 16) {
sum = (sum & 0xFFFF) + (sum >> 16);
}

return (uint16_t)~sum;
}

// Update IP and TCP checksums
static void update_tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
tcph->check = 0;
iph->check = 0;

uint16_t tcp_len = ntohs(iph->tot_len) - iph->ihl * 4;
tcph->check = tcp_checksum(iph->saddr, iph->daddr, (uint16_t *)tcph, tcp_len);

uint32_t sum = 0;
uint16_t *ip_header = (uint16_t *)iph;
int i; // Moved loop variable declaration outside for C89 compatibility
for (i = 0; i < iph->ihl * 2; i++) {
sum += ntohs(ip_header[i]);
}
while (sum >> 16) {
sum = (sum & 0xFFFF) + (sum >> 16);
}
iph->check = htons(~sum);
}

// Send confusion packets (RST) asynchronously - 优化内存和系统调用
static void *send_confusion_packets_async(void *arg) {
confusion_data_t *data = (confusion_data_t *)arg;
if (!data || g_config.raw_socket < 0) {
    return NULL;
}

// 立即复制数据到本地变量，避免栈数据失效
confusion_data_t local_data = *data;

struct sockaddr_in dest_addr = {
.sin_family = AF_INET,
.sin_addr.s_addr = local_data.ip_copy.saddr
};

// 使用栈分配的数据包缓冲区，减少内存占用
char packet_buf[sizeof(struct iphdr) + sizeof(struct tcphdr)];
struct iphdr *ip_hdr = (struct iphdr *)packet_buf;
struct tcphdr *tcp_hdr = (struct tcphdr *)(packet_buf + sizeof(struct iphdr));

int i;
int failed_count = 0;
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
.saddr = local_data.ip_copy.daddr,
.daddr = local_data.ip_copy.saddr
};

*tcp_hdr = (struct tcphdr){
.source = local_data.tcp_copy.dest,
.dest = local_data.tcp_copy.source,
.seq = htonl(ntohl(local_data.tcp_copy.seq) + seq_offset),
.ack_seq = local_data.tcp_copy.ack_seq,
.doff = 5,
.window = htons(random_window),
.rst = 1
};

tcp_hdr->check = tcp_checksum(ip_hdr->saddr, ip_hdr->daddr,
(uint16_t *)tcp_hdr, sizeof(struct tcphdr));

if (sendto(g_config.raw_socket, packet_buf,
sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
(struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
    // 减少错误日志输出频率，避免系统调用开销
    failed_count++;
    if (failed_count == 1) {  // 只在第一次失败时记录错误
        log_error("Failed to send confusion packet", errno);
    }
} 
#ifdef DEBUG
else {
    // 减少printf调用，只在调试模式下输出
    printf("Sent confusion packet %d: Seq=%u, Win=%u, Dst=%s:%u\n",
    i + 1, ntohl(tcp_hdr->seq), random_window,
    inet_ntoa(*(struct in_addr *)&ip_hdr->daddr), ntohs(tcp_hdr->dest));
}
#endif

// 减少usleep调用，批量发送后再等待
if (i % 5 == 4) {  // 每5个包等待一次
    usleep(1000);
}
}

return NULL;
}

// 哈希函数
static uint32_t hash_connection(uint32_t dst_ip, uint16_t dst_port) {
    return ((dst_ip ^ (dst_port << 16)) * 2654435761U) & HASH_MASK;
}

// Find existing connection - 使用哈希表
static connection_node_t* find_connection(uint32_t dst_ip, uint16_t dst_port) {
    uint32_t hash = hash_connection(dst_ip, dst_port);
    connection_node_t *node = g_config.conn_table.buckets[hash];
    
    while (node) {
        if (node->dst_ip == dst_ip && node->dst_port == dst_port) {
            return node;
        }
        node = node->next;
    }
    return NULL;
}

// Add new connection to tracking - 使用哈希表和节点池
static connection_node_t* add_connection(uint32_t dst_ip, uint16_t dst_port) {
    if (g_config.conn_table.total_connections >= MAX_CONNECTIONS) {
        cleanup_old_connections();
        if (g_config.conn_table.total_connections >= MAX_CONNECTIONS) {
            return NULL;
        }
    }
    
    connection_node_t *node = get_free_node();
    if (!node) {
        return NULL;
    }
    
    node->dst_ip = dst_ip;
    node->dst_port = dst_port;
    node->edit_count = 1;
    node->last_seen = (uint32_t)time(NULL);
    
    uint32_t hash = hash_connection(dst_ip, dst_port);
    node->next = g_config.conn_table.buckets[hash];
    g_config.conn_table.buckets[hash] = node;
    g_config.conn_table.total_connections++;
    
    return node;
}

// Clean up stale connections - 优化哈希表清理
static void cleanup_old_connections(void) {
    uint32_t now = (uint32_t)time(NULL);
    uint32_t i;
    
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        connection_node_t **current = &g_config.conn_table.buckets[i];
        
        while (*current) {
            connection_node_t *node = *current;
            if (now - node->last_seen >= CLEANUP_INTERVAL || 
                node->edit_count >= CLEANUP_THRESHOLD) {
                *current = node->next;
                return_free_node(node);
                g_config.conn_table.total_connections--;
            } else {
                current = &node->next;
            }
        }
    }
    g_config.last_cleanup_time = now;
}

// 定期清理检查
static void periodic_cleanup_check(void) {
    time_t now = time(NULL);
    if (now - g_config.last_cleanup_time >= PERIODIC_CLEANUP_INTERVAL) {
        cleanup_old_connections();
    }
}

// 初始化连接表和节点池
static void init_connection_table(void) {
    size_t i;
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        g_config.conn_table.buckets[i] = NULL;
    }
    g_config.conn_table.total_connections = 0;
    g_config.conn_table.free_nodes = NULL;
    g_config.conn_table.free_count = 0;
    
    // 预分配一些节点到空闲池
    for (i = 0; i < 1000; i++) {
        connection_node_t *node = malloc(sizeof(connection_node_t));
        if (node) {
            node->next = g_config.conn_table.free_nodes;
            g_config.conn_table.free_nodes = node;
            g_config.conn_table.free_count++;
        }
    }
}

// 销毁连接表
static void destroy_connection_table(void) {
    size_t i;
    
    // 清理哈希表中的所有节点
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        connection_node_t *node = g_config.conn_table.buckets[i];
        while (node) {
            connection_node_t *next = node->next;
            free(node);
            node = next;
        }
    }
    
    // 清理空闲节点池
    connection_node_t *node = g_config.conn_table.free_nodes;
    while (node) {
        connection_node_t *next = node->next;
        free(node);
        node = next;
    }
}

// 从空闲池获取节点
static connection_node_t* get_free_node(void) {
    if (g_config.conn_table.free_nodes) {
        connection_node_t *node = g_config.conn_table.free_nodes;
        g_config.conn_table.free_nodes = node->next;
        g_config.conn_table.free_count--;
        memset(node, 0, sizeof(connection_node_t));
        return node;
    }
    
    // 空闲池为空，直接分配
    return malloc(sizeof(connection_node_t));
}

// 归还节点到空闲池
static void return_free_node(connection_node_t* node) {
    if (!node) return;
    
    // 限制空闲池大小，避免内存占用过多
    if (g_config.conn_table.free_count < 500) {
        node->next = g_config.conn_table.free_nodes;
        g_config.conn_table.free_nodes = node;
        g_config.conn_table.free_count++;
    } else {
        free(node);
    }
}

// Extract TCP flags
static uint8_t get_tcp_flags(const struct tcphdr *tcph) {
return ((tcph->syn ? 0x02 : 0) | (tcph->ack ? 0x10 : 0) |
(tcph->fin ? 0x01 : 0) | (tcph->rst ? 0x04 : 0) |
(tcph->psh ? 0x08 : 0));
}

// Validate packet size and protocol
static int validate_packet(const struct iphdr *iph, int packet_len) {
if (packet_len < (int)(iph->ihl * 4 + sizeof(struct tcphdr))) {
log_error("Packet too small for IP+TCP headers", 0);
return 0;
}
if (iph->protocol != IPPROTO_TCP) {
return 0;
}
return 1;
}

// Log errors with optional errno
static void log_error(const char *msg, int errnum) {
fprintf(stderr, "Error: %s", msg);
if (errnum) {
fprintf(stderr, ": %s", strerror(errnum));
}
fprintf(stderr, "\n");
}

// Check and add iptables rule if not exists
static int check_and_add_iptables_rule(void) {
    // 检查当前iptables规则
    printf("正在检查iptables规则...\n");
    
    // 首先清理可能存在的重复规则
    printf("清理可能存在的重复规则...\n");
    system("iptables -D OUTPUT -p tcp --sport 443 -j NFQUEUE --queue-num 443 --queue-bypass 2>/dev/null || true");
    
    // 使用更精确的检查：确保匹配的是端口443而不是4430等
    // 使用正则表达式精确匹配 spt:443 后面跟着空格或行尾
    FILE *fp = popen("iptables -L OUTPUT -n | grep -E 'NFQUEUE.*tcp.*spt:443[[:space:]]' | wc -l", "r");
    if (fp == NULL) {
        log_error("无法执行iptables检查命令", errno);
        return -1;
    }
    
    char buffer[64];
    int rule_count = 0;
    
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        rule_count = atoi(buffer);
    }
    pclose(fp);
    
    printf("当前存在 %d 条精确匹配的规则 (sport 443)\n", rule_count);
    
    if (rule_count == 0) {
        // 没有规则，添加一条
        printf("添加iptables规则...\n");
        char iptables_cmd[256];
        snprintf(iptables_cmd, sizeof(iptables_cmd),
            "iptables -I OUTPUT -p tcp --sport 443 -j NFQUEUE --queue-num 443 --queue-bypass");
        
        printf("执行命令: %s\n", iptables_cmd);
        int result = system(iptables_cmd);
        
        if (result == 0) {
            printf("✅  iptables规则添加成功\n");
            return 0;
        } else {
            printf("❌  错误: iptables规则添加失败 (返回码: %d)\n", result);
            printf("请确保:\n");
            printf("  1. 以root权限运行程序\n");
            printf("  2. 系统已安装iptables\n");
            printf("  3. 内核支持netfilter功能\n");
            return -1;
        }
    } else {
        printf("✅  iptables规则已存在 (%d 条)，无需添加\n", rule_count);
        return 0;
    }
}

// Setup Netfilter queue
static int setup_netfilter(void) {
	// 检查是否以root权限运行
	if (getuid() != 0) {
		log_error("程序需要root权限运行，请使用 sudo 或以root用户身份运行", 0);
		return -1;
	}

	g_config.nfq_handle = nfq_open();
	if (!g_config.nfq_handle) {
		log_error("Failed to open nfqueue", errno);
		log_error("请确保已加载netfilter_queue内核模块: modprobe nfnetlink_queue", 0);
		return -1;
	}

	if (nfq_unbind_pf(g_config.nfq_handle, AF_INET) < 0) {
		log_error("Failed to unbind nfqueue", errno);
		nfq_close(g_config.nfq_handle);
		return -1;
	}

	if (nfq_bind_pf(g_config.nfq_handle, AF_INET) < 0) {
		log_error("Failed to bind nfqueue", errno);
		nfq_close(g_config.nfq_handle);
		return -1;
	}

	g_config.queue_handle = nfq_create_queue(g_config.nfq_handle, g_config.queue_num, &handle_packet, NULL);
	if (!g_config.queue_handle) {
		log_error("Failed to create queue", errno);
		log_error("请检查iptables规则是否正确设置NFQUEUE目标", 0);
		printf("示例iptables规则: iptables -I OUTPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d\n", g_config.queue_num);
		nfq_close(g_config.nfq_handle);
		return -1;
	}

	if (nfq_set_mode(g_config.queue_handle, NFQNL_COPY_PACKET, 0xffff) < 0) {
		log_error("Failed to set packet copy mode", errno);
		nfq_destroy_queue(g_config.queue_handle);
		nfq_close(g_config.nfq_handle);
		return -1;
	}

	return 0;
}

// Parse command-line arguments
static int parse_arguments(int argc, char **argv) {
	int opt;
	while ((opt = getopt(argc, argv, "q:w:c:h")) != -1) {
		switch (opt) {
		case 'q':
			g_config.queue_num = atoi(optarg);
			if (g_config.queue_num < 0) {
				log_error("Invalid queue number", 0);
				return -1;
			}
			break;
		case 'w':
			g_config.window_size = atoi(optarg);
			if (g_config.window_size < MIN_WINDOW_SIZE || g_config.window_size > MAX_WINDOW_SIZE) {
				log_error("Invalid window size", 0);
				return -1;
			}
			break;
		case 'c':
			g_config.confusion_times = atoi(optarg);
			if (g_config.confusion_times > MAX_CONFUSION_PACKETS) {
				log_error("Too many confusion packets", 0);
				return -1;
			}
			break;
		case 'h':
			printf("TCP窗口大小修改工具\n\n");
			printf("使用方法: %s -q <queue_num> -w <window_size> -c <confusion_times>\n\n", argv[0]);
			printf("参数说明:\n");
			printf("  -q <queue_num>      Netfilter队列号 (必需)\n");
			printf("  -w <window_size>    TCP窗口大小 (1-%d) (必需)\n", MAX_WINDOW_SIZE);
			printf("  -c <confusion_times> 混淆包数量 (0-%d)\n", MAX_CONFUSION_PACKETS);
			printf("  -h                  显示此帮助信息\n\n");
			printf("运行要求:\n");
			printf("  1. 必须以root权限运行\n");
			printf("  2. 需要加载netfilter_queue内核模块: modprobe nfnetlink_queue\n");
			printf("  3. 需要设置相应的iptables规则\n\n");
			printf("示例:\n");
			printf("  %s -q 443 -w 30 -c 3\n", argv[0]);
    printf("  iptables -I OUTPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num 443\n\n");
			exit(0);
			break;
		default:
			fprintf(stderr, "使用 %s -h 查看帮助信息\n", argv[0]);
			return -1;
		}
	}
	if (g_config.queue_num < 0 || g_config.window_size < MIN_WINDOW_SIZE) {
		fprintf(stderr, "错误: 缺少必需参数\n");
		fprintf(stderr, "使用 %s -h 查看帮助信息\n", argv[0]);
		return -1;
	}
	return 0;
}

// Cleanup resources and exit
// Cleanup resources and exit
static void cleanup_and_exit(int sig) {
	g_config.running = 0;
	
	if (g_config.queue_handle) {
		nfq_destroy_queue(g_config.queue_handle);
	}
	if (g_config.nfq_handle) {
		nfq_close(g_config.nfq_handle);
	}
	if (g_config.raw_socket >= 0) {
		close(g_config.raw_socket);
	}
	destroy_connection_table();
	pthread_mutex_destroy(&g_config.conn_mutex);
	
	// 清理curl库
	curl_global_cleanup();
	
	exit(0);
}

// 添加创建systemd服务文件的函数
static int create_systemd_service(const char *program_path, int queue_num, int window_size, int confusion_times) {
    FILE *service_file;
    char service_content[2048];
    
    // 创建服务文件内容
    snprintf(service_content, sizeof(service_content),
        "[Unit]\n"
        "Description=GYD443 TCP Window Size Modifier\n"
        "After=network.target\n"
        "Wants=network.target\n\n"
        "[Service]\n"
        "Type=forking\n"
        "ExecStart=%s -q %d -w %d -c %d\n"
        "ExecStop=/bin/kill -TERM $MAINPID\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "User=root\n"
        "Group=root\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n",
        program_path, queue_num, window_size, confusion_times);
    
    // 写入服务文件
    service_file = fopen("/etc/systemd/system/GYD443.service", "w");
    if (!service_file) {
        log_error("Failed to create systemd service file", errno);
        return -1;
    }
    
    if (fprintf(service_file, "%s", service_content) < 0) {
        log_error("Failed to write systemd service file", errno);
        fclose(service_file);
        return -1;
    }
    
    fclose(service_file);
    printf("systemd服务文件创建成功: /etc/systemd/system/GYD443.service\n");
    return 0;
}

// 添加安装和启用systemd服务的函数
static int install_and_enable_service() {
    int result;
    
    // 重新加载systemd配置
    printf("正在重新加载systemd配置...\n");
    result = system("systemctl daemon-reload");
    if (result != 0) {
        printf("警告: systemctl daemon-reload 失败\n");
        return -1;
    }
    
    // 启用服务（开机自启动）
    printf("正在启用GYD443服务开机自启动...\n");
    result = system("systemctl enable GYD443.service");
    if (result != 0) {
        printf("警告: systemctl enable GYD443.service 失败\n");
        return -1;
    }
    
    printf("GYD443服务已成功配置为开机自启动\n");
    printf("您可以使用以下命令管理服务:\n");
    printf("  启动服务: systemctl start GYD443.service\n");
    printf("  停止服务: systemctl stop GYD443.service\n");
    printf("  查看状态: systemctl status GYD443.service\n");
    printf("  禁用自启: systemctl disable GYD443.service\n");
    
    return 0;
}

// Authorization functions implementation
static size_t write_callback(void *contents, size_t size, size_t nmemb, http_response_t *response) {
    size_t realsize = size * nmemb;
    char *ptr = realloc(response->memory, response->size + realsize + 1);
    
    if (ptr == NULL) {
        printf("内存分配失败\n");
        return 0;
    }
    
    response->memory = ptr;
    memcpy(&(response->memory[response->size]), contents, realsize);
    response->size += realsize;
    response->memory[response->size] = 0;
    
    return realsize;
}

static char* get_external_ip(void) {
    CURL *curl;
    CURLcode res;
    http_response_t response = {0};
    char *ip = NULL;
    int i; /* 将循环变量声明移到函数开头 */
    
    curl = curl_easy_init();
    if (curl) {
        /* 使用多个IP查询服务，提高成功率 */
        const char *ip_services[] = {
            "http://ipinfo.io/ip",
            "http://icanhazip.com",
            "http://ipecho.net/plain",
            "http://checkip.amazonaws.com",
            NULL
        };
        
        for (i = 0; ip_services[i] != NULL && ip == NULL; i++) {
            /* 重置响应结构 */
            if (response.memory) {
                free(response.memory);
                response.memory = NULL;
                response.size = 0;
            }
            
            /* 设置URL */
            curl_easy_setopt(curl, CURLOPT_URL, ip_services[i]);
            
            /* 设置回调函数 */
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            
            /* 设置超时时间 */
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
            
            /* 执行请求 */
            res = curl_easy_perform(curl);
            
            if (res == CURLE_OK && response.memory && response.size > 0) {
                /* 去除换行符和空格 */
                char *start = response.memory;
                char *end = response.memory + response.size - 1;
                
                /* 去除开头空格 */
                while (start < end && (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r')) {
                    start++;
                }
                
                /* 去除结尾空格和换行 */
                while (end > start && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r' || *end == '\0')) {
                    end--;
                }
                
                if (end > start) {
                    size_t ip_len = end - start + 1;
                    ip = malloc(ip_len + 1);
                    if (ip) {
                        memcpy(ip, start, ip_len);
                        ip[ip_len] = '\0';
                        printf("\n📋  获取到外网IP: %s\n", ip);
                        break;
                    }
                }
            }
        }
        
        curl_easy_cleanup(curl);
    }
    
    if (response.memory) {
        free(response.memory);
    }
    
    if (!ip) {
        printf("警告: 无法获取外网IP，使用默认授权密钥\n");
        ip = strdup("DZVC-Z442-1RY1-1XDW");
    }
    
    return ip;
}

static int verify_license_key(const char *license_key) {
    CURL *curl;
    CURLcode res;
    http_response_t response = {0};
    char url[512];
    int result = -1;
    
    // 构建请求URL
    snprintf(url, sizeof(url), "http://api.5205230.xyz/verify_key_and_date.php?license_key=%s", license_key);
    
    curl = curl_easy_init();
    if (curl) {
        // 设置URL
        curl_easy_setopt(curl, CURLOPT_URL, url);
        
        // 设置回调函数
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        
        // 设置超时时间
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        
        // 执行请求
        res = curl_easy_perform(curl);
        
        if (res == CURLE_OK && response.memory) {
            // 检查响应内容
            if (strstr(response.memory, "未授权")) {
                printf("\n❌  授权验证失败: 未授权\n");
                result = 0;
            } else if (strstr(response.memory, "授权到期")) {
                printf("\n❌  授权验证失败: 授权到期\n");
                result = 0;
            } else if (strstr(response.memory, "授权成功")) {
                printf("\n✅  授权验证成功\n");
                result = 1;
            } else {
                printf("\n❌  授权验证失败: 服务器响应异常\n");
                result = 0;
            }
        } else {
            printf("\n❌  授权验证失败: 网络请求失败\n");
            result = 0;
        }
        
        // 清理
        curl_easy_cleanup(curl);
    } else {
        printf("\n❌ 授权验证失败: 初始化HTTP客户端失败\n");
        result = 0;
    }
    
    if (response.memory) {
        free(response.memory);
    }
    
    return result;
}

#ifdef __linux__
// Main function

int main(int argc, char **argv) {

if (parse_arguments(argc, argv) < 0) {
return 1;
}

// 初始化curl库
curl_global_init(CURL_GLOBAL_DEFAULT);

// 执行授权检测
printf("\n💡  正在进行授权验证...\n");
char *license_key = get_external_ip();
if (!license_key) {
    printf("\n❌  无法获取授权密钥，程序退出\n");
    curl_global_cleanup();
    return 1;
}

int auth_result = verify_license_key(license_key);
free(license_key);  // 释放动态分配的内存

if (auth_result != 1) {
    printf("\n📞  联系客服✈️：@mikeuse\n\n");
    curl_global_cleanup();
    return 1;
}

printf("\n✅  授权验证通过，程序继续运行...\n\n");

// 检查并添加iptables规则
printf("🔧  正在检查iptables规则...\n");
if (check_and_add_iptables_rule() != 0) {
    printf("⚠️  iptables规则检查失败，但程序将继续运行\n");
}

#ifdef __linux__
// 获取程序的完整路径
char program_path[1024];
ssize_t len = readlink("/proc/self/exe", program_path, sizeof(program_path) - 1);
if (len == -1) {
    log_error("Failed to get program path", errno);
    return 1;
}
program_path[len] = '\0';

// 创建systemd服务文件并启用自启动
printf("✅  正在配置开机自启动...\n\n");
if (create_systemd_service(program_path, g_config.queue_num, g_config.window_size, g_config.confusion_times) == 0) {
    if (install_and_enable_service() == 0) {
        printf("开机自启动配置成功！\n");
    }
} else {
    printf("警告: 开机自启动配置失败，程序将继续运行但不会自动启动\n");
}
#else
printf("注意: 当前系统不支持systemd自启动功能，仅在Linux系统上可用\n");
#endif

srand(time(NULL));
init_connection_table();

if (pthread_mutex_init(&g_config.conn_mutex, NULL) != 0) {
log_error("Failed to initialize mutex", errno);
destroy_connection_table();
return 1;
}

g_config.raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
if (g_config.raw_socket < 0) {
log_error("Failed to create raw socket", errno);
pthread_mutex_destroy(&g_config.conn_mutex);
destroy_connection_table();
return 1;
}

if (setup_netfilter() < 0) {
close(g_config.raw_socket);
pthread_mutex_destroy(&g_config.conn_mutex);
destroy_connection_table();
return 1;
}

signal(SIGINT, cleanup_and_exit);
	signal(SIGTERM, cleanup_and_exit);

	// 转为后台运行
	if (daemon(0, 0) == -1) {
		log_error("Failed to daemonize process", errno);
		cleanup_and_exit(1);
		return 1;
	}

	char buf[65535];
	int rv;
	while (g_config.running) {
rv = recv(nfq_fd(g_config.nfq_handle), buf, sizeof(buf), 0);
if (rv >= 0) {
nfq_handle_packet(g_config.nfq_handle, buf, rv);
} else if (errno != EINTR) {
log_error("Error receiving packet", errno);
}
}

cleanup_and_exit(0);
return 0;
}
#endif
