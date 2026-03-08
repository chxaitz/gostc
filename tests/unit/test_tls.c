/**
 * @file tls_client_netconn.c
 * @brief 基于lwIP 2.0.3 netconn + mbedTLS的TLS客户端
 * @version 2.0 (简洁版 - 直接使用netconn_xx API)
 */

#include "../src/gostc_tls.c"


/* 测试配置 */
#define SERVER_IP             "192.168.101.1"
#define SERVER_PORT           1111
#define TEST_BUFFER_SIZE      2048
#define CONNECT_TIMEOUT       5000

/**
 * @brief 发送HTTP请求 (TLS加密)
 */
static int mbedtls_tls_send_http_request(tls_client_ctx_t *ctx)
{
    int ret;
    char request[256];
    unsigned char buffer[TEST_BUFFER_SIZE];
    int total_received = 0;
    
    /* 构造HTTP GET请求 */
    snprintf(request, sizeof(request),
             "GET / HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: lwIP-netconn-TLS/1.0\r\n"
             "Connection: close\r\n"
             "\r\n",
             SERVER_IP);
    
    printf("[TLS] 发送HTTP请求 (%zu 字节)\n", strlen(request));
    printf("------[请求内容]------\n%s------------------\n", request);
    
    /* 通过TLS发送 */
    ret = mbedtls_ssl_write(&ctx->ssl, (unsigned char *)request, strlen(request));
    if (ret <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            printf("[TLS] 发送失败: -0x%x\n", -ret);
            return ret;
        }
    }
    
    printf("[TLS] 请求发送完成\n");
    
    /* 接收响应 */
    printf("[TLS] 等待响应...\n");
    do {
        memset(buffer, 0, sizeof(buffer));
        ret = mbedtls_ssl_read(&ctx->ssl, buffer, sizeof(buffer) - 1);
        
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            sys_msleep(10);
            continue;
        }
        
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            printf("[TLS] 服务器正常关闭连接\n");
            break;
        }
        
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            printf("[TLS] 连接被重置（服务器已关闭）\n");
            break;
        }
        
        if (ret <= 0) {
            printf("[TLS] 接收错误: -0x%x\n", -ret);
            break;
        }
        
        total_received += ret;
        printf("[TLS] 收到 %d 字节 (累计 %d)\n", ret, total_received);
        printf("------[响应内容]------\n%.*s\n--------------------\n", ret, buffer);
    } while (1);
    
    return 0;
}


/*=============================================================================
 * 主函数
 *===========================================================================*/

/**
 * @brief 主测试函数
 */
static int tls_client_test(void)
{
    int ret;
    
    printf("\n=== TLS客户端测试开始 (lwIP 2.0.3 + netconn + mbedTLS) ===\n");
    printf("目标: %s:%d\n", SERVER_IP, SERVER_PORT);
    
    /* 初始化上下文 */
    memset(&g_ctx, 0, sizeof(g_ctx));
    
    /* 1. 初始化mbedTLS - 直接调用，纯内存操作 */
    ret = mbedtls_tls_init(&g_ctx);
    if (ret != 0) {
        printf("[TLS] 初始化失败: %d\n", ret);
        return ret;
    }
    
    /* 2. 加载证书 - 直接调用 */
    ret = mbedtls_load_certificates(&g_ctx);
    if (ret != 0) {
        printf("[TLS] 加载证书失败: %d\n", ret);
        return ret;
    }
    
    /* 3. 建立TCP连接 - netconn API内部处理线程同步 */
    ret = netconn_do_connect(&g_ctx.netconn_ctx, SERVER_IP, SERVER_PORT);
    if (ret != 0) {
        printf("[NET] 连接失败: %d\n", ret);
        goto cleanup;
    }
    
    /* 4. 创建SSL会话 - 直接调用 */
    ret = mbedtls_ssl_setup(&g_ctx.ssl, &g_ctx.conf);
    if (ret != 0) {
        printf("[TLS] ssl_setup失败: -0x%x\n", -ret);
        goto cleanup;
    }
    
    /* 5. TLS握手 - 会调用netconn_recv_cb/netconn_send_cb */
    ret = mbedtls_tls_handshake(&g_ctx);
    if (ret != 0) {
        printf("[TLS] 握手失败: %d\n", ret);
        goto cleanup;
    }
    
    /* 6. 发送HTTP请求并接收响应 */
    ret = mbedtls_tls_send_http_request(&g_ctx);
    
cleanup:
    /* 7. 清理资源 */
    netconn_close_conn(&g_ctx.netconn_ctx);
    
    mbedtls_ssl_free(&g_ctx.ssl);
    mbedtls_ssl_config_free(&g_ctx.conf);
    mbedtls_x509_crt_free(&g_ctx.cacert);
#if mTLS_MODE
    mbedtls_x509_crt_free(&g_ctx.clicert);
    mbedtls_pk_free(&g_ctx.pkey);
#endif /* mTLS_MODE */
    mbedtls_ctr_drbg_free(&g_ctx.ctr_drbg);
    mbedtls_entropy_free(&g_ctx.entropy);
    
    if (ret == 0) {
        printf("\n=== 测试成功 ✓ ===\n");
    } else {
        printf("\n=== 测试失败 ✗ (错误码: %d) ===\n", ret);
    }
    
    return ret;
}

/**
 * @brief 网卡状态检测函数
 */
void check_netif_status(void)
{
    printf("\n=== 网络接口状态 ===\n");
    printf("netif_default: %p\n", netif_default);
    
    if (netif_default) {
        printf("  名称: %c%c%d\n", 
               netif_default->name[0], 
               netif_default->name[1], 
               netif_default->num);
        
        printf("  IP地址: %s\n", ip4addr_ntoa(netif_ip4_addr(netif_default)));
        printf("  子网掩码: %s\n", ip4addr_ntoa(netif_ip4_netmask(netif_default)));
        printf("  网关: %s\n", ip4addr_ntoa(netif_ip4_gw(netif_default)));
        
        printf("  状态: %s\n", netif_is_up(netif_default) ? "UP" : "DOWN");
        printf("  链路: %s\n", netif_is_link_up(netif_default) ? "UP" : "DOWN");
    }
    
    printf("=== 检查结束 ===\n\n");
}

/*=============================================================================
 * 网络初始化函数
 *===========================================================================*/

static struct netif netif;

#if LWIP_IPV4
#define NETIF_ADDRS ipaddr, netmask, gw,
void init_default_netif(const ip4_addr_t *ipaddr, const ip4_addr_t *netmask, const ip4_addr_t *gw)
#else
#define NETIF_ADDRS
void init_default_netif(void)
#endif
{
#if NO_SYS
    netif_add(&netif, NETIF_ADDRS NULL, tapif_init, netif_input);
#else
    netif_add(&netif, NETIF_ADDRS NULL, tapif_init, tcpip_input);
#endif
    netif_set_default(&netif);
}

#if LWIP_NETIF_STATUS_CALLBACK
static void status_callback(struct netif *state_netif)
{
    if (netif_is_up(state_netif)) {
#if LWIP_IPV4
        printf("status_callback==UP, local interface IP is %s\n", 
               ip4addr_ntoa(netif_ip4_addr(state_netif)));
#else
        printf("status_callback==UP\n");
#endif
    } else {
        printf("status_callback==DOWN\n");
    }
}
#endif

static void test_netif_init(void)
{
#if LWIP_IPV4 && USE_ETHERNET
    ip4_addr_t ipaddr, netmask, gw;
#endif

#if USE_DHCP || USE_AUTOIP
    err_t err;
#endif

#if USE_ETHERNET
#if LWIP_IPV4
    ip4_addr_set_zero(&gw);
    ip4_addr_set_zero(&ipaddr);
    ip4_addr_set_zero(&netmask);
#if USE_DHCP
    printf("Starting lwIP, local interface IP is dhcp-enabled\n");
#elif USE_AUTOIP
    printf("Starting lwIP, local interface IP is autoip-enabled\n");
#else
    LWIP_PORT_INIT_GW(&gw);
    LWIP_PORT_INIT_IPADDR(&ipaddr);
    LWIP_PORT_INIT_NETMASK(&netmask);
    printf("Starting lwIP, local interface IP is %s\n", ip4addr_ntoa(&ipaddr));
#endif
#endif

#if LWIP_IPV4
    init_default_netif(&ipaddr, &netmask, &gw);
#else
    init_default_netif();
#endif
#if LWIP_IPV6
    netif_create_ip6_linklocal_address(netif_default, 1);
    printf("ip6 linklocal address: %s\n", 
           ip6addr_ntoa(netif_ip6_addr(netif_default, 0)));
#endif
#if LWIP_NETIF_STATUS_CALLBACK
    netif_set_status_callback(netif_default, status_callback);
#endif

    netif_set_up(netif_default);
#if USE_DHCP
    err = dhcp_start(netif_default);
    LWIP_ASSERT("dhcp_start failed", err == ERR_OK);
#elif USE_AUTOIP
    err = autoip_start(netif_default);
    LWIP_ASSERT("autoip_start failed", err == ERR_OK);
#endif

#endif
}

static void test_init(void * arg)
{
    sys_sem_t *init_sem = (sys_sem_t*)arg;

    srand((unsigned int)time(0));
    test_netif_init();
    sys_sem_signal(init_sem);
}

/**
 * @brief 主函数入口
 */
int main(void)
{
    sys_sem_t init_sem;
    int result;
    
    printf("========================================\n");
    printf("lwIP 2.0.3 + mbedTLS TLS 1.2 客户端测试\n");
    printf("基于netconn API (简洁版 - 直接调用)\n");
    printf("========================================\n");
    
    /* 初始化信号量 */
    sys_sem_new(&init_sem, 0);
    
    /* 初始化tcpip */
    tcpip_init(test_init, &init_sem);
    
    /* 等待网络初始化完成 */
    sys_sem_wait(&init_sem);
    sys_sem_free(&init_sem);
    
    /* 初始化netconn线程 */
    netconn_thread_init();
    printf("[SYS] lwIP初始化完成\n");

    check_netif_status();
    
    /* 执行测试 */
    result = tls_client_test();
    
    /* 等待一下再退出 */
    sys_msleep(1000);
    
    return result;
}
