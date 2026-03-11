/**
 * @file tls_client_netconn.c
 * @brief 基于lwIP 2.0.3 netconn + mbedTLS的TLS客户端
 * @version 2.0 (简洁版 - 直接使用netconn_xx API)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "lwip/api.h"
#include "lwip/autoip.h"
#include "lwip/dhcp.h"
#include "lwip/dns.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
#include "lwip/sys.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/platform.h"

#include "tapif.h"
#include "lwipcfg.h"


#define CONNECT_TIMEOUT       5000

/* 双证模式 */
#define mTLS_MODE             1

/* 调试级别 (0-4) 4最详细 */
#define MBEDTLS_DEBUG_LEVEL 1

/** Define this to 1 to enable a port-specific ethernet interface as default interface. */
#ifndef USE_DEFAULT_ETH_NETIF
#define USE_DEFAULT_ETH_NETIF 1
#endif

/** Use an ethernet adapter? Default to enabled if port-specific ethernet netif or PPPoE are used. */
#ifndef USE_ETHERNET
#define USE_ETHERNET  USE_DEFAULT_ETH_NETIF
#endif

/**
 * @brief mbedTLS netconn上下文结构
 * 
 * 将netconn连接包装成mbedTLS可以使用的I/O上下文
 */
typedef struct {
    struct netconn *conn;          /* netconn连接 */
    ip_addr_t remote_addr;         /* 服务器地址 */
    uint16_t remote_port;          /* 服务器端口 */
    uint8_t connected;             /* 连接标志 */
    
    /* 用于处理 TCP 分片的部分读取 */
    struct netbuf *pending_buf;    /* 挂起的 netbuf（存储未读完的数据） */
    u16_t pending_offset;          /* 当前在挂起 buffer 中的读取位置 */
    u16_t pending_len;             /* 挂起 buffer 的总数据长度 */
} mbedtls_netconn_context_t;

/**
 * @brief TLS客户端整体上下文
 */
typedef struct {
    mbedtls_netconn_context_t netconn_ctx;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;       // CA证书（验证服务器）
    mbedtls_x509_crt clicert;      // 客户端证书（自己被验证）
    mbedtls_pk_context pkey;       // 客户端私钥
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    uint8_t handshake_done;
    char error_buf[200];
} tls_client_ctx_t;

static tls_client_ctx_t g_ctx;

/**
 * @brief mbedTLS调试回调
 */
static void my_debug(void *ctx, int level, const char *file, int line,
                     const char *str)
{
    ((void)level);
    fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *)ctx);
}

/*=============================================================================
 * 自定义netconn I/O函数 - 这些会被mbedTLS在握手和读写时调用
 *===========================================================================*/

/**
 * @brief 自定义netconn接收函数
 */
static int netconn_recv_cb(void *ctx, unsigned char *buf, size_t len)
{
    mbedtls_netconn_context_t *netctx = (mbedtls_netconn_context_t *)ctx;
    struct netbuf *nbuf = NULL;
    err_t err;
    size_t total_recv = 0;
    size_t remaining = len;
    
    printf("[RECV] Requested %zu bytes\n", len);
    
    if (netctx == NULL || netctx->conn == NULL || !netctx->connected) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
    
    // 首先处理 pending 数据
    if (netctx->pending_buf != NULL) {
        printf("[RECV] Processing pending: offset=%u, len=%u\n", 
               netctx->pending_offset, netctx->pending_len);
        
        size_t pending_avail = netctx->pending_len - netctx->pending_offset;
        size_t copy_len = pending_avail < remaining ? pending_avail : remaining;
        
        if (copy_len > 0) {
            netbuf_copy_partial(netctx->pending_buf, buf, copy_len, netctx->pending_offset);
            netctx->pending_offset += copy_len;
            
            total_recv += copy_len;
            remaining -= copy_len;
            printf("[RECV] Copied %zu bytes from pending, remaining=%zu\n", copy_len, remaining);
        }
        
        if (netctx->pending_offset >= netctx->pending_len) {
            printf("[RECV] Pending buffer fully consumed, deleting\n");
            netbuf_delete(netctx->pending_buf);
            netctx->pending_buf = NULL;
            netctx->pending_offset = 0;
            netctx->pending_len = 0;
        }
        
        if (remaining == 0) {
            printf("[RECV] Request satisfied from pending, returning %zu\n", total_recv);
            return total_recv;
        }
    }
    
    // 读取新数据
    while (remaining > 0) {
        printf("[RECV] Calling netconn_recv, remaining=%zu\n", remaining);
        err = netconn_recv(netctx->conn, &nbuf);
        
        if (err != ERR_OK) {
            printf("[RECV] netconn_recv returned %d\n", err);
            if (err == ERR_TIMEOUT) {
                return total_recv > 0 ? total_recv : MBEDTLS_ERR_SSL_TIMEOUT;
            }
            if (err == ERR_CLSD || err == ERR_RST || err == ERR_CONN) {
                if (netctx->pending_buf != NULL) {
                    netbuf_delete(netctx->pending_buf);
                    netctx->pending_buf = NULL;
                    netctx->pending_offset = 0;
                    netctx->pending_len = 0;
                }
                return MBEDTLS_ERR_NET_CONN_RESET;
            }
            if (err == ERR_WOULDBLOCK || err == ERR_INPROGRESS) {
                return total_recv > 0 ? total_recv : MBEDTLS_ERR_SSL_WANT_READ;
            }
            return MBEDTLS_ERR_NET_RECV_FAILED;
        }
        
        if (nbuf == NULL) {
            printf("[RECV] nbuf is NULL\n");
            return total_recv > 0 ? total_recv : 0;
        }
        
        size_t buf_len = netbuf_len(nbuf);
        printf("[RECV] Received netbuf with %zu bytes\n", buf_len);
        
        unsigned char header[16];
        netbuf_copy_partial(nbuf, header, sizeof(header), 0);
        printf("[RECV] First 16 bytes: ");
        for (int i = 0; i < 16; i++) printf("%02x ", header[i]);
        printf("\n");
        
        if (buf_len <= remaining) {
            printf("[RECV] Copying full %zu bytes\n", buf_len);
            netbuf_copy(nbuf, buf + total_recv, buf_len);
            total_recv += buf_len;
            remaining -= buf_len;
            netbuf_delete(nbuf);
            printf("[RECV] Full copy done, total=%zu, remaining=%zu\n", total_recv, remaining);
        } else {
            printf("[RECV] Partial copy: need %zu of %zu bytes\n", remaining, buf_len);
            netbuf_copy_partial(nbuf, buf + total_recv, remaining, 0);
            total_recv += remaining;
            
            // 保存剩余的包作为 pending
            netctx->pending_buf = nbuf;
            netctx->pending_offset = remaining;
            netctx->pending_len = buf_len;
            printf("[RECV] Saved pending: offset=%u, len=%u\n", 
                   netctx->pending_offset, netctx->pending_len);
            
            remaining = 0;
        }
    }
    
    printf("[RECV] Returning %zu bytes\n", total_recv);
    return total_recv;
}

/**
 * @brief 自定义netconn发送函数
 */
static int netconn_send_cb(void *ctx, const unsigned char *buf, size_t len)
{
    mbedtls_netconn_context_t *netctx = (mbedtls_netconn_context_t *)ctx;
    err_t err;
    size_t written = 0;
    
    if (netctx == NULL || netctx->conn == NULL || !netctx->connected) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
    
    /* 发送数据 - netconn_write内部会通过tcpip_api_call处理线程同步 */
    err = netconn_write_partly(netctx->conn, buf, len, NETCONN_COPY, &written);
    if (err != ERR_OK) {
        if (err == ERR_TIMEOUT) {
            return MBEDTLS_ERR_SSL_TIMEOUT;
        } else if (err == ERR_RST) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        } else {
            return MBEDTLS_ERR_NET_SEND_FAILED;
        }
    }
    
    return written;
}

/*=============================================================================
 * TCP连接管理
 *===========================================================================*/

/**
 * @brief 建立TCP连接
 */
static int netconn_do_connect(mbedtls_netconn_context_t *netctx,
                               const char *host, uint16_t port)
{
    err_t err;
    ip_addr_t server_ip;
    int retry_count = 0;
    int max_retries = 3;
    
    printf("[NET] 正在解析地址: %s:%d\n", host, port);
    
    /* 解析IP地址 */
    if (!ipaddr_aton(host, &server_ip)) {
        printf("[NET] 地址解析失败\n");
        return MBEDTLS_ERR_NET_UNKNOWN_HOST;
    }
    
    while (retry_count < max_retries) {
        /* 创建TCP连接 */
        netctx->conn = netconn_new(NETCONN_TCP);
        if (netctx->conn == NULL) {
            printf("[NET] 创建netconn失败\n");
            return MBEDTLS_ERR_NET_SOCKET_FAILED;
        }
        
        /* 设置接收超时 */
        netconn_set_recvtimeout(netctx->conn, CONNECT_TIMEOUT);
        
        printf("[NET] 正在连接到 %s:%d... (尝试 %d/%d)\n", 
               host, port, retry_count + 1, max_retries);
        
        /* 初始化 pending 字段 */
        netctx->pending_buf = NULL;
        netctx->pending_offset = 0;
        netctx->pending_len = 0;

        /* 连接到服务器 */
        err = netconn_connect(netctx->conn, &server_ip, port);
        
        if (err == ERR_OK) {
            netctx->connected = 1;
            netctx->remote_addr = server_ip;
            netctx->remote_port = port;
            printf("[NET] TCP连接成功\n");
            return 0;
        }
        
        printf("[NET] 连接失败: %d\n", err);
        
        /* 连接失败，必须删除并重新创建netconn */
        netconn_delete(netctx->conn);
        netctx->conn = NULL;
        
        if (err == ERR_INPROGRESS) {
            /* 非阻塞连接正在进行，等待一会再重试 */
            printf("[NET] 连接进行中，等待重试...\n");
            sys_msleep(1000);
        }
        
        retry_count++;
    }
    
    printf("[NET] 连接失败，已达最大重试次数\n");
    return MBEDTLS_ERR_NET_CONNECT_FAILED;
}

/**
 * @brief 关闭TCP连接
 */
static void netconn_close_conn(mbedtls_netconn_context_t *netctx)
{
    if (netctx) {
        if (netctx->pending_buf != NULL) {
            netbuf_delete(netctx->pending_buf);
            netctx->pending_buf = NULL;
            netctx->pending_offset = 0;
            netctx->pending_len = 0;
        }
        
        if (netctx->conn) {
            netconn_close(netctx->conn);
            netconn_delete(netctx->conn);
            netctx->conn = NULL;
        }
        netctx->connected = 0;
        printf("[NET] 连接已关闭\n");
    }
}

/*=============================================================================
 * mbedTLS TLS 1.2 客户端实现
 *===========================================================================*/

/**
 * @brief 初始化mbedTLS (TLS 1.2)
 * 
 * 注意：这些都是纯内存操作，可以在任何线程执行
 */
static int mbedtls_tls_init(tls_client_ctx_t *ctx)
{
    const char *pers = "tls_client_netconn";
    
    printf("[TLS] 初始化mbedTLS...\n");
    
    /* 初始化mbedTLS相关结构 - 纯内存操作，不需要锁 */
    mbedtls_ssl_init(&ctx->ssl);
    mbedtls_ssl_config_init(&ctx->conf);
    mbedtls_x509_crt_init(&ctx->cacert);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    mbedtls_entropy_init(&ctx->entropy);
    
    /* 设置调试回调 */
    mbedtls_ssl_conf_dbg(&ctx->conf, my_debug, stdout);
    mbedtls_debug_set_threshold(MBEDTLS_DEBUG_LEVEL);
    
    /* 初始化随机数生成器 */
    int ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func,
                                    &ctx->entropy, (const unsigned char *)pers,
                                    strlen(pers));
    if (ret != 0) {
        printf("[TLS] ctr_drbg初始化失败: -0x%x\n", -ret);
        return ret;
    }
    
    /* 设置默认配置 (TLS 1.2) */
    ret = mbedtls_ssl_config_defaults(&ctx->conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        printf("[TLS] ssl_config_defaults失败: -0x%x\n", -ret);
        return ret;
    }
    // 在 mbedtls_tls_init 函数中，在 ssl_config_defaults 之后添加
    mbedtls_ssl_conf_extended_master_secret(&ctx->conf, 0);  // 禁用 EMS
    mbedtls_ssl_conf_encrypt_then_mac(&ctx->conf, MBEDTLS_SSL_ETM_DISABLED);
    
    /* 设置TLS版本为1.2 */
    mbedtls_ssl_conf_max_version(&ctx->conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                 MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_min_version(&ctx->conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                 MBEDTLS_SSL_MINOR_VERSION_3);
    
    /* 设置RNG回调 */
    mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
    
    /* 设置端点（客户端） */
    mbedtls_ssl_conf_endpoint(&ctx->conf, MBEDTLS_SSL_IS_CLIENT);
    
    /* 设置传输类型（TCP） */
    mbedtls_ssl_conf_transport(&ctx->conf, MBEDTLS_SSL_TRANSPORT_STREAM);

    // 在 mbedtls_ssl_config_defaults 之后添加
    // 禁用可能引起问题的扩展
    mbedtls_ssl_conf_session_tickets(&ctx->conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);

    // 禁用所有扩展
    mbedtls_ssl_conf_renegotiation(&ctx->conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);

    // 限制加密套件
    int ciphersuites[] = {
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        0
    };
    mbedtls_ssl_conf_ciphersuites(&ctx->conf, ciphersuites);
    
    printf("[TLS] mbedTLS初始化完成\n");
    return 0;
}

/**
 * @brief 加载证书 (用于验证)
 */
static int mbedtls_load_certificates(tls_client_ctx_t *ctx)
{
    int ret;
    
    // 选项1：如果这是测试环境，临时禁用证书验证
    // mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_NONE);
    // printf("[TLS] 警告：证书验证已禁用（仅用于测试）\n");
    // return 0;
    
    // 选项2：如果你有 CA 证书文件，加载它
    ret = mbedtls_x509_crt_parse_file(&ctx->cacert, "certs/ygdy_root_ca_cert.pem");
    if (ret < 0) {
        printf("[TLS] 加载CA证书失败: -0x%x\n", -ret);
        return ret;
    }

#if mTLS_MODE
    // 选项3：如果是双证模式，还需加载客户端证书与私钥
    ret = mbedtls_x509_crt_parse_file(&ctx->clicert, "certs/ygdy_client.crt");
    if (ret < 0) {
        printf("[TLS] 加载客户端证书失败: -0x%x\n", -ret);
        return ret;
    }
    ret = mbedtls_pk_parse_keyfile(&ctx->pkey, "certs/ygdy_client_key.pem", NULL);
    if (ret < 0) {
        printf("[TLS] 加载客户端私钥失败: -0x%x\n", -ret);
        return ret;
    }
    
    /* 设置客户端自己的证书和私钥 - 这是双向认证的关键！ */
    ret = mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->clicert, &ctx->pkey);
    if (ret != 0) {
        printf("[TLS] 设置客户端证书失败: -0x%x\n", -ret);
        return ret;
    }
#endif /* mTLS_MODE */

    /* 设置CA证书链（用于验证服务器）*/
    mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->cacert, NULL);
    /* 设置验证模式：要求服务器提供有效证书 */
    mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    printf("[TLS] CA证书加载完成\n");
    return 0;
}

/**
 * @brief 执行TLS握手
 */
static int mbedtls_tls_handshake(tls_client_ctx_t *ctx)
{
    int ret;
    
    printf("[TLS] 开始TLS握手...\n");
    
    /* 设置SSL上下文 - 绑定I/O回调函数 */
    mbedtls_ssl_set_bio(&ctx->ssl, &ctx->netconn_ctx,
                        netconn_send_cb,    /* 发送回调 */
                        netconn_recv_cb,    /* 接收回调 */
                        NULL);              /* 不需要recv_timeout */
    
    /* 执行TLS握手 */
    while ((ret = mbedtls_ssl_handshake(&ctx->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_strerror(ret, ctx->error_buf, sizeof(ctx->error_buf));
            printf("[TLS] 握手失败: -0x%x (%s)\n", -ret, ctx->error_buf);
            return ret;
        }
        /* 等待I/O可操作 - 短暂等待，让出CPU */
        sys_msleep(10);
    }
    
    printf("[TLS] 握手成功!\n");
    
    /* 验证服务器证书 */
    uint32_t flags = mbedtls_ssl_get_verify_result(&ctx->ssl);
    if (flags != 0) {
        printf("[TLS] 证书验证失败:\n");
        if (flags & MBEDTLS_X509_BADCERT_EXPIRED)    printf("  - 证书已过期\n");
        if (flags & MBEDTLS_X509_BADCERT_REVOKED)    printf("  - 证书已被吊销\n");
        if (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH)printf("  - 主机名不匹配\n");
        if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) printf("  - 证书不受信任\n");
        /* 对于测试环境，可以选择忽略 */
    } else {
        printf("[TLS] 证书验证通过\n");
    }
    
    ctx->handshake_done = 1;
    return 0;
}

