/**
 * @file    gostc_lwip_intercept.c
 * @brief   lwIP拦截模块实现
 * @author  Kilo Code
 * @date    2026-03-07
 * @version 1.0.0
 * 
 * @note    通过函数指针重定向实现lwIP TCP/UDP/DNS拦截
 * @warning 需要lwIP 2.0.3版本支持
 */

#include "gostc.h"
#include "gostc_err.h"
#include "gostc_os.h"
#include "gostc_conn.h"
#include <string.h>

/* lwIP头文件 */
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/dns.h"
#include "lwip/ip.h"

/* 模块内部全局变量 */
static bool g_intercept_initialized = false;
static os_mutex_handle_t g_intercept_mutex = NULL;

/* 原始lwIP函数指针 */
static err_t (*g_original_tcp_connect)(struct tcp_pcb *pcb, const ip_addr_t *ipaddr,
                                      u16_t port, tcp_connected_fn connected) = NULL;
static err_t (*g_original_tcp_write)(struct tcp_pcb *pcb, const void *dataptr, u16_t len,
                                    u8_t apiflags) = NULL;
static err_t (*g_original_tcp_output)(struct tcp_pcb *pcb) = NULL;
static err_t (*g_original_udp_send)(struct udp_pcb *pcb, struct pbuf *p) = NULL;
static err_t (*g_original_udp_sendto)(struct udp_pcb *pcb, struct pbuf *p,
                                     const ip_addr_t *dst_ip, u16_t dst_port) = NULL;
static err_t (*g_original_dns_gethostbyname)(const char *hostname, ip_addr_t *addr,
                                           dns_found_callback found, void *callback_arg) = NULL;

/* 内部函数声明 */
static err_t _intercept_tcp_connect(struct tcp_pcb *pcb, const ip_addr_t *ipaddr,
                                   u16_t port, tcp_connected_fn connected);
static err_t _intercept_tcp_write(struct tcp_pcb *pcb, const void *dataptr, u16_t len,
                                 u8_t apiflags);
static err_t _intercept_tcp_output(struct tcp_pcb *pcb);
static err_t _intercept_udp_send(struct udp_pcb *pcb, struct pbuf *p);
static err_t _intercept_udp_sendto(struct udp_pcb *pcb, struct pbuf *p,
                                  const ip_addr_t *dst_ip, u16_t dst_port);
static err_t _intercept_dns_gethostbyname(const char *hostname, ip_addr_t *addr,
                                        dns_found_callback found, void *callback_arg);
static int32_t _should_intercept_connection(uint32_t remote_ip, uint16_t remote_port,
                                          uint8_t protocol);
static int32_t _create_proxy_connection(void *pcb, uint8_t protocol,
                                       uint32_t local_ip, uint16_t local_port,
                                       uint32_t remote_ip, uint16_t remote_port);

/* 内部函数实现 */

/**
 * @brief   拦截的TCP连接函数
 */
static err_t _intercept_tcp_connect(struct tcp_pcb *pcb, const ip_addr_t *ipaddr,
                                   u16_t port, tcp_connected_fn connected)
{
    if (pcb == NULL || ipaddr == NULL) {
        return ERR_ARG;
    }
    
    /* 检查是否需要拦截 */
    uint32_t remote_ip = ipaddr->addr;
    uint16_t remote_port = port;
    
    int32_t intercept = _should_intercept_connection(remote_ip, remote_port, PROTOCOL_TCP);
    if (intercept < 0) {
        /* 不需要拦截，调用原始函数 */
        if (g_original_tcp_connect != NULL) {
            return g_original_tcp_connect(pcb, ipaddr, port, connected);
        }
        return ERR_VAL;
    }
    
    /* 需要拦截，创建代理连接 */
    uint32_t local_ip = 0; /* TODO: 获取本地IP */
    uint16_t local_port = pcb->local_port;
    
    int32_t ret = _create_proxy_connection(pcb, PROTOCOL_TCP, local_ip, local_port,
                                          remote_ip, remote_port);
    if (ret != GOSTC_OK) {
        /* 代理连接失败，回退到原始连接 */
        if (g_original_tcp_connect != NULL) {
            return g_original_tcp_connect(pcb, ipaddr, port, connected);
        }
        return ERR_VAL;
    }
    
    /* 代理连接已建立，返回成功 */
    /* TODO: 设置连接状态和回调函数 */
    
    return ERR_OK;
}

/**
 * @brief   拦截的TCP写函数
 */
static err_t _intercept_tcp_write(struct tcp_pcb *pcb, const void *dataptr, u16_t len,
                                 u8_t apiflags)
{
    if (pcb == NULL || dataptr == NULL || len == 0) {
        return ERR_ARG;
    }
    
    /* 查找连接 */
    gostc_conn_ctx_t *conn = gostc_conn_find_by_pcb(pcb);
    if (conn == NULL) {
        /* 不是代理连接，调用原始函数 */
        if (g_original_tcp_write != NULL) {
            return g_original_tcp_write(pcb, dataptr, len, apiflags);
        }
        return ERR_VAL;
    }
    
    /* 是代理连接，通过代理发送数据 */
    /* TODO: 实现代理数据转发 */
    
    /* 更新统计信息 */
    gostc_conn_update_stats(conn, len, 0);
    
    /* 模拟成功发送 */
    return ERR_OK;
}

/**
 * @brief   拦截的TCP输出函数
 */
static err_t _intercept_tcp_output(struct tcp_pcb *pcb)
{
    if (pcb == NULL) {
        return ERR_ARG;
    }
    
    /* 查找连接 */
    gostc_conn_ctx_t *conn = gostc_conn_find_by_pcb(pcb);
    if (conn == NULL) {
        /* 不是代理连接，调用原始函数 */
        if (g_original_tcp_output != NULL) {
            return g_original_tcp_output(pcb);
        }
        return ERR_VAL;
    }
    
    /* 是代理连接，通过代理输出 */
    /* TODO: 实现代理输出 */
    
    return ERR_OK;
}

/**
 * @brief   拦截的UDP发送函数
 */
static err_t _intercept_udp_send(struct udp_pcb *pcb, struct pbuf *p)
{
    if (pcb == NULL || p == NULL) {
        return ERR_ARG;
    }
    
    /* 检查是否需要拦截 */
    uint32_t remote_ip = pcb->remote_ip.addr;
    uint16_t remote_port = pcb->remote_port;
    
    int32_t intercept = _should_intercept_connection(remote_ip, remote_port, PROTOCOL_UDP);
    if (intercept < 0) {
        /* 不需要拦截，调用原始函数 */
        if (g_original_udp_send != NULL) {
            return g_original_udp_send(pcb, p);
        }
        return ERR_VAL;
    }
    
    /* 需要拦截，创建代理连接（如果尚未创建） */
    uint32_t local_ip = 0; /* TODO: 获取本地IP */
    uint16_t local_port = pcb->local_port;
    
    /* 查找或创建连接 */
    gostc_conn_ctx_t *conn = gostc_conn_find_by_pcb(pcb);
    if (conn == NULL) {
        int32_t ret = _create_proxy_connection(pcb, PROTOCOL_UDP, local_ip, local_port,
                                              remote_ip, remote_port);
        if (ret != GOSTC_OK) {
            /* 代理连接失败，回退到原始发送 */
            if (g_original_udp_send != NULL) {
                return g_original_udp_send(pcb, p);
            }
            return ERR_VAL;
        }
        
        conn = gostc_conn_find_by_pcb(pcb);
        if (conn == NULL) {
            return ERR_VAL;
        }
    }
    
    /* 通过代理发送UDP数据 */
    /* TODO: 实现UDP代理转发 */
    
    /* 更新统计信息 */
    gostc_conn_update_stats(conn, p->tot_len, 0);
    
    /* 释放pbuf */
    pbuf_free(p);
    
    return ERR_OK;
}

/**
 * @brief   拦截的UDP发送到指定地址函数
 */
static err_t _intercept_udp_sendto(struct udp_pcb *pcb, struct pbuf *p,
                                  const ip_addr_t *dst_ip, u16_t dst_port)
{
    if (pcb == NULL || p == NULL || dst_ip == NULL) {
        return ERR_ARG;
    }
    
    /* 检查是否需要拦截 */
    uint32_t remote_ip = dst_ip->addr;
    uint16_t remote_port = dst_port;
    
    int32_t intercept = _should_intercept_connection(remote_ip, remote_port, PROTOCOL_UDP);
    if (intercept < 0) {
        /* 不需要拦截，调用原始函数 */
        if (g_original_udp_sendto != NULL) {
            return g_original_udp_sendto(pcb, p, dst_ip, dst_port);
        }
        return ERR_VAL;
    }
    
    /* 需要拦截，创建代理连接 */
    uint32_t local_ip = 0; /* TODO: 获取本地IP */
    uint16_t local_port = pcb->local_port;
    
    /* 查找或创建连接 */
    gostc_conn_ctx_t *conn = gostc_conn_find_by_pcb(pcb);
    if (conn == NULL) {
        int32_t ret = _create_proxy_connection(pcb, PROTOCOL_UDP, local_ip, local_port,
                                              remote_ip, remote_port);
        if (ret != GOSTC_OK) {
            /* 代理连接失败，回退到原始发送 */
            if (g_original_udp_sendto != NULL) {
                return g_original_udp_sendto(pcb, p, dst_ip, dst_port);
            }
            return ERR_VAL;
        }
        
        conn = gostc_conn_find_by_pcb(pcb);
        if (conn == NULL) {
            return ERR_VAL;
        }
    }
    
    /* 通过代理发送UDP数据 */
    /* TODO: 实现UDP代理转发 */
    
    /* 更新统计信息 */
    gostc_conn_update_stats(conn, p->tot_len, 0);
    
    /* 释放pbuf */
    pbuf_free(p);
    
    return ERR_OK;
}

/**
 * @brief   拦截的DNS查询函数
 */
static err_t _intercept_dns_gethostbyname(const char *hostname, ip_addr_t *addr,
                                        dns_found_callback found, void *callback_arg)
{
    if (hostname == NULL || addr == NULL) {
        return ERR_ARG;
    }
    
    /* 检查域名是否在白名单中 */
    /* TODO: 调用DNS过滤器 */
    
    /* 如果域名被阻止，返回错误 */
    /* if (blocked) {
        return ERR_VAL;
    } */
    
    /* 调用原始DNS函数 */
    if (g_original_dns_gethostbyname != NULL) {
        return g_original_dns_gethostbyname(hostname, addr, found, callback_arg);
    }
    
    return ERR_VAL;
}

/**
 * @brief   检查是否需要拦截连接
 */
static int32_t _should_intercept_connection(uint32_t remote_ip, uint16_t remote_port,
                                          uint8_t protocol)
{
    /* TODO: 根据配置规则检查是否需要拦截 */
    /* 1. 检查代理规则 */
    /* 2. 检查TLS规则 */
    /* 3. 返回拦截决定 */
    
    /* 临时实现：总是拦截 */
    (void)remote_ip;
    (void)remote_port;
    (void)protocol;
    
    return GOSTC_OK;
}

/**
 * @brief   创建代理连接
 */
static int32_t _create_proxy_connection(void *pcb, uint8_t protocol,
                                       uint32_t local_ip, uint16_t local_port,
                                       uint32_t remote_ip, uint16_t remote_port)
{
    /* 创建连接记录 */
    uint32_t conn_id = gostc_conn_create(pcb, protocol, local_ip, local_port,
                                        remote_ip, remote_port);
    if (conn_id == INVALID_CONNECTION_ID) {
        return GOSTC_ERROR_CONN;
    }
    
    /* 查找连接 */
    gostc_conn_ctx_t *conn = gostc_conn_find_by_id(conn_id);
    if (conn == NULL) {
        return GOSTC_ERROR_CONN_NOT_FOUND;
    }
    
    /* 设置使用代理 */
    int32_t ret = gostc_conn_update_proxy_info(conn, 1, 0, -1, NULL);
    if (ret != GOSTC_OK) {
        gostc_conn_delete(conn_id);
        return ret;
    }
    
    /* 更新连接状态 */
    gostc_conn_update_state(conn, CONN_STATE_CONNECTING);
    
    /* TODO: 实际建立代理连接 */
    
    return GOSTC_OK;
}

/* 公共函数实现 */

int32_t gostc_intercept_init(void)
{
    if (g_intercept_initialized) {
        return GOSTC_ERROR_ALREADY_INITIALIZED;
    }
    
    /* 创建互斥锁 */
    os_error_e os_err = os_mutex_create(&g_intercept_mutex);
    if (os_err != OS_OK) {
        return GOSTC_ERROR_OS_MUTEX_CREATE_FAILED;
    }
    
    /* 保存原始函数指针 */
    /* 注意：这里需要获取lwIP函数的实际地址 */
    /* 由于我们无法直接获取函数指针，这里使用条件编译或运行时查找 */
    
    /* 临时实现：设置标志 */
    g_intercept_initialized = true;
    
    return GOSTC_OK;
}

int32_t gostc_intercept_deinit(void)
{
    if (!g_intercept_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* 恢复原始函数指针 */
    /* TODO: 恢复lwIP函数 */
    
    /* 删除互斥锁 */
    if (g_intercept_mutex != NULL) {
        os_mutex_delete(g_intercept_mutex);
        g_intercept_mutex = NULL;
    }
    
    g_intercept_initialized = false;
    
    return GOSTC_OK;
}

int32_t gostc_intercept_install_hooks(void)
{
    if (!g_intercept_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    os_mutex_lock(g_intercept_mutex, OS_WAIT_FOREVER);
    
    /* 安装拦截钩子 */
    /* 注意：这里需要实际替换lwIP函数指针 */
    /* 由于平台依赖性，这里只做标记 */
    
    os_mutex_unlock(g_intercept_mutex);
    
    return GOSTC_OK;
}

int32_t gostc_intercept_remove_hooks(void)
{
    if (!g_intercept_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    os_mutex_lock(g_intercept_mutex, OS_WAIT_FOREVER);
    
    /* 移除拦截钩子 */
    /* 恢复原始函数指针 */
    
    os_mutex_unlock(g_intercept_mutex);
    
    return GOSTC_OK;
}

int32_t gostc_intercept_get_status(void)
{
    if (!g_intercept_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* 返回拦截状态 */
    /* TODO: 检查各个钩子是否已安装 */
    
    return GOSTC_OK;
}

int32_t gostc_intercept_enable(uint8_t enable)
{
    if (!g_intercept_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    os_mutex_lock(g_intercept_mutex, OS_WAIT_FOREVER);
    
    if (enable) {
        /* 启用拦截 */
        gostc_intercept_install_hooks();
    } else {
        /* 禁用拦截 */
        gostc_intercept_remove_hooks();
    }
    
    os_mutex_unlock(g_intercept_mutex);
    
    return GOSTC_OK;
}

int32_t gostc_intercept_set_callback(uint8_t hook_type, void *callback)
{
    if (!g_intercept_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* TODO: 设置自定义回调函数 */
    (void)hook_type;
    (void)callback;
    
    return GOSTC_ERROR_NOT_SUPPORTED;
}

int32_t gostc_intercept_get_stats(uint32_t *tcp_intercepts, uint32_t *udp_intercepts,
                                 uint32_t *dns_intercepts, uint32_t *total_intercepts)
{
    if (!g_intercept_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* TODO: 实现统计信息 */
    if (tcp_intercepts != NULL) {
        *tcp_intercepts = 0;
    }
    
    if (udp_intercepts != NULL) {
        *udp_intercepts = 0;
    }
    
    if (dns_intercepts != NULL) {
        *dns_intercepts = 0;
    }
    
    if (total_intercepts != NULL) {
        *total_intercepts = 0;
    }
    
    return GOSTC_OK;
}

/* 内部函数实现 */

/**
 * @brief   初始化拦截上下文
 */
static int32_t _intercept_context_init(void)
{
    if (g_intercept_ctx != NULL) {
        return GOSTC_ERROR_ALREADY_INITIALIZED;
    }
    
    /* 分配上下文内存 */
    g_intercept_ctx = (gostc_intercept_ctx_t *)os_malloc(sizeof(gostc_intercept_ctx_t));
    if (g_intercept_ctx == NULL) {
        return GOSTC_ERROR_NO_MEMORY;
    }
    
    /* 初始化上下文 */
    memset(g_intercept_ctx, 0, sizeof(gostc_intercept_ctx_t));
    
    /* 初始化互斥锁 */
    if (os_mutex_create(&g_intercept_ctx->mutex) != OS_OK) {
        os_free(g_intercept_ctx);
        g_intercept_ctx = NULL;
        return GOSTC_ERROR_NO_MEMORY;
    }
    
    /* 初始化统计信息 */
    g_intercept_ctx->stats.start_time = os_get_tick_count();
    
    return GOSTC_OK;
}

/**
 * @brief   检查是否需要拦截连接
 */
static bool _should_intercept_connection(uint32_t dest_ip, uint16_t dest_port, uint8_t protocol)
{
    /* 简化实现：检查配置规则 */
    /* 在实际实现中，这里应该查询配置规则 */
    
    (void)dest_ip;
    (void)dest_port;
    (void)protocol;
    
    /* 默认返回true进行拦截 */
    return true;
}

/**
 * @brief   处理TCP连接拦截
 */
static int32_t _handle_tcp_intercept(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{
    if (!g_intercept_initialized || g_intercept_ctx == NULL) {
        return ERR_OK; /* 未初始化，不拦截 */
    }
    
    /* 检查是否需要拦截 */
    if (!_should_intercept_connection(ipaddr->addr, port, IP_PROTO_TCP)) {
        return ERR_OK; /* 不需要拦截 */
    }
    
    /* 获取互斥锁 */
    if (os_mutex_lock(g_intercept_ctx->mutex, 100) != OS_OK) {
        return ERR_OK; /* 获取锁失败，不拦截 */
    }
    
    /* 更新统计信息 */
    g_intercept_ctx->stats.tcp_intercepts++;
    g_intercept_ctx->stats.total_intercepts++;
    
    /* 记录日志 */
    gostc_log_debug("[INTERCEPT] TCP连接拦截: %lu.%lu.%lu.%lu:%u", 
                  (pcb->remote_ip.addr >> 24) & 0xFF,
                  (pcb->remote_ip.addr >> 16) & 0xFF,
                  (pcb->remote_ip.addr >> 8) & 0xFF,
                  pcb->remote_ip.addr & 0xFF,
                  pcb->remote_port);
    
    /* 释放互斥锁 */
    os_mutex_unlock(g_intercept_ctx->mutex);
    
    /* 这里应该实现实际的代理连接逻辑 */
    /* 简化实现：返回错误码表示连接被拒绝 */
    return ERR_ABRT; /* 连接中止 */
}

/**
 * @brief   处理UDP数据包拦截
 */
static int32_t _handle_udp_intercept(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
    if (!g_intercept_initialized || g_intercept_ctx == NULL) {
        return ERR_OK; /* 未初始化，不拦截 */
    }
    
    /* 检查是否需要拦截 */
    if (!_should_intercept_connection(addr->addr, port, IP_PROTO_UDP)) {
        return ERR_OK; /* 不需要拦截 */
    }
    
    /* 获取互斥锁 */
    if (os_mutex_lock(g_intercept_ctx->mutex, 100) != OS_OK) {
        return ERR_OK; /* 获取锁失败，不拦截 */
    }
    
    /* 更新统计信息 */
    g_intercept_ctx->stats.udp_intercepts++;
    g_intercept_ctx->stats.total_intercepts++;
    
    /* 记录日志 */
    gostc_log_debug("[INTERCEPT] UDP数据包拦截: %lu.%lu.%lu.%lu:%u, 长度: %u", 
                  (addr->addr >> 24) & 0xFF,
                  (addr->addr >> 16) & 0xFF,
                  (addr->addr >> 8) & 0xFF,
                  addr->addr & 0xFF,
                  port,
                  p->tot_len);
    
    /* 释放互斥锁 */
    os_mutex_unlock(g_intercept_ctx->mutex);
    
    /* 这里应该实现实际的代理转发逻辑 */
    /* 简化实现：丢弃数据包 */
    pbuf_free(p);
    return ERR_OK;
}

/**
 * @brief   处理DNS查询拦截
 */
static int32_t _handle_dns_intercept(const char *name, ip_addr_t *addr)
{
    if (!g_intercept_initialized || g_intercept_ctx == NULL) {
        return ERR_OK; /* 未初始化，不拦截 */
    }
    
    /* 获取互斥锁 */
    if (os_mutex_lock(g_intercept_ctx->mutex, 100) != OS_OK) {
        return ERR_OK; /* 获取锁失败，不拦截 */
    }
    
    /* 更新统计信息 */
    g_intercept_ctx->stats.dns_intercepts++;
    g_intercept_ctx->stats.total_intercepts++;
    
    /* 记录日志 */
    gostc_log_debug("[INTERCEPT] DNS查询拦截: %s", name);
    
    /* 释放互斥锁 */
    os_mutex_unlock(g_intercept_ctx->mutex);
    
    /* 调用DNS过滤模块 */
    int32_t dns_result = gostc_dns_check(name);
    if (dns_result != GOSTC_OK) {
        /* DNS被拒绝 */
        gostc_log_warn("[INTERCEPT] DNS查询被拒绝: %s", name);
        return ERR_VAL; /* 返回错误值 */
    }
    
    /* DNS允许，继续正常解析 */
    return ERR_OK;
}

/* 文件结束 */
