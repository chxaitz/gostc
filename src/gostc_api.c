/**
 * @file    gostc_api.c
 * @brief   通信代理API接口模块实现
 * @author  Kilo Code
 * @date    2026-03-07
 * @version 1.0.0
 * 
 * @note    提供通信代理组件的公共API接口
 * @warning API函数是线程安全的
 */

#include "gostc.h"
#include "gostc_err.h"
#include "gostc_os.h"
#include "gostc_cfg.h"
#include "gostc_conn.h"
#include "gostc_tls.h"
#include "gostc_dns.h"
#include <string.h>

/* 模块内部全局变量 */
static bool g_api_initialized = false;
static os_mutex_handle_t g_api_mutex = NULL;

/* 内部函数声明 */
static int32_t _api_initialize_modules(void);
static int32_t _api_deinitialize_modules(void);

/* 内部函数实现 */

/**
 * @brief   初始化所有模块
 */
static int32_t _api_initialize_modules(void)
{
    int32_t ret;
    
    /* 初始化错误处理系统 */
    ret = gostc_error_init();
    if (ret != GOSTC_OK) {
        return ret;
    }
    
    /* 初始化配置管理系统 */
    ret = gostc_config_init();
    if (ret != GOSTC_OK) {
        gostc_error_deinit();
        return ret;
    }
    
    /* 初始化连接管理器 */
    ret = gostc_conn_mgr_init(DEFAULT_MAX_CONNECTIONS);
    if (ret != GOSTC_OK) {
        gostc_config_deinit();
        gostc_error_deinit();
        return ret;
    }
    
    /* 初始化DNS过滤器 */
    ret = gostc_dns_init(NULL);
    if (ret != GOSTC_OK) {
        gostc_conn_mgr_deinit();
        gostc_config_deinit();
        gostc_error_deinit();
        return ret;
    }
    
    /* 初始化TLS引擎 */
    ret = gostc_tls_init(NULL);
    if (ret != GOSTC_OK) {
        gostc_dns_deinit();
        gostc_conn_mgr_deinit();
        gostc_config_deinit();
        gostc_error_deinit();
        return ret;
    }
    
    /* 初始化lwIP拦截器 */
    ret = gostc_intercept_init();
    if (ret != GOSTC_OK) {
        gostc_tls_deinit();
        gostc_dns_deinit();
        gostc_conn_mgr_deinit();
        gostc_config_deinit();
        gostc_error_deinit();
        return ret;
    }
    
    return GOSTC_OK;
}

/**
 * @brief   反初始化所有模块
 */
static int32_t _api_deinitialize_modules(void)
{
    int32_t ret = GOSTC_OK;
    int32_t temp_ret;
    
    /* 反初始化lwIP拦截器 */
    temp_ret = gostc_intercept_deinit();
    if (temp_ret != GOSTC_OK) {
        ret = temp_ret;
    }
    
    /* 反初始化TLS引擎 */
    temp_ret = gostc_tls_deinit();
    if (temp_ret != GOSTC_OK) {
        ret = temp_ret;
    }
    
    /* 反初始化DNS过滤器 */
    temp_ret = gostc_dns_deinit();
    if (temp_ret != GOSTC_OK) {
        ret = temp_ret;
    }
    
    /* 反初始化连接管理器 */
    temp_ret = gostc_conn_mgr_deinit();
    if (temp_ret != GOSTC_OK) {
        ret = temp_ret;
    }
    
    /* 反初始化配置管理系统 */
    temp_ret = gostc_config_deinit();
    if (temp_ret != GOSTC_OK) {
        ret = temp_ret;
    }
    
    /* 反初始化错误处理系统 */
    temp_ret = gostc_error_deinit();
    if (temp_ret != GOSTC_OK) {
        ret = temp_ret;
    }
    
    return ret;
}

/* 公共函数实现 */

int32_t gostc_init(const gostc_config_t *config)
{
    if (g_api_initialized) {
        return GOSTC_ERROR_ALREADY_INITIALIZED;
    }
    
    /* 创建API互斥锁 */
    os_error_e os_err = os_mutex_create(&g_api_mutex);
    if (os_err != OS_OK) {
        return GOSTC_ERROR_OS_MUTEX_CREATE_FAILED;
    }
    
    os_mutex_lock(g_api_mutex, OS_WAIT_FOREVER);
    
    /* 初始化所有模块 */
    int32_t ret = _api_initialize_modules();
    if (ret != GOSTC_OK) {
        os_mutex_unlock(g_api_mutex);
        os_mutex_delete(g_api_mutex);
        g_api_mutex = NULL;
        return ret;
    }
    
    /* 应用配置（如果提供了配置） */
    if (config != NULL) {
        ret = gostc_config_apply(config);
        if (ret != GOSTC_OK) {
            /* 配置应用失败，但继续初始化 */
            gostc_error_record(ret, "gostc_api", "gostc_init", __LINE__, 
                             "Failed to apply initial config");
        }
    }
    
    /* 启用lwIP拦截 */
    ret = gostc_intercept_enable(1);
    if (ret != GOSTC_OK) {
        gostc_error_record(ret, "gostc_api", "gostc_init", __LINE__,
                         "Failed to enable intercept hooks");
    }
    
    g_api_initialized = true;
    
    os_mutex_unlock(g_api_mutex);
    
    return GOSTC_OK;
}

int32_t gostc_deinit(void)
{
    if (!g_api_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    os_mutex_lock(g_api_mutex, OS_WAIT_FOREVER);
    
    /* 禁用lwIP拦截 */
    gostc_intercept_enable(0);
    
    /* 反初始化所有模块 */
    int32_t ret = _api_deinitialize_modules();
    
    g_api_initialized = false;
    
    os_mutex_unlock(g_api_mutex);
    
    /* 删除API互斥锁 */
    if (g_api_mutex != NULL) {
        os_mutex_delete(g_api_mutex);
        g_api_mutex = NULL;
    }
    
    return ret;
}

void gostc_get_version(uint8_t *major, uint8_t *minor, uint8_t *patch)
{
    if (major != NULL) {
        *major = GOSTC_VERSION_MAJOR;
    }
    
    if (minor != NULL) {
        *minor = GOSTC_VERSION_MINOR;
    }
    
    if (patch != NULL) {
        *patch = GOSTC_VERSION_PATCH;
    }
}

int32_t gostc_get_status(void)
{
    if (!g_api_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* 检查各个模块状态 */
    int32_t status = GOSTC_OK;
    
    /* TODO: 检查各个模块的状态 */
    
    return status;
}

int32_t gostc_reload_config(const gostc_config_t *config)
{
    if (!g_api_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    GOSTC_CHECK_PTR(config);
    
    os_mutex_lock(g_api_mutex, OS_WAIT_FOREVER);
    
    /* 应用新配置 */
    int32_t ret = gostc_config_apply(config);
    
    os_mutex_unlock(g_api_mutex);
    
    return ret;
}

int32_t gostc_get_config(gostc_config_t *config)
{
    if (!g_api_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    GOSTC_CHECK_PTR(config);
    
    return gostc_config_load_default(config);
}

int32_t gostc_reset_stats(void)
{
    if (!g_api_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    os_mutex_lock(g_api_mutex, OS_WAIT_FOREVER);
    
    /* 重置各个模块的统计信息 */
    gostc_error_reset_stats();
    /* TODO: 重置其他模块的统计信息 */
    
    os_mutex_unlock(g_api_mutex);
    
    return GOSTC_OK;
}

int32_t gostc_get_stats(runtime_stats_t *stats)
{
    if (!g_api_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    GOSTC_CHECK_PTR(stats);
    
    /* TODO: 收集各个模块的统计信息 */
    memset(stats, 0, sizeof(runtime_stats_t));
    
    return GOSTC_OK;
}

/* 高级API函数 */

int32_t gostc_add_proxy_rule(uint32_t dest_ip, uint32_t dest_mask, uint16_t dest_port,
                            uint8_t protocol, uint8_t action, uint8_t use_tls)
{
    if (!g_api_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* TODO: 实现代理规则添加 */
    (void)dest_ip;
    (void)dest_mask;
    (void)dest_port;
    (void)protocol;
    (void)action;
    (void)use_tls;
    
    return GOSTC_ERROR_NOT_SUPPORTED;
}

int32_t gostc_remove_proxy_rule(uint32_t rule_id)
{
    if (!g_api_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* TODO: 实现代理规则删除 */
    (void)rule_id;
    
    return GOSTC_ERROR_NOT_SUPPORTED;
}

int32_t gostc_add_dns_rule(const char *pattern, uint8_t action, uint8_t match_type)
{
    if (!g_api_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    if (pattern == NULL) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    uint32_t rule_id = gostc_dns_add_rule(pattern, action, match_type);
    if (rule_id == 0) {
        return GOSTC_ERROR_DNS;
    }
    
    return GOSTC_OK;
}

int32_t gostc_remove_dns_rule(uint32_t rule_id)
{
    if (!g_api_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    return gostc_dns_delete_rule(rule_id);
}

int32_t gostc_query_domain(const char *domain, uint32_t *ip_addr, uint8_t *action)
{
    if (!g_api_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    if (domain == NULL) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    dns_query_result_t result;
    int32_t ret = gostc_dns_query(domain, &result);
    if (ret != GOSTC_OK) {
        return ret;
    }
    
    if (ip_addr != NULL) {
        *ip_addr = result.ip_addr;
    }
    
    if (action != NULL) {
        *action = result.action;
    }
    
    return GOSTC_OK;
}

int32_t gostc_get_connection_count(uint32_t *total, uint32_t *active, uint32_t *proxy)
{
    if (!g_api_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* TODO: 实现连接计数获取 */
    if (total != NULL) {
        *total = 0;
    }
    
    if (active != NULL) {
        *active = 0;
    }
    
    if (proxy != NULL) {
        *proxy = 0;
    }
    
    return GOSTC_OK;
}

int32_t gostc_get_tls_stats(uint32_t *handshakes, uint32_t *success, uint32_t *failed,
                           uint64_t *encrypted, uint64_t *decrypted)
{
    if (!g_api_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    gostc_tls_ctx_t stats;
    int32_t ret = gostc_tls_get_stats(&stats);
    if (ret != GOSTC_OK) {
        return ret;
    }
    
    if (handshakes != NULL) {
        *handshakes = stats.handshake_count;
    }
    
    if (success != NULL) {
        *success = stats.handshake_success;
    }
    
    if (failed != NULL) {
        *failed = stats.handshake_failed;
    }
    
    if (encrypted != NULL) {
        *encrypted = stats.bytes_encrypted;
    }
    
    if (decrypted != NULL) {
        *decrypted = stats.bytes_decrypted;
    }
    
    return GOSTC_OK;
}

int32_t gostc_enable_feature(uint32_t feature, uint8_t enable)
{
    if (!g_api_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    int32_t ret = GOSTC_OK;
    
    switch (feature) {
        case 0: /* DNS过滤 */
            /* TODO: 启用/禁用DNS过滤 */
            break;
            
        case 1: /* TLS加密 */
            /* TODO: 启用/禁用TLS加密 */
            break;
            
        case 2: /* 代理功能 */
            /* TODO: 启用/禁用代理功能 */
            break;
            
        case 3: /* 拦截功能 */
            ret = gostc_intercept_enable(enable);
            break;
            
        default:
            ret = GOSTC_ERROR_NOT_SUPPORTED;
    }
    
    return ret;
}

int32_t gostc_get_last_error(char *buffer, uint32_t size)
{
    if (buffer == NULL || size == 0) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    gostc_error_info_t error_info;
    int32_t ret = gostc_error_get_last(&error_info);
    if (ret != GOSTC_OK) {
        return ret;
    }
    
    /* 格式化错误信息 */
    const char *error_str = gostc_error_to_string(error_info.code);
    if (error_str == NULL) {
        error_str = "Unknown error";
    }
    
    snprintf(buffer, size, "[%s] %s: %s (line %u)",
             error_info.module, error_info.function,
             error_info.message ? error_info.message : error_str,
             error_info.line);
    
    buffer[size - 1] = '\0';
    
    return GOSTC_OK;
}

int32_t gostc_perform_diagnostics(void)
{
    if (!g_api_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* TODO: 执行系统诊断 */
    
    return GOSTC_OK;
}