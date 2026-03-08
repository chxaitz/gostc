/**
 * @file    gostc_config_mgr.c
 * @brief   通信代理配置管理模块实现
 * @author  Kilo Code
 * @date    2026-03-07
 * @version 1.0.0
 * 
 * @note    配置采用硬编码方式，支持运行时动态更新
 * @warning 配置验证在应用前进行，无效配置将被拒绝
 */

#include "gostc.h"
#include "gostc_cfg.h"
#include "gostc_err.h"
#include "gostc_os.h"
#include <string.h>

/* 模块内部全局变量 */
static gostc_config_t g_config;                /* 当前配置 */
static gostc_config_t g_default_config;        /* 默认配置 */
static os_mutex_handle_t g_config_mutex = NULL; /* 配置互斥锁 */
static bool g_initialized = false;             /* 初始化标志 */

/* 内部函数声明 */
static int32_t _config_validate_proxy_server(const proxy_server_config_t *config);
static int32_t _config_validate_proxy_rules(const proxy_rules_config_t *config);
static int32_t _config_validate_dns_rules(const dns_rules_config_t *config);
static int32_t _config_validate_tls_rules(const tls_rules_config_t *config);
static int32_t _config_validate_system(const system_config_t *config);
static void _config_set_defaults(gostc_config_t *config);
static uint32_t _config_calculate_checksum(const gostc_config_t *config);

/* 内部函数实现 */

/**
 * @brief   验证代理服务器配置
 */
static int32_t _config_validate_proxy_server(const proxy_server_config_t *config)
{
    GOSTC_CHECK_PTR(config);
    
    /* 检查服务器主机名 */
    if (strlen(config->server_host) == 0) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    /* 检查服务器端口 */
    if (config->server_port == 0 || config->server_port > 65535) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    /* 检查代理类型 */
    if (config->server_type >= PROXY_TYPE_MAX) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    /* 检查认证信息 */
    if (config->auth_required) {
        if (strlen(config->username) == 0 || strlen(config->password) == 0) {
            return GOSTC_ERROR_CONFIG_INVALID;
        }
    }
    
    /* 检查连接参数 */
    if (config->connect_timeout_ms == 0 || config->connect_timeout_ms > 60000) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    return GOSTC_OK;
}

/**
 * @brief   验证代理规则配置
 */
static int32_t _config_validate_proxy_rules(const proxy_rules_config_t *config)
{
    GOSTC_CHECK_PTR(config);
    
    /* 检查规则数量 */
    if (config->rule_count > 0 && config->rules == NULL) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    /* 检查默认动作 */
    if (config->default_action >= ACTION_MAX) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    /* 验证每个规则 */
    proxy_rule_entry_t *rule = config->rules;
    while (rule != NULL) {
        /* 检查协议类型 */
        if (rule->protocol >= PROTOCOL_MAX) {
            return GOSTC_ERROR_CONFIG_INVALID;
        }
        
        /* 检查动作 */
        if (rule->action >= ACTION_MAX) {
            return GOSTC_ERROR_CONFIG_INVALID;
        }
        
        /* 检查端口 */
        if (rule->dest_port > 65535) {
            return GOSTC_ERROR_CONFIG_INVALID;
        }
        
        rule = rule->next;
    }
    
    return GOSTC_OK;
}

/**
 * @brief   验证DNS规则配置
 */
static int32_t _config_validate_dns_rules(const dns_rules_config_t *config)
{
    GOSTC_CHECK_PTR(config);
    
    /* 检查规则数量 */
    if (config->rule_count > 0 && config->rules == NULL) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    /* 检查默认动作 */
    if (config->default_action > 1) { /* 0=ALLOW, 1=DENY */
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    /* 检查缓存配置 */
    if (config->enable_cache) {
        if (config->cache_size == 0 || config->cache_size > 32) { /* DNS_MAX_CACHE_SIZE */
            return GOSTC_ERROR_CONFIG_INVALID;
        }
        if (config->cache_ttl_ms == 0 || config->cache_ttl_ms > 3600000) {
            return GOSTC_ERROR_CONFIG_INVALID;
        }
    }
    
    /* 验证每个规则 */
    dns_rule_entry_t *rule = config->rules;
    while (rule != NULL) {
        /* 检查模式长度 */
        if (strlen(rule->pattern) == 0 || strlen(rule->pattern) >= MAX_RULE_PATTERN_LEN) {
            return GOSTC_ERROR_CONFIG_INVALID;
        }
        
        /* 检查动作 */
        if (rule->action > 1) { /* 0=ALLOW, 1=DENY */
            return GOSTC_ERROR_CONFIG_INVALID;
        }
        
        /* 检查匹配类型 */
        if (rule->pattern_type > 2) { /* 0=精确,1=通配符,2=正则 */
            return GOSTC_ERROR_CONFIG_INVALID;
        }
        
        rule = rule->next;
    }
    
    return GOSTC_OK;
}

/**
 * @brief   验证TLS规则配置
 */
static int32_t _config_validate_tls_rules(const tls_rules_config_t *config)
{
    GOSTC_CHECK_PTR(config);
    
    /* 检查规则数量 */
    if (config->rule_count > 0 && config->rules == NULL) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    /* 检查证书配置 */
    if (config->ca_cert != NULL && config->ca_cert_len == 0) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    if (config->client_cert != NULL && config->client_cert_len == 0) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    if (config->client_key != NULL && config->client_key_len == 0) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    /* 检查TLS参数 */
    if (config->handshake_timeout_ms == 0 || config->handshake_timeout_ms > 30000) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    /* 验证每个规则 */
    tls_rule_entry_t *rule = config->rules;
    while (rule != NULL) {
        /* 检查端口 */
        if (rule->dest_port > 65535) {
            return GOSTC_ERROR_CONFIG_INVALID;
        }
        
        rule = rule->next;
    }
    
    return GOSTC_OK;
}

/**
 * @brief   验证系统配置
 */
static int32_t _config_validate_system(const system_config_t *config)
{
    GOSTC_CHECK_PTR(config);
    
    /* 检查性能参数 */
    if (config->max_connections == 0 || config->max_connections > 256) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    if (config->connection_timeout_ms == 0 || config->connection_timeout_ms > 60000) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    if (config->tls_handshake_timeout_ms == 0 || config->tls_handshake_timeout_ms > 30000) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    if (config->enable_connection_pool && config->connection_pool_size == 0) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    /* 检查日志配置 */
    if (config->log_level > 3) { /* 0=ERROR,1=WARN,2=INFO,3=DEBUG */
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    if (config->log_buffer_size == 0 || config->log_buffer_size > 65535) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    /* 检查诊断配置 */
    if (config->enable_diagnostics && config->diagnostic_interval_ms == 0) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    return GOSTC_OK;
}

/**
 * @brief   设置默认配置
 */
static void _config_set_defaults(gostc_config_t *config)
{
    GOSTC_ASSERT(config != NULL);
    
    memset(config, 0, sizeof(gostc_config_t));
    
    /* 版本信息 */
    config->version = CONFIG_VERSION_1_0;
    config->magic = CONFIG_MAGIC;
    
    /* 代理服务器配置 */
    strncpy(config->proxy_server.server_host, "proxy.example.com", MAX_HOSTNAME_LEN - 1);
    config->proxy_server.server_port = 1080;
    config->proxy_server.server_type = PROXY_TYPE_SOCKS5;
    config->proxy_server.auth_required = 0;
    config->proxy_server.connect_timeout_ms = 5000;
    config->proxy_server.keepalive_interval_ms = 30000;
    config->proxy_server.retry_count = 3;
    
    /* 代理规则配置 */
    config->proxy_rules.rule_count = 0;
    config->proxy_rules.rules = NULL;
    config->proxy_rules.default_action = ACTION_DIRECT;
    
    /* DNS规则配置 */
    config->dns_rules.rule_count = 0;
    config->dns_rules.rules = NULL;
    config->dns_rules.default_action = DNS_ACTION_DENY; /* 空白名单：全部拒绝 */
    config->dns_rules.enable_cache = 1;
    config->dns_rules.cache_size = DNS_MAX_CACHE_SIZE;
    config->dns_rules.cache_ttl_ms = DNS_CACHE_TTL_MS;
    
    /* TLS规则配置 */
    config->tls_rules.rule_count = 0;
    config->tls_rules.rules = NULL;
    config->tls_rules.ca_cert = NULL;
    config->tls_rules.ca_cert_len = 0;
    config->tls_rules.client_cert = NULL;
    config->tls_rules.client_cert_len = 0;
    config->tls_rules.client_key = NULL;
    config->tls_rules.client_key_len = 0;
    config->tls_rules.handshake_timeout_ms = TLS_HANDSHAKE_TIMEOUT_MS;
    config->tls_rules.session_cache_size = TLS_MAX_SESSION_CACHE;
    
    /* 系统配置 */
    config->system.max_connections = DEFAULT_MAX_CONNECTIONS;
    config->system.connection_timeout_ms = DEFAULT_CONN_TIMEOUT_MS;
    config->system.tls_handshake_timeout_ms = DEFAULT_TLS_TIMEOUT_MS;
    config->system.enable_connection_pool = 1;
    config->system.connection_pool_size = 8;
    config->system.log_level = DEFAULT_LOG_LEVEL;
    config->system.enable_file_log = 0;
    config->system.enable_console_log = 1;
    config->system.log_buffer_size = 1024;
    config->system.enable_statistics = 1;
    config->system.enable_diagnostics = 0;
    config->system.diagnostic_interval_ms = 60000;
    
    /* 运行时统计 */
    memset(&config->stats, 0, sizeof(runtime_stats_t));
    config->stats.start_time = os_get_tick_count();
    
    /* 计算校验和 */
    config->checksum = _config_calculate_checksum(config);
}

/**
 * @brief   计算配置校验和
 */
static uint32_t _config_calculate_checksum(const gostc_config_t *config)
{
    GOSTC_ASSERT(config != NULL);
    
    /* 简单校验和算法：累加所有字节 */
    const uint8_t *data = (const uint8_t *)config;
    uint32_t checksum = 0;
    size_t data_size = sizeof(gostc_config_t) - sizeof(config->checksum);
    
    for (size_t i = 0; i < data_size; i++) {
        checksum += data[i];
    }
    
    return checksum;
}

/* 公共函数实现 */

int32_t gostc_config_init(void)
{
    if (g_initialized) {
        return GOSTC_ERROR_ALREADY_INITIALIZED;
    }
    
    /* 创建配置互斥锁 */
    os_error_e os_err = os_mutex_create(&g_config_mutex);
    if (os_err != OS_OK) {
        GOSTC_ERROR_RETURN(GOSTC_ERROR_OS_MUTEX_CREATE_FAILED, 
                          "Failed to create config mutex");
    }
    
    /* 设置默认配置 */
    _config_set_defaults(&g_default_config);
    
    /* 复制默认配置到当前配置 */
    memcpy(&g_config, &g_default_config, sizeof(gostc_config_t));
    
    g_initialized = true;
    
    return GOSTC_OK;
}

int32_t gostc_config_deinit(void)
{
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* 删除配置互斥锁 */
    if (g_config_mutex != NULL) {
        os_mutex_delete(g_config_mutex);
        g_config_mutex = NULL;
    }
    
    /* TODO: 释放规则链表内存 */
    
    g_initialized = false;
    
    return GOSTC_OK;
}

int32_t gostc_config_load_default(gostc_config_t *config)
{
    GOSTC_CHECK_PTR(config);
    
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    os_mutex_lock(g_config_mutex, OS_WAIT_FOREVER);
    memcpy(config, &g_default_config, sizeof(gostc_config_t));
    os_mutex_unlock(g_config_mutex);
    
    return GOSTC_OK;
}

int32_t gostc_config_validate(const gostc_config_t *config)
{
    GOSTC_CHECK_PTR(config);
    
    /* 检查版本和魔数 */
    if (config->version != CONFIG_VERSION_1_0) {
        return GOSTC_ERROR_CONFIG_VERSION;
    }
    
    if (config->magic != CONFIG_MAGIC) {
        return GOSTC_ERROR_CONFIG_CHECKSUM;
    }
    
    /* 验证校验和 */
    uint32_t calculated_checksum = _config_calculate_checksum(config);
    if (calculated_checksum != config->checksum) {
        return GOSTC_ERROR_CONFIG_CHECKSUM;
    }
    
    /* 验证各个子配置 */
    int32_t ret;
    
    ret = _config_validate_proxy_server(&config->proxy_server);
    if (ret != GOSTC_OK) {
        return ret;
    }
    
    ret = _config_validate_proxy_rules(&config->proxy_rules);
    if (ret != GOSTC_OK) {
        return ret;
    }
    
    ret = _config_validate_dns_rules(&config->dns_rules);
    if (ret != GOSTC_OK) {
        return ret;
    }
    
    ret = _config_validate_tls_rules(&config->tls_rules);
    if (ret != GOSTC_OK) {
        return ret;
    }
    
    ret = _config_validate_system(&config->system);
    if (ret != GOSTC_OK) {
        return ret;
    }
    
    return GOSTC_OK;
}

int32_t gostc_config_apply(const gostc_config_t *config)
{
    GOSTC_CHECK_PTR(config);
    
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* 验证配置 */
    int32_t ret = gostc_config_validate(config);
    if (ret != GOSTC_OK) {
        return ret;
    }
    
    os_mutex_lock(g_config_mutex, OS_WAIT_FOREVER);
    
    /* 复制配置 */
    memcpy(&g_config, config, sizeof(gostc_config_t));
    
    /* 更新校验和 */
    g_config.checksum = _config_calculate_checksum(&g_config);
    
    os_mutex_unlock(g_config_mutex);
    
    /* TODO: 通知其他模块配置已更新 */
    
    return GOSTC_OK;
}

int32_t gostc_config_save_to_file(const gostc_config_t *config, const char *path)
{
    /* 文件系统支持可选功能 */
    (void)config;
    (void)path;
    return GOSTC_ERROR_NOT_SUPPORTED;
}

int32_t gostc_config_load_from_file(gostc_config_t *config, const char *path)
{
    /* 文件系统支持可选功能 */
    (void)config;
    (void)path;
    return GOSTC_ERROR_NOT_SUPPORTED;
}

int32_t gostc_config_get_value(const char *key, void *value, uint32_t size)
{
    GOSTC_CHECK_PTR(key);
    GOSTC_CHECK_PTR(value);
    
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* TODO: 实现键值查询 */
    (void)size;
    
    return GOSTC_ERROR_NOT_SUPPORTED;
}

int32_t gostc_config_set_value(const char *key, const void *value, uint32_t size)
{
    GOSTC_CHECK_PTR(key);
    GOSTC_CHECK_PTR(value);
    
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* TODO: 实现键值设置 */
    (void)size;
    
    return GOSTC_ERROR_NOT_SUPPORTED;