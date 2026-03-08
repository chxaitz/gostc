/**
 * @file    gostc_dns_filter.c
 * @brief   DNS白名单过滤模块实现
 * @author  Kilo Code
 * @date    2026-03-07
 * @version 1.0.0
 * 
 * @note    基于正则表达式引擎实现DNS域名白名单过滤
 * @warning 默认空白名单（全部拒绝），需要显式添加允许的域名
 */

#include "gostc_dns.h"
#include "gostc_err.h"
#include "gostc_os.h"
#include <string.h>

/* 模块内部全局变量 */
static gostc_dns_ctx_t g_dns_ctx;
static bool g_initialized = false;

/* 内部函数声明 */
static int32_t _dns_load_default_config(gostc_dns_config_t *config);
static int32_t _dns_validate_config(const gostc_dns_config_t *config);
static uint32_t _dns_hash_string(const char *str);
static int32_t _dns_match_pattern(const char *domain, const dns_rule_entry_t *rule);
static int32_t _dns_add_to_cache(const char *domain, uint32_t ip_addr, uint8_t action);
static int32_t _dns_find_in_cache(const char *domain, dns_query_result_t *result);

/* 内部函数实现 */

/**
 * @brief   加载默认DNS配置
 */
static int32_t _dns_load_default_config(gostc_dns_config_t *config)
{
    GOSTC_CHECK_PTR(config);
    
    memset(config, 0, sizeof(gostc_dns_config_t));
    
    /* 规则配置 */
    config->rules = NULL;
    config->rule_count = 0;
    config->default_action = DNS_ACTION_DENY; /* 空白名单：全部拒绝 */
    
    /* 缓存配置 */
    config->enable_cache = 1;
    config->cache_size = DNS_MAX_CACHE_SIZE;
    config->cache_ttl_ms = DNS_CACHE_TTL_MS;
    
    /* 性能配置 */
    config->enable_precompile = 0;
    config->enable_hash_index = 0;
    
    return GOSTC_OK;
}

/**
 * @brief   验证DNS配置
 */
static int32_t _dns_validate_config(const gostc_dns_config_t *config)
{
    GOSTC_CHECK_PTR(config);
    
    /* 检查默认动作 */
    if (config->default_action > DNS_ACTION_DENY) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    /* 检查缓存配置 */
    if (config->enable_cache) {
        if (config->cache_size == 0 || config->cache_size > DNS_MAX_CACHE_SIZE) {
            return GOSTC_ERROR_CONFIG_INVALID;
        }
        if (config->cache_ttl_ms == 0 || config->cache_ttl_ms > 3600000) {
            return GOSTC_ERROR_CONFIG_INVALID;
        }
    }
    
    return GOSTC_OK;
}

/**
 * @brief   计算字符串哈希值
 */
static uint32_t _dns_hash_string(const char *str)
{
    if (str == NULL) {
        return 0;
    }
    
    /* 简单哈希函数 */
    uint32_t hash = 5381;
    int c;
    
    while ((c = *str++) != '\0') {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    
    return hash;
}

/**
 * @brief   匹配域名模式
 */
static int32_t _dns_match_pattern(const char *domain, const dns_rule_entry_t *rule)
{
    if (domain == NULL || rule == NULL) {
        return -1;
    }
    
    switch (rule->match_type) {
        case DNS_MATCH_EXACT:
            /* 精确匹配 */
            return (strcmp(domain, rule->pattern) == 0) ? 0 : -1;
            
        case DNS_MATCH_WILDCARD:
            /* 通配符匹配 */
            /* TODO: 实现通配符匹配 */
            return -1;
            
        case DNS_MATCH_REGEX:
            /* 正则表达式匹配 */
            /* TODO: 使用正则表达式引擎 */
            return -1;
            
        default:
            return -1;
    }
}

/**
 * @brief   添加条目到缓存
 */
static int32_t _dns_add_to_cache(const char *domain, uint32_t ip_addr, uint8_t action)
{
    if (domain == NULL || strlen(domain) == 0) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    if (!g_dns_ctx.config.enable_cache) {
        return GOSTC_ERROR_NOT_SUPPORTED;
    }
    
    /* 查找是否已存在 */
    for (uint8_t i = 0; i < g_dns_ctx.cache_count; i++) {
        if (strcmp(g_dns_ctx.cache[i].domain, domain) == 0) {
            /* 更新现有条目 */
            g_dns_ctx.cache[i].ip_addr = ip_addr;
            g_dns_ctx.cache[i].action = action;
            g_dns_ctx.cache[i].timestamp = os_get_tick_count();
            g_dns_ctx.cache[i].hit_count++;
            return GOSTC_OK;
        }
    }
    
    /* 检查缓存是否已满 */
    if (g_dns_ctx.cache_count >= g_dns_ctx.config.cache_size) {
        /* 移除最旧的条目 */
        uint32_t oldest_time = 0xFFFFFFFF;
        uint8_t oldest_index = 0;
        
        for (uint8_t i = 0; i < g_dns_ctx.cache_count; i++) {
            if (g_dns_ctx.cache[i].timestamp < oldest_time) {
                oldest_time = g_dns_ctx.cache[i].timestamp;
                oldest_index = i;
            }
        }
        
        /* 覆盖最旧的条目 */
        strncpy(g_dns_ctx.cache[oldest_index].domain, domain, 
                sizeof(g_dns_ctx.cache[oldest_index].domain) - 1);
        g_dns_ctx.cache[oldest_index].domain[sizeof(g_dns_ctx.cache[oldest_index].domain) - 1] = '\0';
        g_dns_ctx.cache[oldest_index].ip_addr = ip_addr;
        g_dns_ctx.cache[oldest_index].action = action;
        g_dns_ctx.cache[oldest_index].timestamp = os_get_tick_count();
        g_dns_ctx.cache[oldest_index].ttl_ms = g_dns_ctx.config.cache_ttl_ms;
        g_dns_ctx.cache[oldest_index].hit_count = 1;
    } else {
        /* 添加新条目 */
        strncpy(g_dns_ctx.cache[g_dns_ctx.cache_count].domain, domain, 
                sizeof(g_dns_ctx.cache[g_dns_ctx.cache_count].domain) - 1);
        g_dns_ctx.cache[g_dns_ctx.cache_count].domain[sizeof(g_dns_ctx.cache[g_dns_ctx.cache_count].domain) - 1] = '\0';
        g_dns_ctx.cache[g_dns_ctx.cache_count].ip_addr = ip_addr;
        g_dns_ctx.cache[g_dns_ctx.cache_count].action = action;
        g_dns_ctx.cache[g_dns_ctx.cache_count].timestamp = os_get_tick_count();
        g_dns_ctx.cache[g_dns_ctx.cache_count].ttl_ms = g_dns_ctx.config.cache_ttl_ms;
        g_dns_ctx.cache[g_dns_ctx.cache_count].hit_count = 1;
        g_dns_ctx.cache_count++;
    }
    
    return GOSTC_OK;
}

/**
 * @brief   在缓存中查找域名
 */
static int32_t _dns_find_in_cache(const char *domain, dns_query_result_t *result)
{
    if (domain == NULL || result == NULL) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    if (!g_dns_ctx.config.enable_cache) {
        return GOSTC_ERROR_CONFIG_NOT_FOUND;
    }
    
    uint32_t current_time = os_get_tick_count();
    
    for (uint8_t i = 0; i < g_dns_ctx.cache_count; i++) {
        if (strcmp(g_dns_ctx.cache[i].domain, domain) == 0) {
            /* 检查是否过期 */
            if (current_time - g_dns_ctx.cache[i].timestamp > g_dns_ctx.cache[i].ttl_ms) {
                /* 缓存过期，移除条目 */
                for (uint8_t j = i; j < g_dns_ctx.cache_count - 1; j++) {
                    memcpy(&g_dns_ctx.cache[j], &g_dns_ctx.cache[j + 1], sizeof(dns_cache_entry_t));
                }
                g_dns_ctx.cache_count--;
                return GOSTC_ERROR_CONFIG_NOT_FOUND;
            }
            
            /* 找到有效缓存条目 */
            strncpy(result->domain, domain, sizeof(result->domain) - 1);
            result->domain[sizeof(result->domain) - 1] = '\0';
            result->ip_addr = g_dns_ctx.cache[i].ip_addr;
            result->action = g_dns_ctx.cache[i].action;
            result->from_cache = 1;
            result->match_type = 0; /* 缓存不记录匹配类型 */
            result->rule_id = 0;    /* 缓存不记录规则ID */
            result->match_time_us = 0;
            result->error_code = GOSTC_OK;
            
            /* 更新命中计数 */
            g_dns_ctx.cache[i].hit_count++;
            g_dns_ctx.cache_hits++;
            
            return GOSTC_OK;
        }
    }
    
    return GOSTC_ERROR_CONFIG_NOT_FOUND;
}

/* 公共函数实现 */

int32_t gostc_dns_init(const gostc_dns_config_t *config)
{
    if (g_initialized) {
        return GOSTC_ERROR_ALREADY_INITIALIZED;
    }
    
    /* 初始化DNS上下文 */
    memset(&g_dns_ctx, 0, sizeof(gostc_dns_ctx_t));
    
    /* 加载配置 */
    if (config != NULL) {
        /* 验证配置 */
        int32_t ret = _dns_validate_config(config);
        if (ret != GOSTC_OK) {
            return ret;
        }
        
        /* 复制配置 */
        memcpy(&g_dns_ctx.config, config, sizeof(gostc_dns_config_t));
    } else {
        /* 使用默认配置 */
        _dns_load_default_config(&g_dns_ctx.config);
    }
    
    /* 分配缓存内存 */
    if (g_dns_ctx.config.enable_cache) {
        g_dns_ctx.cache = (dns_cache_entry_t *)os_malloc(
            sizeof(dns_cache_entry_t) * g_dns_ctx.config.cache_size);
        if (g_dns_ctx.cache == NULL) {
            return GOSTC_ERROR_NO_MEMORY;
        }
        
        memset(g_dns_ctx.cache, 0, sizeof(dns_cache_entry_t) * g_dns_ctx.config.cache_size);
        g_dns_ctx.cache_count = 0;
    }
    
    /* 创建互斥锁 */
    os_error_e os_err = os_mutex_create(&g_dns_ctx.mutex);
    if (os_err != OS_OK) {
        if (g_dns_ctx.cache != NULL) {
            os_free(g_dns_ctx.cache);
        }
        return GOSTC_ERROR_OS_MUTEX_CREATE_FAILED;
    }
    
    /* 初始化哈希索引 */
    if (g_dns_ctx.config.enable_hash_index) {
        /* TODO: 分配哈希索引表 */
    }
    
    g_dns_ctx.initialized = true;
    g_dns_ctx.enabled = true;
    g_initialized = true;
    
    return GOSTC_OK;
}

int32_t gostc_dns_deinit(void)
{
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* 清除规则 */
    gostc_dns_clear_rules();
    
    /* 清除缓存 */
    gostc_dns_clear_cache();
    
    /* 释放哈希索引 */
    if (g_dns_ctx.hash_index != NULL) {
        os_free(g_dns_ctx.hash_index);
        g_dns_ctx.hash_index = NULL;
    }
    
    /* 删除互斥锁 */
    if (g_dns_ctx.mutex != NULL) {
        os_mutex_delete(g_dns_ctx.mutex);
        g_dns_ctx.mutex = NULL;
    }
    
    /* 释放缓存内存 */
    if (g_dns_ctx.cache != NULL) {
        os_free(g_dns_ctx.cache);
        g_dns_ctx.cache = NULL;
        g_dns_ctx.cache_count = 0;
    }
    
    /* 重置DNS上下文 */
    memset(&g_dns_ctx, 0, sizeof(gostc_dns_ctx_t));
    
    g_initialized = false;
    
    return GOSTC_OK;
}

uint32_t gostc_dns_add_rule(const char *pattern, uint8_t action, uint8_t match_type)
{
    if (!g_initialized) {
        return 0;
    }
    
    if (pattern == NULL || strlen(pattern) == 0 || strlen(pattern) >= DNS_MAX_PATTERN_LEN) {
        return 0;
    }
    
    if (action > DNS_ACTION_DENY) {
        return 0;
    }
    
    if (match_type > DNS_MATCH_REGEX) {
        return 0;
    }
    
    os_mutex_lock(g_dns_ctx.mutex, OS_WAIT_FOREVER);
    
    /* 分配规则条目 */
    dns_rule_entry_t *new_rule = (dns_rule_entry_t *)os_malloc(sizeof(dns_rule_entry_t));
    if (new_rule == NULL) {
        os_mutex_unlock(g_dns_ctx.mutex);
        return 0;
    }
    
    /* 初始化规则条目 */
    memset(new_rule, 0, sizeof(dns_rule_entry_t));
    
    /* 生成规则ID */
    static uint32_t next_rule_id = 1;
    new_rule->rule_id = next_rule_id++;
    
    strncpy(new_rule->pattern, pattern, sizeof(new_rule->pattern) - 1);
    new_rule->pattern[sizeof(new_rule->pattern) - 1] = '\0';
    new_rule->action = action;
    new_rule->match_type = match_type;
    new_rule->regex_compiled = NULL;
    new_rule->match_count = 0;
    new_rule->last_match_time = 0;
    
    /* 添加到规则链表 */
    new_rule->next = g_dns_ctx.rule_list;
    g_dns_ctx.rule_list = new_rule;
    g_dns_ctx.config.rule_count++;
    
    /* 更新哈希索引 */
    if (g_dns_ctx.config.enable_hash_index && match_type == DNS_MATCH_EXACT) {
        /* TODO: 添加到哈希索引 */
    }
    
    /* 预编译正则表达式 */
    if (g_dns_ctx.config.enable_precompile && match_type == DNS_MATCH_REGEX) {
        /* TODO: 预编译正则表达式 */
    }
    
    os_mutex_unlock(g_dns_ctx.mutex);
    
    return new_rule->rule_id;
}

int32_t gostc_dns_query(const char *domain, dns_query_result_t *result)
{
    if (!g_initialized || !g_dns_ctx.enabled) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    if (domain == NULL || strlen(domain) == 0) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 记录查询开始时间 */
    uint32_t start_time = os_get_tick_count();
    
    /* 初始化结果 */
    dns_query_result_t local_result;
    memset(&local_result, 0, sizeof(dns_query_result_t));
    strncpy(local_result.domain, domain, sizeof(local_result.domain) - 1);
    local_result.domain[sizeof(local_result.domain) - 1] = '\0';
    
    os_mutex_lock(g_dns_ctx.mutex, OS_WAIT_FOREVER);
    
    /* 更新统计信息 */
    g_dns_ctx.total_queries++;
    
    /* 首先检查缓存 */
    if (g_dns_ctx.config.enable_cache) {
        int32_t cache_ret = _dns_find_in_cache(domain, &local_result);
        if (cache_ret == GOSTC_OK) {
            /* 缓存命中 */
            local_result.match_time_us = (os_get_tick_count() - start_time) * 1000;
            
            if (result != NULL) {
                memcpy(result, &local_result, sizeof(dns_query_result_t));
            }
            
            os_mutex_unlock(g_dns_ctx.mutex);
            
            /* 根据动作返回 */
            return (local_result.action == DNS_ACTION_ALLOW) ? GOSTC_OK : GOSTC_ERROR_DNS_NOT_ALLOWED;
        }
    }
    
    /* 遍历规则进行匹配 */
    dns_rule_entry_t *rule = g_dns_ctx.rule_list;
    dns_rule_entry_t *matched_rule = NULL;
    
    while (rule != NULL) {
        int32_t match_ret = _dns_match_pattern(domain, rule);
        if (match_ret == 0) {
            /* 匹配成功 */
            matched_rule = rule;
            break;
        }
        
        rule = rule->next;
    }
    
    /* 计算匹配时间 */
    uint32_t match_time = os_get_tick_count() - start_time;
    
    /* 更新统计信息 */
    g_dns_ctx.total_queries++;
    
    if (matched_rule != NULL) {
        /* 找到匹配的规则 */
        g_dns_ctx.cache_hits++;
        
        /* 根据规则动作处理 */
        if (matched_rule->action == DNS_ACTION_ALLOW) {
            g_dns_ctx.allowed_queries++;
            
            /* 添加到缓存（如果启用缓存） */
            if (g_dns_ctx.config.enable_cache) {
                /* 这里应该调用缓存添加函数 */
                /* _dns_cache_add(domain, DNS_ACTION_ALLOW, match_time); */
            }
            
            /* 记录日志 */
            gostc_log_debug("[DNS] 域名允许: %s (规则ID: %u, 匹配时间: %u)", 
                          domain, matched_rule->rule_id, match_time);
            return GOSTC_OK;
        } else {
            /* DNS_ACTION_DENY */
            g_dns_ctx.denied_queries++;
            
            /* 添加到缓存（如果启用缓存） */
            if (g_dns_ctx.config.enable_cache) {
                /* 这里应该调用缓存添加函数 */
                /* _dns_cache_add(domain, DNS_ACTION_DENY, match_time); */
            }
            
            /* 记录日志 */
            gostc_log_warn("[DNS] 域名拒绝: %s (规则ID: %u, 匹配时间: %u)", 
                         domain, matched_rule->rule_id, match_time);
            return GOSTC_ERROR_DNS_NOT_ALLOWED;
        }
    } else {
        /* 没有匹配的规则，使用默认动作 */
        if (g_dns_ctx.config.default_action == DNS_ACTION_ALLOW) {
            g_dns_ctx.allowed_queries++;
            gostc_log_debug("[DNS] 域名默认允许: %s (匹配时间: %u)", 
                          domain, match_time);
            return GOSTC_OK;
        } else {
            /* 默认拒绝 */
            g_dns_ctx.denied_queries++;
            gostc_log_warn("[DNS] 域名默认拒绝: %s (匹配时间: %u)", 
                         domain, match_time);
            return GOSTC_ERROR_DNS_NOT_ALLOWED;
        }
    }
}