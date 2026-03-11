/**
 * @file    gostc_dns.c
 * @brief   DNS白名单过滤模块实现
 * @author  mosser
 * @date    2026-03-08
 * @version 1.0.0
 * 
 * @note    基于正则表达式引擎实现DNS域名白名单过滤
 * @warning 默认空白名单（全部拒绝），需要显式添加允许的域名
 */

#include "gostc_dns.h"
#include "gostc_err.h"
#include "gostc_log.h"
#include "gostc_os.h"
#include "re.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* 模块内部全局变量 */
static dns_rule_ctx_t g_dns_ctx;
static bool g_initialized = false;

/* 内部函数声明 */
static int32_t _dns_load_default_config(gostc_dns_config_t *config);
static int32_t _dns_validate_config(const gostc_dns_config_t *config);
static int32_t _dns_match_pattern(const char *domain, const dns_rule_entry_t *rule);
static int32_t _dns_parse_rule_line(const char *line, dns_rule_action_t *action, 
                                   dns_rule_type_t *rule_type, char *pattern);
static void _dns_free_rule(dns_rule_entry_t *rule);
static dns_rule_entry_t *_dns_find_rule_by_id(uint32_t rule_id);

/* 内部无锁函数声明（假设调用者已持有互斥锁） */
static uint32_t _dns_add_rule_unlocked(const char *pattern, 
                                      dns_rule_action_t action, 
                                      dns_rule_type_t rule_type);
static int32_t _dns_delete_rule_unlocked(uint32_t rule_id);

/* 内部函数实现 */

/**
 * @brief   加载默认DNS配置
 */
static int32_t _dns_load_default_config(gostc_dns_config_t *config)
{
    GOSTC_CHECK_PTR(config);
    
    memset(config, 0, sizeof(gostc_dns_config_t));
    
    /* 默认配置：空白名单（全部拒绝） */
    config->default_action = DNS_ACTION_DENY;
    config->enable_precompile = false;
    
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
    
    return GOSTC_OK;
}

/**
 * @brief   匹配域名模式
 */
static int32_t _dns_match_pattern(const char *domain, const dns_rule_entry_t *rule)
{
    if (domain == NULL || rule == NULL) {
        return -1;
    }
    
    switch (rule->rule_type) {
        case DNS_RULE_EXACT:
            /* 精确匹配 */
            return (strcmp(domain, rule->pattern) == 0) ? 0 : -1;
            
        case DNS_RULE_WILDCARD:
            /* 通配符匹配 */
            /* 支持 *.example.com 格式 */
            if (rule->pattern[0] == '*' && rule->pattern[1] == '.') {
                const char *suffix = rule->pattern + 2; /* 跳过"*." */
                size_t domain_len = strlen(domain);
                size_t suffix_len = strlen(suffix);
                
                if (domain_len >= suffix_len && 
                    strcasecmp(domain + domain_len - suffix_len, suffix) == 0) {
                    return 0;
                }
            }
            return -1;
            
        case DNS_RULE_REGEX: {
            /* 正则表达式匹配 - 使用 re_match 直接匹配 */
            int match_result = re_match(rule->pattern, domain, NULL);
            return (match_result >= 0) ? 0 : -1;
        }
            
        case DNS_RULE_SUFFIX:
            /* 后缀匹配 */
            /* 支持 .example.com 格式 */
            if (rule->pattern[0] == '.') {
                size_t domain_len = strlen(domain);
                size_t suffix_len = strlen(rule->pattern);
                
                if (domain_len >= suffix_len && 
                    strcasecmp(domain + domain_len - suffix_len, rule->pattern) == 0) {
                    return 0;
                }
            }
            return -1;
            
        default:
            return -1;
    }
}

/**
 * @brief   解析规则行
 */
static int32_t _dns_parse_rule_line(const char *line, dns_rule_action_t *action, 
                                   dns_rule_type_t *rule_type, char *pattern)
{
    char line_copy[512];
    char *token;
    int field_count = 0;
    
    if (line == NULL || action == NULL || rule_type == NULL || pattern == NULL) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 复制行以便分割 */
    strncpy(line_copy, line, sizeof(line_copy) - 1);
    line_copy[sizeof(line_copy) - 1] = '\0';
    
    /* 去除前后空白字符 */
    char *start = line_copy;
    while (isspace((unsigned char)*start)) start++;
    
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
    
        /* 跳过空行和注释行 */
        if (strlen(start) == 0 || start[0] == '#') {
            return GOSTC_ERROR_AGAIN;  /* 使用AGAIN表示跳过 */
        }
    
    /* 分割字段 */
    token = strtok(start, ",");
    while (token != NULL && field_count < 3) {
        /* 去除字段前后的空白字符 */
        char *field_start = token;
        while (isspace((unsigned char)*field_start)) field_start++;
        
        char *field_end = field_start + strlen(field_start) - 1;
        while (field_end > field_start && isspace((unsigned char)*field_end)) field_end--;
        *(field_end + 1) = '\0';
        
        switch (field_count) {
            case 0: /* 动作 */
                if (strcmp(field_start, "ALW") == 0) {
                    *action = DNS_ACTION_ALLOW;
                } else if (strcmp(field_start, "DEN") == 0) {
                    *action = DNS_ACTION_DENY;
                } else {
                    return GOSTC_ERROR_CONFIG_INVALID;
                }
                break;
                
            case 1: /* 规则类型 */
                if (strcmp(field_start, "EXAC") == 0) {
                    *rule_type = DNS_RULE_EXACT;
                } else if (strcmp(field_start, "WILD") == 0) {
                    *rule_type = DNS_RULE_WILDCARD;
                } else if (strcmp(field_start, "REGX") == 0) {
                    *rule_type = DNS_RULE_REGEX;
                } else if (strcmp(field_start, "SUFF") == 0) {
                    *rule_type = DNS_RULE_SUFFIX;
                } else {
                    return GOSTC_ERROR_CONFIG_INVALID;
                }
                break;
                
            case 2: /* 模式 */
                strncpy(pattern, field_start, DNS_MAX_PATTERN_LEN - 1);
                pattern[DNS_MAX_PATTERN_LEN - 1] = '\0';
                break;
        }
        
        field_count++;
        token = strtok(NULL, ",");
    }
    
    if (field_count != 3) {
        return GOSTC_ERROR_CONFIG_INVALID;
    }
    
    return GOSTC_OK;
}

/**
 * @brief   释放规则内存
 */
static void _dns_free_rule(dns_rule_entry_t *rule)
{
    if (rule == NULL) {
        return;
    }
    
    os_free(rule);
}

/**
 * @brief   根据ID查找规则
 */
static dns_rule_entry_t *_dns_find_rule_by_id(uint32_t rule_id)
{
    dns_rule_entry_t *rule = g_dns_ctx.rule_list;
    
    while (rule != NULL) {
        if (rule->rule_id == rule_id) {
            return rule;
        }
        rule = rule->next;
    }
    
    return NULL;
}



/* 公共函数实现 */

int32_t gostc_dns_init(const gostc_dns_config_t *config)
{
    if (g_initialized) {
        return GOSTC_ERROR_ALREADY_INITIALIZED;
    }
    
    /* 初始化DNS上下文 */
    memset(&g_dns_ctx, 0, sizeof(dns_rule_ctx_t));
    
    /* 加载配置 */
    if (config != NULL) {
        /* 验证配置 */
        int32_t ret = _dns_validate_config(config);
        if (ret != GOSTC_OK) {
            return ret;
        }
        
        /* 复制配置 */
        g_dns_ctx.default_action = config->default_action;
    } else {
        /* 使用默认配置 */
        gostc_dns_config_t default_config;
        _dns_load_default_config(&default_config);
        g_dns_ctx.default_action = default_config.default_action;
    }
    
    /* 创建互斥锁 */
    os_error_e os_err = os_mutex_create(&g_dns_ctx.mutex);
    if (os_err != OS_OK) {
        return GOSTC_ERROR_OS_MUTEX_CREATE_FAILED;
    }
    
    g_dns_ctx.initialized = true;
    g_dns_ctx.enabled = true;
    g_initialized = true;
    
    gostc_log_info("[DNS] DNS过滤器初始化完成，默认动作：%s", 
                  (g_dns_ctx.default_action == DNS_ACTION_ALLOW) ? "允许" : "拒绝");
    
    return GOSTC_OK;
}

int32_t gostc_dns_deinit(void)
{
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    os_mutex_lock(g_dns_ctx.mutex, OS_WAIT_FOREVER);
    
    /* 清除所有规则 */
    dns_rule_entry_t *rule = g_dns_ctx.rule_list;
    while (rule != NULL) {
        dns_rule_entry_t *next = rule->next;
        _dns_free_rule(rule);
        rule = next;
    }
    
    g_dns_ctx.rule_list = NULL;
    g_dns_ctx.rule_count = 0;
    
    /* 删除互斥锁 */
    if (g_dns_ctx.mutex != NULL) {
        os_mutex_delete(g_dns_ctx.mutex);
        g_dns_ctx.mutex = NULL;
    }
    
    /* 重置DNS上下文 */
    memset(&g_dns_ctx, 0, sizeof(dns_rule_ctx_t));
    
    g_initialized = false;
    
    gostc_log_info("[DNS] DNS过滤器反初始化完成");
    
    return GOSTC_OK;
}

int32_t netconn_gethostbyname_addrtype_ex(const char *name, 
                                         void *addr, 
                                         uint8_t dns_addrtype)
{
    if (!g_initialized || !g_dns_ctx.enabled) {
        /* 如果未初始化或禁用，直接返回错误 */
        return DNS_ERR_VAL;
    }
    
    if (name == NULL) {
        return DNS_ERR_VAL;
    }
    
    /* 查询域名 */
    int32_t result = gostc_dns_query(name);
    
    if (result == GOSTC_OK) {
        gostc_log_info("[DNS] 域名允许: %s", name);
        netconn_gethostbyname_addrtype(name, addr, dns_addrtype);
        return GOSTC_OK;
    } else {
        /* 拒绝访问 */
        gostc_log_warn("[DNS] 域名拒绝: %s", name);
        return DNS_ERR_VAL;
    }
}

int32_t gostc_dns_load_rules(const char *org_text)
{
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    if (org_text == NULL) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 清除现有规则 */
    gostc_dns_clear_rules();
    
    os_mutex_lock(g_dns_ctx.mutex, OS_WAIT_FOREVER);
    
    const char *line_start = org_text;
    const char *line_end;
    uint32_t line_num = 0;
    uint32_t success_count = 0;
    
    while (*line_start != '\0') {
        /* 查找行结束位置 */
        line_end = strchr(line_start, '\n');
        if (line_end == NULL) {
            line_end = line_start + strlen(line_start);
        }
        
        /* 提取行 */
        size_t line_len = line_end - line_start;
        char line[512];
        
        if (line_len >= sizeof(line)) {
            line_len = sizeof(line) - 1;
        }
        
        strncpy(line, line_start, line_len);
        line[line_len] = '\0';
        
        line_num++;
        
        /* 解析规则行 */
        dns_rule_action_t action;
        dns_rule_type_t rule_type;
        char pattern[DNS_MAX_PATTERN_LEN];
        
        int32_t parse_ret = _dns_parse_rule_line(line, &action, &rule_type, pattern);
        
        if (parse_ret == GOSTC_OK) {
            /* 添加规则 - 直接调用无锁版本，因为已经持有互斥锁 */
            uint32_t rule_id = _dns_add_rule_unlocked(pattern, action, rule_type);
            if (rule_id != 0) {
                success_count++;
                gostc_log_debug("[DNS] 加载规则成功 (行 %u): %s,%s,%s", 
                              line_num,
                              (action == DNS_ACTION_ALLOW) ? "ALW" : "DEN",
                              (rule_type == DNS_RULE_EXACT) ? "EXAC" : 
                              (rule_type == DNS_RULE_WILDCARD) ? "WILD" :
                              (rule_type == DNS_RULE_REGEX) ? "REGX" : "SUFF",
                              pattern);
            }
        } else if (parse_ret != GOSTC_ERROR_AGAIN) {
            gostc_log_warn("[DNS] 解析规则失败 (行 %u): %s", line_num, line);
        }
        
        /* 移动到下一行 */
        if (*line_end == '\0') {
            break;
        }
        line_start = line_end + 1;
    }
    
    os_mutex_unlock(g_dns_ctx.mutex);
    
    gostc_log_info("[DNS] 加载DNS规则完成，成功 %u 条，失败 %u 条", 
                  success_count, line_num - success_count);
    
    return GOSTC_OK;
}

uint32_t gostc_dns_add_rule(const char *pattern, 
                           dns_rule_action_t action, 
                           dns_rule_type_t rule_type)
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
    
    if (rule_type > DNS_RULE_SUFFIX) {
        return 0;
    }
    
    os_mutex_lock(g_dns_ctx.mutex, OS_WAIT_FOREVER);
    
    uint32_t rule_id = _dns_add_rule_unlocked(pattern, action, rule_type);
    
    os_mutex_unlock(g_dns_ctx.mutex);
    
    return rule_id;
}

int32_t gostc_dns_delete_rule(uint32_t rule_id)
{
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    if (rule_id == 0) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    os_mutex_lock(g_dns_ctx.mutex, OS_WAIT_FOREVER);
    
    int32_t result = _dns_delete_rule_unlocked(rule_id);
    
    os_mutex_unlock(g_dns_ctx.mutex);
    
    if (result != GOSTC_OK) {
        gostc_log_warn("[DNS] 删除规则失败，未找到规则 (ID: %u)", rule_id);
        return GOSTC_ERROR_CONFIG_NOT_FOUND;
    }
    
    return GOSTC_OK;
}

int32_t gostc_dns_clear_rules(void)
{
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    os_mutex_lock(g_dns_ctx.mutex, OS_WAIT_FOREVER);
    
    dns_rule_entry_t *rule = g_dns_ctx.rule_list;
    while (rule != NULL) {
        dns_rule_entry_t *next = rule->next;
        _dns_free_rule(rule);
        rule = next;
    }
    
    g_dns_ctx.rule_list = NULL;
    g_dns_ctx.rule_count = 0;
    
    os_mutex_unlock(g_dns_ctx.mutex);
    
    gostc_log_info("[DNS] 清除所有规则完成");
    return GOSTC_OK;
}

int32_t gostc_dns_query(const char *domain)
{
    if (!g_initialized || !g_dns_ctx.enabled) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    if (domain == NULL || strlen(domain) == 0) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    os_mutex_lock(g_dns_ctx.mutex, OS_WAIT_FOREVER);
    
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
    
    int32_t result;
    
    if (matched_rule != NULL) {
        /* 找到匹配的规则 */
        matched_rule->hit_count++;
        
        if (matched_rule->action == DNS_ACTION_ALLOW) {
            gostc_log_debug("[DNS] 域名允许: %s (规则ID: %u)", domain, matched_rule->rule_id);
            result = GOSTC_OK;
        } else {
            gostc_log_warn("[DNS] 域名拒绝: %s (规则ID: %u)", domain, matched_rule->rule_id);
            result = DNS_ERR_VAL;
        }
    } else {
        /* 没有匹配的规则，使用默认动作 */
        if (g_dns_ctx.default_action == DNS_ACTION_ALLOW) {
            gostc_log_debug("[DNS] 域名默认允许: %s", domain);
            result = GOSTC_OK;
        } else {
            gostc_log_warn("[DNS] 域名默认拒绝: %s", domain);
            result = DNS_ERR_VAL;
        }
    }
    
    os_mutex_unlock(g_dns_ctx.mutex);
    
    return result;
}

int32_t gostc_dns_set_default_action(dns_rule_action_t action)
{
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    if (action > DNS_ACTION_DENY) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    os_mutex_lock(g_dns_ctx.mutex, OS_WAIT_FOREVER);
    g_dns_ctx.default_action = action;
    os_mutex_unlock(g_dns_ctx.mutex);
    
    gostc_log_info("[DNS] 设置默认动作为: %s", 
                  (action == DNS_ACTION_ALLOW) ? "允许" : "拒绝");
    
    return GOSTC_OK;
}

uint32_t gostc_dns_get_rule_count(void)
{
    if (!g_initialized) {
        return 0;
    }
    
    os_mutex_lock(g_dns_ctx.mutex, OS_WAIT_FOREVER);
    uint32_t count = g_dns_ctx.rule_count;
    os_mutex_unlock(g_dns_ctx.mutex);
    
    return count;
}

int32_t gostc_dns_enable(bool enable)
{
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    os_mutex_lock(g_dns_ctx.mutex, OS_WAIT_FOREVER);
    g_dns_ctx.enabled = enable;
    os_mutex_unlock(g_dns_ctx.mutex);
    
    gostc_log_info("[DNS] %sDNS过滤", enable ? "启用" : "禁用");
    
    return GOSTC_OK;
}

int32_t gostc_dns_precompile_regex(void)
{
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    os_mutex_lock(g_dns_ctx.mutex, OS_WAIT_FOREVER);
    
    dns_rule_entry_t *rule = g_dns_ctx.rule_list;
    uint32_t compiled_count = 0;
    
    while (rule != NULL) {
        if (rule->rule_type == DNS_RULE_REGEX) {
            /* 不再需要预编译，直接使用 re_match 进行匹配 */
            compiled_count++;
        }
        rule = rule->next;
    }
    
    os_mutex_unlock(g_dns_ctx.mutex);
    
    gostc_log_info("[DNS] 统计正则表达式规则完成，共 %u 个正则规则", compiled_count);
    
    return GOSTC_OK;
}

int32_t gostc_dns_validate_domain(const char *domain)
{
    if (domain == NULL || strlen(domain) == 0) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    size_t len = strlen(domain);
    
    /* 检查域名长度 */
    if (len > DNS_MAX_DOMAIN_LEN - 1) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 简单验证：域名应只包含字母、数字、点号和连字符 */
    for (size_t i = 0; i < len; i++) {
        char c = domain[i];
        if (!(isalnum((unsigned char)c) || c == '.' || c == '-')) {
            return GOSTC_ERROR_INVALID_PARAM;
        }
    }
    
    return GOSTC_OK;
}

/* ========== 内部无锁函数实现 ========== */

/**
 * @brief   添加DNS规则（无锁版本）
 * @param   pattern    匹配模式
 * @param   action     动作：DNS_ACTION_ALLOW/DNS_ACTION_DENY
 * @param   rule_type  规则类型：DNS_RULE_EXACT/WILDCARD/REGEX/SUFFIX
 * @return  uint32_t   成功返回规则ID，失败返回0
 * 
 * @note    调用者必须已持有 g_dns_ctx.mutex 互斥锁
 * @warning 此函数不进行参数验证，调用者需确保参数有效
 */
static uint32_t _dns_add_rule_unlocked(const char *pattern, 
                                      dns_rule_action_t action, 
                                      dns_rule_type_t rule_type)
{
    /* 分配规则条目 */
    dns_rule_entry_t *new_rule = (dns_rule_entry_t *)os_malloc(sizeof(dns_rule_entry_t));
    if (new_rule == NULL) {
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
    new_rule->rule_type = rule_type;
    new_rule->hit_count = 0;
    
    /* 添加到规则链表头部 */
    new_rule->next = g_dns_ctx.rule_list;
    g_dns_ctx.rule_list = new_rule;
    g_dns_ctx.rule_count++;
    
    gostc_log_debug("[DNS] 添加规则成功 (ID: %u): %s,%s,%s", 
                   new_rule->rule_id,
                   (action == DNS_ACTION_ALLOW) ? "ALW" : "DEN",
                   (rule_type == DNS_RULE_EXACT) ? "EXAC" : 
                   (rule_type == DNS_RULE_WILDCARD) ? "WILD" :
                   (rule_type == DNS_RULE_REGEX) ? "REGX" : "SUFF",
                   pattern);
    
    return new_rule->rule_id;
}

/**
 * @brief   删除DNS规则（无锁版本）
 * @param   rule_id   规则ID
 * @return  int32_t   成功返回GOSTC_OK，失败返回错误码
 * 
 * @note    调用者必须已持有 g_dns_ctx.mutex 互斥锁
 */
static int32_t _dns_delete_rule_unlocked(uint32_t rule_id)
{
    dns_rule_entry_t *prev = NULL;
    dns_rule_entry_t *curr = g_dns_ctx.rule_list;
    
    while (curr != NULL) {
        if (curr->rule_id == rule_id) {
            /* 找到要删除的规则 */
            if (prev == NULL) {
                /* 删除链表头 */
                g_dns_ctx.rule_list = curr->next;
            } else {
                prev->next = curr->next;
            }
            
            /* 释放规则内存 */
            _dns_free_rule(curr);
            g_dns_ctx.rule_count--;
            
            gostc_log_debug("[DNS] 删除规则成功 (ID: %u)", rule_id);
            return GOSTC_OK;
        }
        
        prev = curr;
        curr = curr->next;
    }
    
    return GOSTC_ERROR_CONFIG_NOT_FOUND;
}
