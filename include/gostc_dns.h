/**
 * @file    gostc_dns.h
 * @brief   DNS白名单过滤模块头文件
 * @author  mosser
 * @date    2026-03-08
 * @version 1.0.0
 * 
 * @note    基于正则表达式引擎实现DNS域名白名单过滤
 * @warning 默认空白名单（全部拒绝），需要显式添加允许的域名
 */

#ifndef __GOSTC_DNS_H__
#define __GOSTC_DNS_H__

#ifdef __cplusplus
extern "C" {
#endif

/* 包含头文件 */
#include <stdint.h>
#include <stdbool.h>
#include "gostc_err.h"
#include "gostc_os.h"
#include "re.h"

/* 常量定义 */
#define DNS_MAX_PATTERN_LEN       256     /* 最大模式字符串长度 */
#define DNS_MAX_DOMAIN_LEN        256     /* 最大域名长度 */
#define DNS_ERR_VAL               (-6)    /* 拒绝时的错误返回值 */

/* DNS规则动作类型（与策略原文对应） */
typedef enum {
    DNS_ACTION_ALLOW = 0,     /* 允许域名（ALW） */
    DNS_ACTION_DENY = 1,      /* 拒绝域名（DEN） */
} dns_rule_action_t;

/* DNS规则类型（与策略原文对应） */
typedef enum {
    DNS_RULE_EXACT = 0,       /* 精确匹配（EXAC） */
    DNS_RULE_WILDCARD = 1,    /* 通配符匹配（WILD） */
    DNS_RULE_REGEX = 2,       /* 正则表达式匹配（REGX） */
    DNS_RULE_SUFFIX = 3       /* 后缀匹配（SUFF） */
} dns_rule_type_t;

/* DNS规则条目 */
typedef struct dns_rule_entry {
    uint32_t rule_id;                         /* 规则ID（内部使用） */
    char pattern[DNS_MAX_PATTERN_LEN];        /* 原始模式字符串 */
    dns_rule_type_t rule_type;                /* 规则类型 */
    dns_rule_action_t action;                 /* 动作类型 */
    
    /* 统计信息（可选） */
    uint32_t hit_count;                       /* 命中次数 */
    
    struct dns_rule_entry *next;              /* 下一个规则（链表） */
} dns_rule_entry_t;

/* DNS规则上下文 */
typedef struct {
    dns_rule_entry_t *rule_list;              /* 规则链表头 */
    uint32_t rule_count;                      /* 规则总数 */
    dns_rule_action_t default_action;         /* 默认动作（无匹配时） */
    bool initialized;                         /* 是否已初始化 */
    bool enabled;                             /* 是否启用过滤 */
    
    /* 互斥锁（线程安全） */
    void *mutex;
} dns_rule_ctx_t;

/* DNS配置结构体 */
typedef struct {
    dns_rule_action_t default_action;         /* 默认动作（空白名单：全部拒绝） */
    bool enable_precompile;                   /* 是否启用正则预编译 */
} gostc_dns_config_t;

/* 函数声明 */

/**
 * @brief   初始化DNS过滤器
 * @param   config  DNS配置指针（如果为NULL则使用默认配置）
 * @return  int32_t 成功返回GOSTC_OK，失败返回错误码
 */
int32_t gostc_dns_init(const gostc_dns_config_t *config);

/**
 * @brief   反初始化DNS过滤器
 * @return  int32_t 成功返回GOSTC_OK，失败返回错误码
 */
int32_t gostc_dns_deinit(void);

/**
 * @brief   拦截的netconn_gethostbyname_addrtype函数
 * @param   name        主机名
 * @param   addr        返回的IP地址
 * @param   dns_addrtype 地址类型
 * @return  int32_t     允许返回GOSTC_OK，拒绝返回DNS_ERR_VAL(-6)
 */
int32_t netconn_gethostbyname_addrtype_ex(const char *name, 
                                         void *addr, 
                                         uint8_t dns_addrtype);

/**
 * @brief   加载DNS策略明文
 * @param   org_text 策略文本，格式为"策略,规则类型,表达式"
 * @return  int32_t  成功返回GOSTC_OK，失败返回错误码
 * 
 * @note    策略格式示例：
 *          ALW,EXAC,www.baidu.com
 *          DEN,WILD,www.app*.com
 *          ALW,REGX,(\\w+\\.){2}\\w+
 */
int32_t gostc_dns_load_rules(const char *org_text);

/**
 * @brief   添加DNS规则
 * @param   pattern    匹配模式
 * @param   action     动作：DNS_ACTION_ALLOW/DNS_ACTION_DENY
 * @param   rule_type  规则类型：DNS_RULE_EXACT/WILDCARD/REGEX/SUFFIX
 * @return  uint32_t   成功返回规则ID，失败返回0
 */
uint32_t gostc_dns_add_rule(const char *pattern, 
                           dns_rule_action_t action, 
                           dns_rule_type_t rule_type);

/**
 * @brief   删除DNS规则
 * @param   rule_id   规则ID
 * @return  int32_t   成功返回GOSTC_OK，失败返回错误码
 */
int32_t gostc_dns_delete_rule(uint32_t rule_id);

/**
 * @brief   清除所有DNS规则
 * @return  int32_t   成功返回GOSTC_OK，失败返回错误码
 */
int32_t gostc_dns_clear_rules(void);

/**
 * @brief   查询域名是否允许
 * @param   domain    域名
 * @return  int32_t   允许返回GOSTC_OK，阻止返回DNS_ERR_VAL(-6)
 */
int32_t gostc_dns_query(const char *domain);

/**
 * @brief   设置默认动作
 * @param   action    默认动作：DNS_ACTION_ALLOW/DNS_ACTION_DENY
 * @return  int32_t   成功返回GOSTC_OK，失败返回错误码
 */
int32_t gostc_dns_set_default_action(dns_rule_action_t action);

/**
 * @brief   获取规则数量
 * @return  uint32_t  规则数量
 */
uint32_t gostc_dns_get_rule_count(void);

/**
 * @brief   启用/禁用DNS过滤
 * @param   enable    true启用，false禁用
 * @return  int32_t   成功返回GOSTC_OK，失败返回错误码
 */
int32_t gostc_dns_enable(bool enable);

/**
 * @brief   预编译正则表达式
 * @return  int32_t   成功返回GOSTC_OK，失败返回错误码
 * 
 * @note    提高正则匹配性能，但会增加内存使用
 */
int32_t gostc_dns_precompile_regex(void);

/**
 * @brief   验证域名格式
 * @param   domain    域名
 * @return  int32_t   有效返回GOSTC_OK，无效返回错误码
 */
int32_t gostc_dns_validate_domain(const char *domain);

#ifdef __cplusplus
}
#endif

#endif /* __GOSTC_DNS_H__ */