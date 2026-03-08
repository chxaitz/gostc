/**
 * @file    gostc_dns.h
 * @brief   通信代理DNS白名单过滤头文件
 * @author  Kilo Code
 * @date    2026-03-07
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
#include "gostc_dns.h"

/* DNS缓存条目结构体 */
typedef struct {
    char domain[256];                    /* 域名 */
    uint32_t ip_addr;                    /* IP地址（网络字节序） */
    uint8_t action;                      /* 动作：ALLOW/DENY */
    uint32_t timestamp;                  /* 缓存时间戳 */
    uint32_t ttl_ms;                     /* 缓存TTL（毫秒） */
    uint32_t hit_count;                  /* 命中次数 */
} dns_cache_entry_t;

/* DNS过滤器配置结构体 */
typedef struct {
    /* 规则配置 */
    dns_rule_entry_t *rules;             /* 规则链表头 */
    uint16_t rule_count;                 /* 规则数量 */
    uint8_t default_action;              /* 默认动作（空白名单：全部拒绝） */
    
    /* 缓存配置 */
    uint8_t enable_cache : 1;            /* 是否启用缓存 */
    uint8_t cache_size;                  /* 缓存大小 */
    uint32_t cache_ttl_ms;               /* 缓存TTL（毫秒） */
    
    /* 性能配置 */
    uint8_t enable_precompile : 1;       /* 是否启用预编译正则 */
    uint8_t enable_hash_index : 1;       /* 是否启用哈希索引 */
    
    uint8_t reserved[2];                 /* 保留字节 */
} gostc_dns_config_t;

/* DNS过滤器上下文结构体 */
typedef struct {
    /* 配置信息 */
    gostc_dns_config_t config;           /* DNS配置 */
    
    /* 规则管理 */
    dns_rule_entry_t *rule_list;         /* 规则链表 */
    dns_rule_entry_t **hash_index;       /* 哈希索引表（用于精确匹配加速） */
    uint16_t hash_table_size;            /* 哈希表大小 */
    
    /* 缓存管理 */
    dns_cache_entry_t *cache;            /* 缓存数组 */
    uint8_t cache_count;                 /* 当前缓存条目数 */
    
    /* 统计信息 */
    uint32_t total_queries;              /* 总查询数 */
    uint32_t allowed_queries;            /* 允许的查询数 */
    uint32_t denied_queries;             /* 阻止的查询数 */
    uint32_t cache_hits;                 /* 缓存命中数 */
    uint32_t regex_matches;              /* 正则匹配数 */
    uint32_t wildcard_matches;           /* 通配符匹配数 */
    uint32_t exact_matches;              /* 精确匹配数 */
    
    /* 性能统计 */
    uint32_t avg_match_time_us;          /* 平均匹配时间（微秒） */
    uint32_t max_match_time_us;          /* 最大匹配时间（微秒） */
    
    /* 状态信息 */
    uint8_t initialized : 1;             /* 是否已初始化 */
    uint8_t enabled : 1;                 /* 是否启用 */
    
    /* 互斥锁 */
    void *mutex;                         /* 线程安全互斥锁 */
} gostc_dns_ctx_t;

/* DNS查询结果结构体 */
typedef struct {
    char domain[256];                    /* 查询的域名 */
    uint32_t ip_addr;                    /* 解析的IP地址（网络字节序） */
    uint8_t action;                      /* 动作：ALLOW/DENY */
    uint8_t from_cache : 1;              /* 是否来自缓存 */
    uint8_t match_type;                  /* 匹配类型 */
    uint32_t rule_id;                    /* 匹配的规则ID */
    uint32_t match_time_us;              /* 匹配时间（微秒） */
    
    /* 错误信息 */
    int32_t error_code;                  /* 错误码 */
    char error_msg[128];                 /* 错误消息 */
} dns_query_result_t;

/* 函数声明 */

/**
 * @brief   初始化DNS过滤器
 * @param   config  DNS配置指针（如果为NULL则使用默认配置）
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_dns_init(const gostc_dns_config_t *config);

/**
 * @brief   反初始化DNS过滤器
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_dns_deinit(void);

/**
 * @brief   添加DNS规则
 * @param   pattern   匹配模式
 * @param   action    动作：ALLOW/DENY
 * @param   match_type 匹配类型：精确/通配符/正则
 * @return  uint32_t  成功返回规则ID，失败返回0
 */
uint32_t gostc_dns_add_rule(const char *pattern, uint8_t action, uint8_t match_type);

/**
 * @brief   删除DNS规则
 * @param   rule_id   规则ID
 * @return  int32_t   成功返回0，失败返回错误码
 */
int32_t gostc_dns_delete_rule(uint32_t rule_id);

/**
 * @brief   清除所有DNS规则
 * @return  int32_t   成功返回0，失败返回错误码
 */
int32_t gostc_dns_clear_rules(void);

/**
 * @brief   查询域名是否允许
 * @param   domain    域名
 * @param   result    查询结果指针（可为NULL）
 * @return  int32_t   允许返回0，阻止返回错误码
 */
int32_t gostc_dns_query(const char *domain, dns_query_result_t *result);

/**
 * @brief   批量查询域名
 * @param   domains   域名数组
 * @param   count     域名数量
 * @param   results   结果数组
 * @return  int32_t   成功返回0，失败返回错误码
 */
int32_t gostc_dns_batch_query(const char **domains, uint32_t count, dns_query_result_t *results);

/**
 * @brief   添加缓存条目
 * @param   domain    域名
 * @param   ip_addr   IP地址（网络字节序）
 * @param   action    动作：ALLOW/DENY
 * @return  int32_t   成功返回0，失败返回错误码
 */
int32_t gostc_dns_add_cache(const char *domain, uint32_t ip_addr, uint8_t action);

/**
 * @brief   查找缓存条目
 * @param   domain    域名
 * @param   result    查询结果指针
 * @return  int32_t   找到返回0，未找到返回错误码
 */
int32_t gostc_dns_lookup_cache(const char *domain, dns_query_result_t *result);

/**
 * @brief   清除DNS缓存
 * @return  int32_t   成功返回0，失败返回错误码
 */
int32_t gostc_dns_clear_cache(void);

/**
 * @brief   重新加载DNS配置
 * @param   config    新的DNS配置
 * @return  int32_t   成功返回0，失败返回错误码
 */
int32_t gostc_dns_reconfig(const gostc_dns_config_t *config);

/**
 * @brief   获取DNS统计信息
 * @param   stats     统计信息结构体指针
 * @return  int32_t   成功返回0，失败返回错误码
 */
int32_t gostc_dns_get_stats(gostc_dns_ctx_t *stats);

/**
 * @brief   重置DNS统计信息
 * @return  int32_t   成功返回0，失败返回错误码
 */
int32_t gostc_dns_reset_stats(void);

/**
 * @brief   导出DNS规则到文件（如果支持文件系统）
 * @param   path      文件路径
 * @return  int32_t   成功返回0，失败返回错误码
 */
int32_t gostc_dns_export_rules(const char *path);

/**
 * @brief   从文件导入DNS规则（如果支持文件系统）
 * @param   path      文件路径
 * @return  int32_t   成功返回0，失败返回错误码
 */
int32_t gostc_dns_import_rules(const char *path);

/**
 * @brief   预编译正则表达式
 * @return  int32_t   成功返回0，失败返回错误码
 * 
 * @note    提高正则匹配性能，但会增加内存使用
 */
int32_t gostc_dns_precompile_regex(void);

/**
 * @brief   构建哈希索引
 * @return  int32_t   成功返回0，失败返回错误码
 * 
 * @note    提高精确匹配性能，但会增加内存使用
 */
int32_t gostc_dns_build_hash_index(void);

/**
 * @brief   验证域名格式
 * @param   domain    域名
 * @return  int32_t   有效返回0，无效返回错误码
 */
int32_t gostc_dns_validate_domain(const char *domain);

/**
 * @brief   设置默认动作
 * @param   action    默认动作：ALLOW/DENY
 * @return  int32_t   成功返回0，失败返回错误码
 */
int32_t gostc_dns_set_default_action(uint8_t action);

/**
 * @brief   获取规则数量
 * @return  uint32_t  规则数量
 */
uint32_t gostc_dns_get_rule_count(void);

/**
 * @brief   迭代所有规则
 * @param   callback  回调函数
 * @param   user_data 用户数据
 * @return  int32_t   成功返回处理的规则数，失败返回错误码
 */
int32_t gostc_dns_iterate_rules(int32_t (*callback)(dns_rule_entry_t *rule, void *user_data), void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* __GOSTC_DNS_H__ */