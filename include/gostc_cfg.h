/**
 * @file    gostc_cfg.h
 * @brief   通信代理配置管理头文件
 * @author  mosser
 * @date    2026-03-07
 * @version 1.0.0
 * 
 * @note    配置采用硬编码方式，支持运行时动态更新
 * @warning 配置验证在应用前进行，无效配置将被拒绝
 */

#ifndef __GOSTC_CFG_H__
#define __GOSTC_CFG_H__

#ifdef __cplusplus
extern "C" {
#endif

/* 包含头文件 */
#include <stdint.h>
#include <stdbool.h>

/* 宏定义 */
#define CONFIG_MAGIC           0x474F5354  /* "GOST"的十六进制 */
#define CONFIG_VERSION_1_0     0x00010000

#define MAX_HOSTNAME_LEN       64
#define MAX_USERNAME_LEN       32
#define MAX_PASSWORD_LEN       32
#define MAX_RULE_PATTERN_LEN   128
#define MAX_CERT_DATA_LEN      2048

#define DEFAULT_MAX_CONNECTIONS    16
#define DEFAULT_CONN_TIMEOUT_MS    5000
#define DEFAULT_TLS_TIMEOUT_MS     10000
#define DEFAULT_DNS_CACHE_SIZE     32
#define DEFAULT_LOG_LEVEL          2  /* INFO级别 */

/* 代理服务器配置结构体 */
typedef struct {
    /* 基本连接信息 */
    char server_host[MAX_HOSTNAME_LEN];    /* 代理服务器主机名/IP */
    uint16_t server_port;                  /* 代理服务器端口 */
    uint8_t server_type;                   /* 代理类型：SOCKS5/HTTP/Relay */
    
    /* 认证信息 */
    char username[MAX_USERNAME_LEN];       /* 用户名 */
    char password[MAX_PASSWORD_LEN];       /* 密码 */
    uint8_t auth_required : 1;             /* 是否需要认证 */
    uint8_t reserved : 7;                  /* 保留位 */
    
    /* 连接参数 */
    uint16_t connect_timeout_ms;           /* 连接超时（毫秒） */
    uint16_t keepalive_interval_ms;        /* 保活间隔（毫秒） */
    uint8_t retry_count;                   /* 重试次数 */
} proxy_server_config_t;

/* 代理规则条目 */
typedef struct {
    uint32_t rule_id;                      /* 规则ID */
    uint8_t protocol;                      /* 协议类型：TCP/UDP/RAW */
    uint32_t dest_ip;                      /* 目标IP（网络字节序） */
    uint32_t dest_mask;                    /* 子网掩码（网络字节序） */
    uint16_t dest_port;                    /* 目标端口（0表示任意端口） */
    uint8_t action;                        /* 动作：DIRECT/PROXY/BLOCK */
    uint8_t use_tls : 1;                   /* 是否使用TLS */
    uint8_t verify_cert : 1;               /* 是否验证证书 */
    uint8_t reserved : 6;                  /* 保留位 */
    
    struct proxy_rule_entry_t *next;       /* 下一个规则 */
} proxy_rule_entry_t;

/* 代理规则配置 */
typedef struct {
    uint16_t rule_count;                   /* 规则数量 */
    proxy_rule_entry_t *rules;             /* 规则链表头 */
    uint8_t default_action;                /* 默认动作 */
} proxy_rules_config_t;

/* DNS规则条目 */
// typedef struct {
//     uint32_t rule_id;                      /* 规则ID */
//     char pattern[MAX_RULE_PATTERN_LEN];    /* 正则表达式模式 */
//     uint8_t action;                        /* 动作：ALLOW/DENY */
//     uint8_t pattern_type;                  /* 模式类型：0=精确,1=通配符,2=正则 */
    
//     struct dns_rule_entry_t *next;         /* 下一个规则 */
// } dns_rule_entry_t;

/* DNS宏定义 */
#define DNS_MAX_PATTERN_LEN     128     /* 最大模式长度 */
#define DNS_MAX_CACHE_SIZE      32      /* 最大缓存条目数 */
#define DNS_CACHE_TTL_MS        300000  /* 缓存TTL（5分钟） */

#define DNS_MATCH_EXACT         0       /* 精确匹配 */
#define DNS_MATCH_WILDCARD      1       /* 通配符匹配 */
#define DNS_MATCH_REGEX         2       /* 正则表达式匹配 */

#define DNS_ACTION_ALLOW        0       /* 允许 */
#define DNS_ACTION_DENY         1       /* 阻止 */

/* DNS规则条目结构体 */
typedef struct dns_rule_entry {
    uint32_t rule_id;                    /* 规则ID */
    char pattern[DNS_MAX_PATTERN_LEN];   /* 匹配模式 */
    uint8_t action;                      /* 动作：ALLOW/DENY */
    uint8_t match_type;                  /* 匹配类型：精确/通配符/正则 */
    
    /* 正则表达式相关 */
    void *regex_compiled;                /* 编译后的正则表达式（如果match_type=REGEX） */
    
    /* 统计信息 */
    uint32_t match_count;                /* 匹配次数 */
    uint32_t last_match_time;            /* 最后匹配时间 */
    
    /* 链表指针 */
    struct dns_rule_entry *next;         /* 下一个规则 */
} dns_rule_entry_t;

/* DNS规则配置 */
typedef struct {
    uint16_t rule_count;                   /* 规则数量 */
    dns_rule_entry_t *rules;               /* 规则链表头 */
    uint8_t default_action;                /* 默认动作（空白名单：全部拒绝） */
    uint8_t enable_cache : 1;              /* 是否启用缓存 */
    uint8_t cache_size;                    /* 缓存大小 */
    uint32_t cache_ttl_ms;                 /* 缓存TTL（毫秒） */
    uint8_t reserved[3];                   /* 保留字节 */
} dns_rules_config_t;

/* TLS规则条目 */
typedef struct {
    uint32_t rule_id;                      /* 规则ID */
    uint32_t dest_ip;                      /* 目标IP（网络字节序） */
    uint32_t dest_mask;                    /* 子网掩码（网络字节序） */
    uint16_t dest_port;                    /* 目标端口（0表示任意端口） */
    uint8_t require_tls : 1;               /* 是否要求TLS */
    uint8_t verify_cert : 1;               /* 是否验证证书 */
    uint8_t require_tlsv12 : 1;            /* 是否要求TLS 1.2+ */
    uint8_t reserved : 5;                  /* 保留位 */
    
    struct tls_rule_entry_t *next;         /* 下一个规则 */
} tls_rule_entry_t;

/* TLS规则配置 */
typedef struct {
    uint16_t rule_count;                   /* 规则数量 */
    tls_rule_entry_t *rules;               /* 规则链表头 */
    
    /* 证书配置 */
    const char *ca_cert;                   /* CA证书数据 */
    uint16_t ca_cert_len;                  /* CA证书长度 */
    const char *client_cert;               /* 客户端证书数据 */
    uint16_t client_cert_len;              /* 客户端证书长度 */
    const char *client_key;                /* 客户端私钥数据 */
    uint16_t client_key_len;               /* 客户端私钥长度 */
    
    /* TLS参数 */
    uint16_t handshake_timeout_ms;         /* 握手超时（毫秒） */
    uint8_t session_cache_size;            /* 会话缓存大小 */
} tls_rules_config_t;

/* 系统配置 */
typedef struct {
    /* 性能参数 */
    uint16_t max_connections;              /* 最大连接数 */
    uint16_t connection_timeout_ms;        /* 连接超时（毫秒） */
    uint16_t tls_handshake_timeout_ms;     /* TLS握手超时（毫秒） */
    uint8_t enable_connection_pool : 1;    /* 是否启用连接池 */
    uint8_t connection_pool_size;          /* 连接池大小 */
    
    /* 日志配置 */
    uint8_t log_level;                     /* 日志级别：0=ERROR,1=WARN,2=INFO,3=DEBUG */
    uint8_t enable_file_log : 1;           /* 是否启用文件日志（如果支持文件系统） */
    uint8_t enable_console_log : 1;        /* 是否启用控制台日志 */
    uint8_t log_buffer_size;               /* 日志缓冲区大小 */
    
    /* 诊断设置 */
    uint8_t enable_statistics : 1;         /* 是否启用统计 */
    uint8_t enable_diagnostics : 1;        /* 是否启用诊断 */
    uint16_t diagnostic_interval_ms;       /* 诊断间隔（毫秒） */
    
    uint8_t reserved[2];                   /* 保留字节 */
} system_config_t;

/* 运行时统计信息 */
typedef struct {
    /* 连接统计 */
    uint32_t total_connections;            /* 总连接数 */
    uint32_t active_connections;           /* 活动连接数 */
    uint32_t proxy_connections;            /* 代理连接数 */
    uint32_t tls_connections;              /* TLS连接数 */
    uint32_t blocked_connections;          /* 阻止的连接数 */
    
    /* 流量统计 */
    uint64_t bytes_sent;                   /* 发送字节数 */
    uint64_t bytes_received;               /* 接收字节数 */
    uint32_t packets_sent;                 /* 发送包数 */
    uint32_t packets_received;             /* 接收包数 */
    
    /* DNS统计 */
    uint32_t dns_queries;                  /* DNS查询数 */
    uint32_t dns_allowed;                  /* 允许的DNS查询数 */
    uint32_t dns_blocked;                  /* 阻止的DNS查询数 */
    uint32_t dns_cache_hits;               /* DNS缓存命中数 */
    
    /* 错误统计 */
    uint32_t connection_errors;            /* 连接错误数 */
    uint32_t tls_errors;                   /* TLS错误数 */
    uint32_t proxy_errors;                 /* 代理错误数 */
    uint32_t memory_errors;                /* 内存错误数 */
    
    /* 性能统计 */
    uint32_t avg_connection_time_ms;       /* 平均连接时间（毫秒） */
    uint32_t avg_tls_handshake_time_ms;    /* 平均TLS握手时间（毫秒） */
    uint32_t max_connection_time_ms;       /* 最大连接时间（毫秒） */
    uint32_t max_tls_handshake_time_ms;    /* 最大TLS握手时间（毫秒） */
    
    /* 时间戳 */
    uint32_t start_time;                   /* 启动时间 */
    uint32_t last_update_time;             /* 最后更新时间 */
} runtime_stats_t;

/* 全局配置结构体 */
typedef struct {
    /* 版本信息 */
    uint32_t version;
    uint32_t magic;
    
    /* 代理服务器配置 */
    proxy_server_config_t proxy_server;
    
    /* 规则配置 */
    proxy_rules_config_t proxy_rules;
    dns_rules_config_t dns_rules;
    tls_rules_config_t tls_rules;
    
    /* 系统配置 */
    system_config_t system;
    
    /* 运行时统计 */
    runtime_stats_t stats;
    
    /* 校验和 */
    uint32_t checksum;
} gostc_config_t;

/* 函数声明 */

/**
 * @brief   初始化配置管理系统
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_config_init(void);

/**
 * @brief   加载默认配置
 * @param   config  配置结构体指针
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_config_load_default(gostc_config_t *config);

/**
 * @brief   验证配置有效性
 * @param   config  配置结构体指针
 * @return  int32_t 有效返回0，无效返回错误码
 */
int32_t gostc_config_validate(const gostc_config_t *config);

/**
 * @brief   应用配置
 * @param   config  配置结构体指针
 * @return  int32_t 成功返回0，失败返回错误码
 * 
 * @note    配置验证通过后才会应用
 */
int32_t gostc_config_apply(const gostc_config_t *config);

/**
 * @brief   保存配置到文件（如果支持文件系统）
 * @param   config  配置结构体指针
 * @param   path    文件路径
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_config_save_to_file(const gostc_config_t *config, const char *path);

/**
 * @brief   从文件加载配置（如果支持文件系统）
 * @param   config  配置结构体指针
 * @param   path    文件路径
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_config_load_from_file(gostc_config_t *config, const char *path);

/**
 * @brief   获取配置项值
 * @param   key     配置项键名
 * @param   value   值缓冲区
 * @param   size    缓冲区大小
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_config_get_value(const char *key, void *value, uint32_t size);

/**
 * @brief   设置配置项值
 * @param   key     配置项键名
 * @param   value   值指针
 * @param   size    值大小
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_config_set_value(const char *key, const void *value, uint32_t size);

/**
 * @brief   重置配置为默认值
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_config_reset(void);

/**
 * @brief   获取配置校验和
 * @param   config  配置结构体指针
 * @return  uint32_t 校验和
 */
uint32_t gostc_config_calculate_checksum(const gostc_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* __GOSTC_CFG_H__ */