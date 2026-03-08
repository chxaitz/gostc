/**
 * @file    gostc_tls.h
 * @brief   通信代理TLS加密头文件
 * @author  Kilo Code
 * @date    2026-03-07
 * @version 1.0.0
 * 
 * @note    基于mbedTLS实现TLS加密功能
 * @warning TLS功能需要mbedTLS库支持，内存占用较大
 */

#ifndef __GOSTC_TLS_H__
#define __GOSTC_TLS_H__

#ifdef __cplusplus
extern "C" {
#endif

/* 包含头文件 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* 宏定义 */
#define TLS_MAX_SESSION_CACHE  8      /* 最大TLS会话缓存数 */
#define TLS_MAX_CERT_SIZE      2048   /* 最大证书大小 */
#define TLS_MAX_KEY_SIZE       2048   /* 最大密钥大小 */

#define TLS_HANDSHAKE_TIMEOUT_MS 10000 /* TLS握手超时时间（毫秒） */

/* TLS版本定义 */
typedef enum {
    TLS_VERSION_1_0 = 0,      /* TLS 1.0 */
    TLS_VERSION_1_1,          /* TLS 1.1 */
    TLS_VERSION_1_2,          /* TLS 1.2 */
    TLS_VERSION_1_3,          /* TLS 1.3（如果支持） */
    TLS_VERSION_MAX
} tls_version_e;

/* TLS配置结构体 */
typedef struct {
    /* 版本配置 */
    tls_version_e min_version;        /* 最小TLS版本 */
    tls_version_e max_version;        /* 最大TLS版本 */
    uint8_t require_tlsv12 : 1;       /* 是否要求TLS 1.2+ */
    
    /* 证书配置 */
    const char *ca_cert;              /* CA证书数据 */
    uint16_t ca_cert_len;             /* CA证书长度 */
    const char *client_cert;          /* 客户端证书数据 */
    uint16_t client_cert_len;         /* 客户端证书长度 */
    const char *client_key;           /* 客户端私钥数据 */
    uint16_t client_key_len;          /* 客户端私钥长度 */
    
    /* 验证配置 */
    uint8_t verify_cert : 1;          /* 是否验证服务器证书 */
    uint8_t verify_hostname : 1;      /* 是否验证主机名 */
    uint8_t allow_self_signed : 1;    /* 是否允许自签名证书 */
    
    /* 性能配置 */
    uint8_t enable_session_cache : 1; /* 是否启用会话缓存 */
    uint8_t session_cache_size;       /* 会话缓存大小 */
    uint16_t handshake_timeout_ms;    /* 握手超时时间（毫秒） */
    
    /* 密码套件配置 */
    const char *ciphersuites;         /* 密码套件列表 */
    
    uint8_t reserved[2];              /* 保留字节 */
} gostc_tls_config_t;

/* TLS上下文结构体 */
typedef struct gostc_tls_ctx {
    /* 配置信息 */
    gostc_tls_config_t config;        /* TLS配置 */
    
    /* mbedTLS上下文 */
    void *ssl_ctx;                    /* mbedTLS SSL上下文 */
    void *ssl_config;                 /* mbedTLS SSL配置 */
    void *cacert;                     /* CA证书 */
    void *clicert;                    /* 客户端证书 */
    void *pkey;                       /* 客户端私钥 */
    
    /* 会话缓存 */
    void *session_cache[TLS_MAX_SESSION_CACHE]; /* 会话缓存数组 */
    uint8_t session_cache_count;      /* 会话缓存数量 */
    
    /* 统计信息 */
    uint32_t handshake_count;         /* 握手次数 */
    uint32_t handshake_success;       /* 握手成功次数 */
    uint32_t handshake_failed;        /* 握手失败次数 */
    uint32_t bytes_encrypted;         /* 加密字节数 */
    uint32_t bytes_decrypted;         /* 解密字节数 */
    
    /* 状态信息 */
    uint8_t initialized : 1;          /* 是否已初始化 */
    uint8_t enabled : 1;              /* 是否启用 */
    
    /* 互斥锁 */
    void *mutex;                      /* 线程安全互斥锁 */
} gostc_tls_ctx_t;

/* TLS连接结构体 */
typedef struct {
    /* 连接信息 */
    int fd;                           /* 底层套接字文件描述符 */
    void *ssl;                        /* mbedTLS SSL结构体 */
    
    /* 状态信息 */
    uint8_t connected : 1;            /* 是否已连接 */
    uint8_t handshaked : 1;           /* 是否已完成握手 */
    uint8_t encrypted : 1;            /* 是否已加密 */
    
    /* 错误信息 */
    int last_error;                   /* 最后错误码 */
    char error_msg[128];              /* 错误消息 */
    
    /* 性能统计 */
    uint32_t handshake_time_ms;       /* 握手时间（毫秒） */
    uint32_t create_time;             /* 创建时间戳 */
    
    /* 关联的连接ID */
    uint32_t conn_id;                 /* 关联的gostc连接ID */
} gostc_tls_conn_t;

/* 函数声明 */

/**
 * @brief   初始化TLS引擎
 * @param   config  TLS配置指针（如果为NULL则使用默认配置）
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_tls_init(const gostc_tls_config_t *config);

/**
 * @brief   反初始化TLS引擎
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_tls_deinit(void);

/**
 * @brief   创建TLS连接
 * @param   fd      底层套接字文件描述符
 * @param   hostname 服务器主机名（用于证书验证）
 * @param   conn_id  关联的连接ID
 * @return  gostc_tls_conn_t* 成功返回TLS连接指针，失败返回NULL
 */
gostc_tls_conn_t *gostc_tls_connect(int fd, const char *hostname, uint32_t conn_id);

/**
 * @brief   执行TLS握手
 * @param   tls_conn TLS连接指针
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_tls_handshake(gostc_tls_conn_t *tls_conn);

/**
 * @brief   发送加密数据
 * @param   tls_conn TLS连接指针
 * @param   data     要发送的数据
 * @param   len      数据长度
 * @return  int32_t 成功返回发送的字节数，失败返回错误码
 */
int32_t gostc_tls_send(gostc_tls_conn_t *tls_conn, const void *data, size_t len);

/**
 * @brief   接收解密数据
 * @param   tls_conn TLS连接指针
 * @param   buffer   接收缓冲区
 * @param   len      缓冲区长度
 * @return  int32_t 成功返回接收的字节数，失败返回错误码
 */
int32_t gostc_tls_recv(gostc_tls_conn_t *tls_conn, void *buffer, size_t len);

/**
 * @brief   关闭TLS连接
 * @param   tls_conn TLS连接指针
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_tls_close(gostc_tls_conn_t *tls_conn);

/**
 * @brief   获取TLS连接状态
 * @param   tls_conn TLS连接指针
 * @return  int32_t 连接状态（0=未连接，1=已连接，2=已握手，<0=错误）
 */
int32_t gostc_tls_get_state(gostc_tls_conn_t *tls_conn);

/**
 * @brief   获取TLS错误信息
 * @param   tls_conn TLS连接指针
 * @param   buffer   错误信息缓冲区
 * @param   len      缓冲区长度
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_tls_get_error(gostc_tls_conn_t *tls_conn, char *buffer, size_t len);

/**
 * @brief   重新配置TLS引擎
 * @param   config  新的TLS配置
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_tls_reconfig(const gostc_tls_config_t *config);

/**
 * @brief   获取TLS统计信息
 * @param   stats   统计信息结构体指针
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_tls_get_stats(gostc_tls_ctx_t *stats);

/**
 * @brief   重置TLS统计信息
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_tls_reset_stats(void);

/**
 * @brief   清除TLS会话缓存
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_tls_clear_session_cache(void);

/**
 * @brief   验证证书
 * @param   cert     证书数据
 * @param   cert_len 证书长度
 * @param   hostname 主机名（用于验证）
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_tls_verify_cert(const char *cert, size_t cert_len, const char *hostname);

/**
 * @brief   加载证书
 * @param   cert_type 证书类型：0=CA证书，1=客户端证书，2=客户端私钥
 * @param   data     证书数据
 * @param   len      数据长度
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_tls_load_cert(uint8_t cert_type, const char *data, size_t len);

/**
 * @brief   卸载证书
 * @param   cert_type 证书类型：0=CA证书，1=客户端证书，2=客户端私钥
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_tls_unload_cert(uint8_t cert_type);

/**
 * @brief   设置TLS调试级别
 * @param   level    调试级别：0=无，1=错误，2=信息，3=详细
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_tls_set_debug_level(uint8_t level);

#ifdef __cplusplus
}
#endif

#endif /* __GOSTC_TLS_H__ */