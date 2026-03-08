/**
 * @file    gostc_conn.h
 * @brief   通信代理连接管理头文件
 * @author  Kilo Code
 * @date    2026-03-07
 * @version 1.0.0
 * 
 * @note    连接管理包括连接创建、查找、状态跟踪和资源管理
 * @warning 连接管理是线程安全的，支持多任务并发访问
 */

#ifndef __GOSTC_CONN_H__
#define __GOSTC_CONN_H__

#ifdef __cplusplus
extern "C" {
#endif

/* 包含头文件 */
#include <stdint.h>
#include <stdbool.h>

/* 宏定义 */
#define MAX_CONNECTION_ID        0xFFFFFFFF
#define INVALID_CONNECTION_ID    0

#define CONNECTION_HASH_SIZE     16  /* 连接哈希表大小，必须是2的幂 */

/* 连接上下文结构体 */
typedef struct gostc_conn_ctx {
    /* 连接标识 */
    uint32_t conn_id;                    /* 连接ID */
    void *pcb;                           /* lwIP PCB指针（tcp_pcb/udp_pcb） */
    uint8_t protocol;                    /* 协议类型：TCP/UDP/RAW */
    
    /* 地址信息 */
    uint32_t local_ip;                   /* 本地IP地址（网络字节序） */
    uint32_t remote_ip;                  /* 远程IP地址（网络字节序） */
    uint16_t local_port;                 /* 本地端口（主机字节序） */
    uint16_t remote_port;                /* 远程端口（主机字节序） */
    
    /* 代理信息 */
    uint8_t use_proxy : 1;               /* 是否使用代理 */
    uint8_t use_tls : 1;                 /* 是否使用TLS */
    uint8_t proxy_established : 1;       /* 代理连接是否已建立 */
    uint8_t tls_established : 1;         /* TLS连接是否已建立 */
    uint8_t reserved : 4;                /* 保留位 */
    
    /* 代理连接信息 */
    int proxy_fd;                        /* 代理连接文件描述符 */
    void *tls_context;                   /* TLS上下文（mbedTLS） */
    
    /* 状态信息 */
    uint8_t state;                       /* 连接状态 */
    uint32_t create_time;                /* 创建时间戳（系统tick） */
    uint32_t last_activity_time;         /* 最后活动时间戳 */
    
    /* 流量统计 */
    uint32_t bytes_sent;                 /* 已发送字节数 */
    uint32_t bytes_received;             /* 已接收字节数 */
    uint32_t packets_sent;               /* 已发送包数 */
    uint32_t packets_received;           /* 已接收包数 */
    
    /* 错误信息 */
    int32_t last_error;                  /* 最后错误码 */
    char error_msg[64];                  /* 错误消息 */
    
    /* 链表指针 */
    struct gostc_conn_ctx *next;         /* 哈希冲突链表下一个节点 */
    struct gostc_conn_ctx *prev;         /* 哈希冲突链表上一个节点 */
    
    /* 超时管理 */
    uint32_t timeout_ms;                 /* 超时时间（毫秒） */
    void *timeout_timer;                 /* 超时定时器句柄 */
    
    /* 用户数据 */
    void *user_data;                     /* 用户自定义数据指针 */
} gostc_conn_ctx_t;

/* 连接管理器结构体 */
typedef struct {
    /* 连接哈希表 */
    gostc_conn_ctx_t *hash_table[CONNECTION_HASH_SIZE];
    
    /* 连接池 */
    gostc_conn_ctx_t *free_list;         /* 空闲连接链表 */
    gostc_conn_ctx_t *active_list;       /* 活动连接链表 */
    
    /* 统计信息 */
    uint32_t total_connections;          /* 总连接数 */
    uint32_t active_connections;         /* 活动连接数 */
    uint32_t max_connections;            /* 最大连接数 */
    uint32_t connection_timeouts;        /* 连接超时数 */
    
    /* 同步机制 */
    void *mutex;                         /* 互斥锁 */
    
    /* 内存池 */
    void *memory_pool;                   /* 内存池句柄 */
} gostc_conn_mgr_t;

/* 连接查找条件结构体 */
typedef struct {
    uint32_t conn_id;                    /* 连接ID（0表示不限制） */
    void *pcb;                           /* PCB指针（NULL表示不限制） */
    uint32_t remote_ip;                  /* 远程IP（0表示不限制） */
    uint16_t remote_port;                /* 远程端口（0表示不限制） */
    uint8_t protocol;                    /* 协议类型（0xFF表示不限制） */
    uint8_t state;                       /* 连接状态（0xFF表示不限制） */
} gostc_conn_filter_t;

/* 连接迭代器回调函数类型 */
typedef int32_t (*gostc_conn_iterator_cb)(gostc_conn_ctx_t *conn, void *user_data);

/* 函数声明 */

/**
 * @brief   初始化连接管理器
 * @param   max_conn    最大连接数
 * @return  int32_t     成功返回0，失败返回错误码
 */
int32_t gostc_conn_mgr_init(uint32_t max_conn);

/**
 * @brief   反初始化连接管理器
 * @return  int32_t     成功返回0，失败返回错误码
 */
int32_t gostc_conn_mgr_deinit(void);

/**
 * @brief   创建新连接
 * @param   pcb         lwIP PCB指针
 * @param   protocol    协议类型
 * @param   local_ip    本地IP地址
 * @param   local_port  本地端口
 * @param   remote_ip   远程IP地址
 * @param   remote_port 远程端口
 * @return  uint32_t    成功返回连接ID，失败返回INVALID_CONNECTION_ID
 */
uint32_t gostc_conn_create(void *pcb, uint8_t protocol,
                          uint32_t local_ip, uint16_t local_port,
                          uint32_t remote_ip, uint16_t remote_port);

/**
 * @brief   查找连接
 * @param   filter      查找条件
 * @return  gostc_conn_ctx_t* 找到的连接指针，未找到返回NULL
 */
gostc_conn_ctx_t *gostc_conn_find(const gostc_conn_filter_t *filter);

/**
 * @brief   通过连接ID查找连接
 * @param   conn_id     连接ID
 * @return  gostc_conn_ctx_t* 找到的连接指针，未找到返回NULL
 */
gostc_conn_ctx_t *gostc_conn_find_by_id(uint32_t conn_id);

/**
 * @brief   通过PCB查找连接
 * @param   pcb         lwIP PCB指针
 * @return  gostc_conn_ctx_t* 找到的连接指针，未找到返回NULL
 */
gostc_conn_ctx_t *gostc_conn_find_by_pcb(void *pcb);

/**
 * @brief   更新连接状态
 * @param   conn        连接指针
 * @param   state       新状态
 * @return  int32_t     成功返回0，失败返回错误码
 */
int32_t gostc_conn_update_state(gostc_conn_ctx_t *conn, uint8_t state);

/**
 * @brief   更新连接代理信息
 * @param   conn        连接指针
 * @param   use_proxy   是否使用代理
 * @param   use_tls     是否使用TLS
 * @param   proxy_fd    代理连接文件描述符（-1表示无效）
 * @param   tls_context TLS上下文（NULL表示无效）
 * @return  int32_t     成功返回0，失败返回错误码
 */
int32_t gostc_conn_update_proxy_info(gostc_conn_ctx_t *conn,
                                    uint8_t use_proxy, uint8_t use_tls,
                                    int proxy_fd, void *tls_context);

/**
 * @brief   更新连接流量统计
 * @param   conn        连接指针
 * @param   bytes_sent  发送字节数增量
 * @param   bytes_recv  接收字节数增量
 * @return  int32_t     成功返回0，失败返回错误码
 */
int32_t gostc_conn_update_stats(gostc_conn_ctx_t *conn,
                               uint32_t bytes_sent, uint32_t bytes_recv);

/**
 * @brief   删除连接
 * @param   conn_id     连接ID
 * @return  int32_t     成功返回0，失败返回错误码
 */
int32_t gostc_conn_delete(uint32_t conn_id);

/**
 * @brief   删除所有连接
 * @param   force       是否强制删除（即使连接处于活动状态）
 * @return  int32_t     成功返回0，失败返回错误码
 */
int32_t gostc_conn_delete_all(bool force);

/**
 * @brief   迭代所有连接
 * @param   callback    回调函数
 * @param   user_data   用户数据
 * @return  int32_t     成功返回处理的连接数，失败返回错误码
 */
int32_t gostc_conn_iterate(gostc_conn_iterator_cb callback, void *user_data);

/**
 * @brief   获取连接管理器统计信息
 * @param   stats       统计信息结构体指针
 * @return  int32_t     成功返回0，失败返回错误码
 */
int32_t gostc_conn_get_stats(gostc_conn_mgr_t *stats);

/**
 * @brief   清理超时连接
 * @param   timeout_ms  超时时间（毫秒）
 * @return  int32_t     成功返回清理的连接数，失败返回错误码
 */
int32_t gostc_conn_cleanup_timeout(uint32_t timeout_ms);

/**
 * @brief   设置连接用户数据
 * @param   conn        连接指针
 * @param   user_data   用户数据指针
 * @return  int32_t     成功返回0，失败返回错误码
 */
int32_t gostc_conn_set_user_data(gostc_conn_ctx_t *conn, void *user_data);

/**
 * @brief   获取连接用户数据
 * @param   conn        连接指针
 * @return  void*       用户数据指针
 */
void *gostc_conn_get_user_data(gostc_conn_ctx_t *conn);

/**
 * @brief   设置连接超时
 * @param   conn        连接指针
 * @param   timeout_ms  超时时间（毫秒）
 * @return  int32_t     成功返回0，失败返回错误码
 */
int32_t gostc_conn_set_timeout(gostc_conn_ctx_t *conn, uint32_t timeout_ms);

/**
 * @brief   重置连接超时定时器
 * @param   conn        连接指针
 * @return  int32_t     成功返回0，失败返回错误码
 */
int32_t gostc_conn_reset_timeout(gostc_conn_ctx_t *conn);

/**
 * @brief   设置连接错误信息
 * @param   conn        连接指针
 * @param   error_code  错误码
 * @param   error_msg   错误消息（可为NULL）
 * @return  int32_t     成功返回0，失败返回错误码
 */
int32_t gostc_conn_set_error(gostc_conn_ctx_t *conn, int32_t error_code, const char *error_msg);

/**
 * @brief   获取连接错误信息
 * @param   conn        连接指针
 * @param   error_code  错误码输出指针（可为NULL）
 * @param   error_msg   错误消息缓冲区（可为NULL）
 * @param   buf_size    缓冲区大小
 * @return  int32_t     成功返回0，失败返回错误码
 */
int32_t gostc_conn_get_error(gostc_conn_ctx_t *conn, int32_t *error_code, char *error_msg, uint32_t buf_size);

#ifdef __cplusplus
}
#endif

#endif /* __GOSTC_CONN_H__ */