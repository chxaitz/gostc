/**
 * @file    gostc_err.h
 * @brief   通信代理错误处理头文件
 * @author  mosser
 * @date    2026-03-07
 * @version 1.0.0
 * 
 * @note    提供统一的错误码定义和错误处理机制
 * @warning 错误码为负值，0表示成功
 */

#ifndef __GOSTC_ERR_H__
#define __GOSTC_ERR_H__

#ifdef __cplusplus
extern "C" {
#endif

/* 包含头文件 */
#include <stdint.h>

/* 宏定义 */
#define GOSTC_ERROR_BASE        (-1000)  /* 错误码基准值 */

/* 通用错误码 */
typedef enum {
    GOSTC_OK = 0,                       /* 成功 */
    
    /* 通用错误 */
    GOSTC_ERROR = GOSTC_ERROR_BASE,     /* 一般错误 */
    GOSTC_ERROR_INVALID_PARAM,          /* 无效参数 */
    GOSTC_ERROR_INVALID_STATE,          /* 无效状态 */
    GOSTC_ERROR_NOT_INITIALIZED,        /* 未初始化 */
    GOSTC_ERROR_ALREADY_INITIALIZED,    /* 已初始化 */
    GOSTC_ERROR_NOT_SUPPORTED,          /* 不支持 */
    GOSTC_ERROR_TIMEOUT,                /* 超时 */
    GOSTC_ERROR_BUSY,                   /* 忙 */
    GOSTC_ERROR_AGAIN,                  /* 重试 */
    
    /* 内存错误 */
    GOSTC_ERROR_NO_MEMORY,              /* 内存不足 */
    GOSTC_ERROR_OUT_OF_MEMORY,          /* 内存耗尽 */
    GOSTC_ERROR_MEMORY_CORRUPTION,      /* 内存损坏 */
    GOSTC_ERROR_BUFFER_TOO_SMALL,       /* 缓冲区太小 */
    GOSTC_ERROR_BUFFER_OVERFLOW,        /* 缓冲区溢出 */
    
    /* 配置错误 */
    GOSTC_ERROR_CONFIG_INVALID,         /* 配置无效 */
    GOSTC_ERROR_CONFIG_NOT_FOUND,       /* 配置未找到 */
    GOSTC_ERROR_CONFIG_VERSION,         /* 配置版本不匹配 */
    GOSTC_ERROR_CONFIG_CHECKSUM,        /* 配置校验和错误 */
    
    /* 网络错误 */
    GOSTC_ERROR_NETWORK = GOSTC_ERROR_BASE - 100,
    GOSTC_ERROR_NETWORK_DOWN,           /* 网络不可用 */
    GOSTC_ERROR_NETWORK_UNREACHABLE,    /* 网络不可达 */
    GOSTC_ERROR_CONNECTION_REFUSED,     /* 连接被拒绝 */
    GOSTC_ERROR_CONNECTION_RESET,       /* 连接被重置 */
    GOSTC_ERROR_CONNECTION_ABORTED,     /* 连接被中止 */
    GOSTC_ERROR_CONNECTION_TIMEOUT,     /* 连接超时 */
    GOSTC_ERROR_HOST_UNREACHABLE,       /* 主机不可达 */
    GOSTC_ERROR_HOST_NOT_FOUND,         /* 主机未找到 */
    GOSTC_ERROR_ADDRESS_IN_USE,         /* 地址已被使用 */
    GOSTC_ERROR_ADDRESS_NOT_AVAILABLE,  /* 地址不可用 */
    GOSTC_ERROR_NETWORK_UNSUPPORTED,    /* 网络不支持 */
    
    /* TLS错误 */
    GOSTC_ERROR_TLS = GOSTC_ERROR_BASE - 200,
    GOSTC_ERROR_TLS_INIT_FAILED,        /* TLS初始化失败 */
    GOSTC_ERROR_TLS_HANDSHAKE_FAILED,   /* TLS握手失败 */
    GOSTC_ERROR_TLS_CERTIFICATE,        /* 证书错误 */
    GOSTC_ERROR_TLS_CERTIFICATE_EXPIRED,/* 证书过期 */
    GOSTC_ERROR_TLS_CERTIFICATE_INVALID,/* 证书无效 */
    GOSTC_ERROR_TLS_CERTIFICATE_UNTRUSTED, /* 证书不受信任 */
    GOSTC_ERROR_TLS_PROTOCOL,           /* TLS协议错误 */
    GOSTC_ERROR_TLS_CIPHER,             /* 密码套件错误 */
    GOSTC_ERROR_TLS_VERSION,            /* TLS版本不支持 */
    GOSTC_ERROR_TLS_ALERT,              /* TLS警报 */
    GOSTC_ERROR_TLS_INTERNAL,           /* TLS内部错误 */
    
    /* DNS错误 */
    GOSTC_ERROR_DNS = GOSTC_ERROR_BASE - 300,
    GOSTC_ERROR_DNS_INIT_FAILED,        /* DNS初始化失败 */
    GOSTC_ERROR_DNS_QUERY_FAILED,       /* DNS查询失败 */
    GOSTC_ERROR_DNS_PARSE_FAILED,       /* DNS解析失败 */
    GOSTC_ERROR_DNS_TIMEOUT,            /* DNS查询超时 */
    GOSTC_ERROR_DNS_SERVER_FAILED,      /* DNS服务器错误 */
    GOSTC_ERROR_DNS_FORMAT,             /* DNS格式错误 */
    GOSTC_ERROR_DNS_NOT_ALLOWED,        /* DNS不允许（白名单拒绝） */
    GOSTC_ERROR_DNS_CACHE_FULL,         /* DNS缓存已满 */
    GOSTC_ERROR_DNS_REGEX_COMPILE,      /* DNS正则编译失败 */
    
    /* 代理错误 */
    GOSTC_ERROR_PROXY = GOSTC_ERROR_BASE - 400,
    GOSTC_ERROR_PROXY_INIT_FAILED,      /* 代理初始化失败 */
    GOSTC_ERROR_PROXY_CONNECT_FAILED,   /* 代理连接失败 */
    GOSTC_ERROR_PROXY_AUTH_FAILED,      /* 代理认证失败 */
    GOSTC_ERROR_PROXY_PROTOCOL,         /* 代理协议错误 */
    GOSTC_ERROR_PROXY_SERVER,           /* 代理服务器错误 */
    GOSTC_ERROR_PROXY_UNSUPPORTED,      /* 代理类型不支持 */
    
    /* lwIP拦截错误 */
    GOSTC_ERROR_INTERCEPT = GOSTC_ERROR_BASE - 500,
    GOSTC_ERROR_INTERCEPT_INIT_FAILED,  /* 拦截初始化失败 */
    GOSTC_ERROR_INTERCEPT_HOOK_FAILED,  /* 拦截钩子安装失败 */
    GOSTC_ERROR_INTERCEPT_PCB_NOT_FOUND,/* PCB未找到 */
    GOSTC_ERROR_INTERCEPT_CONN_NOT_FOUND, /* 连接未找到 */
    GOSTC_ERROR_INTERCEPT_FUNCTION_NOT_FOUND, /* 函数未找到 */
    
    /* 连接管理错误 */
    GOSTC_ERROR_CONN = GOSTC_ERROR_BASE - 600,
    GOSTC_ERROR_CONN_NOT_FOUND,         /* 连接未找到 */
    GOSTC_ERROR_CONN_ALREADY_EXISTS,    /* 连接已存在 */
    GOSTC_ERROR_CONN_LIMIT_EXCEEDED,    /* 连接数超过限制 */
    GOSTC_ERROR_CONN_INVALID,           /* 连接无效 */
    GOSTC_ERROR_CONN_CLOSED,            /* 连接已关闭 */
    GOSTC_ERROR_CONN_BUSY,              /* 连接忙 */
    
    /* 文件系统错误（如果支持） */
    GOSTC_ERROR_FS = GOSTC_ERROR_BASE - 700,
    GOSTC_ERROR_FS_INIT_FAILED,         /* 文件系统初始化失败 */
    GOSTC_ERROR_FS_NOT_MOUNTED,         /* 文件系统未挂载 */
    GOSTC_ERROR_FS_IO,                  /* 文件系统I/O错误 */
    GOSTC_ERROR_FS_NO_SPACE,            /* 文件系统空间不足 */
    GOSTC_ERROR_FS_NOT_FOUND,           /* 文件未找到 */
    GOSTC_ERROR_FS_ACCESS_DENIED,       /* 文件访问被拒绝 */
    GOSTC_ERROR_FS_ALREADY_EXISTS,      /* 文件已存在 */
    GOSTC_ERROR_FS_INVALID_PATH,        /* 无效路径 */
    GOSTC_ERROR_FS_INVALID_FILE,        /* 无效文件 */
    
    /* 操作系统错误 */
    GOSTC_ERROR_OS = GOSTC_ERROR_BASE - 800,
    GOSTC_ERROR_OS_TASK_CREATE_FAILED,  /* 任务创建失败 */
    GOSTC_ERROR_OS_MUTEX_CREATE_FAILED, /* 互斥锁创建失败 */
    GOSTC_ERROR_OS_SEMAPHORE_CREATE_FAILED, /* 信号量创建失败 */
    GOSTC_ERROR_OS_QUEUE_CREATE_FAILED, /* 队列创建失败 */
    GOSTC_ERROR_OS_TIMER_CREATE_FAILED, /* 定时器创建失败 */
    GOSTC_ERROR_OS_MEMORY_POOL_CREATE_FAILED, /* 内存池创建失败 */
    
    /* 日志错误 */
    GOSTC_ERROR_LOG = GOSTC_ERROR_BASE - 900,
    GOSTC_ERROR_LOG_INIT_FAILED,        /* 日志初始化失败 */
    GOSTC_ERROR_LOG_BUFFER_FULL,        /* 日志缓冲区已满 */
    GOSTC_ERROR_LOG_WRITE_FAILED,       /* 日志写入失败 */
    
    /* 模块特定错误 */
    GOSTC_ERROR_MODULE_SPECIFIC = GOSTC_ERROR_BASE - 1000,
    
    GOSTC_ERROR_MAX = -1                /* 错误码结束标记 */
} gostc_error_e;

/* 错误信息结构体 */
typedef struct {
    int32_t code;                       /* 错误码 */
    const char *module;                 /* 模块名称 */
    const char *function;               /* 函数名称 */
    uint32_t line;                      /* 行号 */
    const char *message;                /* 错误消息 */
    uint32_t timestamp;                 /* 时间戳 */
} gostc_error_info_t;

/* 错误回调函数类型 */
typedef void (*gostc_error_callback_t)(const gostc_error_info_t *error_info, void *user_data);

/* 函数声明 */

/**
 * @brief   初始化错误处理系统
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_error_init(void);

/**
 * @brief   反初始化错误处理系统
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_error_deinit(void);

/**
 * @brief   设置错误回调函数
 * @param   callback  回调函数
 * @param   user_data 用户数据
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_error_set_callback(gostc_error_callback_t callback, void *user_data);

/**
 * @brief   记录错误
 * @param   code     错误码
 * @param   module   模块名称
 * @param   function 函数名称
 * @param   line     行号
 * @param   message  错误消息（可为NULL）
 * @return  int32_t 记录的错误码
 */
int32_t gostc_error_record(int32_t code, const char *module, const char *function, 
                          uint32_t line, const char *message);

/**
 * @brief   获取最后错误信息
 * @param   error_info 错误信息结构体指针
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_error_get_last(gostc_error_info_t *error_info);

/**
 * @brief   清除错误记录
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_error_clear(void);

/**
 * @brief   获取错误码描述
 * @param   code     错误码
 * @return  const char* 错误描述字符串
 */
const char *gostc_error_to_string(int32_t code);

/**
 * @brief   检查错误码是否属于特定类别
 * @param   code     错误码
 * @param   category 错误类别基准值
 * @return  bool     属于该类别返回true，否则返回false
 */
bool gostc_error_is_category(int32_t code, int32_t category);

/**
 * @brief   获取错误统计信息
 * @param   total_errors    总错误数指针
 * @param   fatal_errors    致命错误数指针
 * @param   warning_errors  警告错误数指针
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_error_get_stats(uint32_t *total_errors, uint32_t *fatal_errors, 
                             uint32_t *warning_errors);

/**
 * @brief   重置错误统计信息
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_error_reset_stats(void);

/**
 * @brief   设置错误日志级别
 * @param   level 日志级别：0=无，1=错误，2=警告，3=信息，4=调试
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_error_set_log_level(uint8_t level);

/**
 * @brief   断言宏（调试版本）
 * @param   expr 断言表达式
 */
#ifdef GOSTC_DEBUG
#define GOSTC_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            gostc_error_record(GOSTC_ERROR, __FILE__, __func__, __LINE__, "Assertion failed: " #expr); \
            os_assert_failed(__FILE__, __LINE__, #expr); \
        } \
    } while(0)
#else
#define GOSTC_ASSERT(expr) ((void)0)
#endif

/**
 * @brief   检查返回值宏
 * @param   expr 表达式（应返回错误码）
 */
#define GOSTC_CHECK(expr) \
    do { \
        int32_t __ret = (expr); \
        if (__ret < 0) { \
            return __ret; \
        } \
    } while(0)

/**
 * @brief   检查指针宏
 * @param   ptr 指针
 */
#define GOSTC_CHECK_PTR(ptr) \
    do { \
        if ((ptr) == NULL) { \
            return GOSTC_ERROR_INVALID_PARAM; \
        } \
    } while(0)

/**
 * @brief   记录错误并返回宏
 * @param   code     错误码
 * @param   message  错误消息
 */
#define GOSTC_ERROR_RETURN(code, message) \
    do { \
        gostc_error_record((code), __FILE__, __func__, __LINE__, (message)); \
        return (code); \
    } while(0)

/**
 * @brief   记录错误并跳转宏
 * @param   code     错误码
 * @param   message  错误消息
 * @param   label    跳转标签
 */
#define GOSTC_ERROR_GOTO(code, message, label) \
    do { \
        gostc_error_record((code), __FILE__, __func__, __LINE__, (message)); \
        goto label; \
    } while(0)

#ifdef __cplusplus
}
#endif

#endif /* __GOSTC_ERR_H__ */