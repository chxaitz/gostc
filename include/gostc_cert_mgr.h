/**
 * @file    gostc_cert_mgr.h
 * @brief   通信代理证书管理模块头文件
 * @author  Kilo Code
 * @date    2026-03-07
 * @version 1.0.0
 * 
 * @note    嵌入式环境证书管理，支持base64编码的证书字符串
 * @warning 嵌入式系统无文件系统，证书以字符串形式存储
 */

#ifndef __GOSTC_CERT_MGR_H__
#define __GOSTC_CERT_MGR_H__

#ifdef __cplusplus
extern "C" {
#endif

/* 包含头文件 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* 宏定义 */
#define CERT_MGR_MAX_CERTS       8      /* 最大证书数量 */
#define CERT_MGR_MAX_CERT_SIZE   4096   /* 最大证书大小（字节） */
#define CERT_MGR_MAX_KEY_SIZE    4096   /* 最大密钥大小（字节） */

/* 证书类型定义 */
typedef enum {
    CERT_TYPE_CA = 0,           /* CA证书 */
    CERT_TYPE_CLIENT,           /* 客户端证书 */
    CERT_TYPE_PRIVATE_KEY,      /* 私钥 */
    CERT_TYPE_CRL,              /* 证书吊销列表 */
    CERT_TYPE_MAX
} cert_type_e;

/* 证书格式定义 */
typedef enum {
    CERT_FORMAT_PEM = 0,        /* PEM格式 */
    CERT_FORMAT_DER,            /* DER格式 */
    CERT_FORMAT_BASE64,         /* Base64编码字符串 */
    CERT_FORMAT_MAX
} cert_format_e;

/* 证书验证结果 */
typedef enum {
    CERT_VALID = 0,             /* 证书有效 */
    CERT_INVALID_FORMAT,        /* 格式无效 */
    CERT_INVALID_SIGNATURE,     /* 签名无效 */
    CERT_EXPIRED,               /* 证书过期 */
    CERT_NOT_YET_VALID,         /* 证书尚未生效 */
    CERT_REVOKED,               /* 证书已吊销 */
    CERT_HOSTNAME_MISMATCH,     /* 主机名不匹配 */
    CERT_VERIFY_FAILED          /* 验证失败 */
} cert_verify_result_e;

/* 证书信息结构体 */
typedef struct {
    /* 证书基本信息 */
    cert_type_e type;           /* 证书类型 */
    cert_format_e format;       /* 证书格式 */
    
    /* 证书数据 */
    const char *data;           /* 证书数据指针 */
    uint16_t data_len;          /* 证书数据长度 */
    
    /* 证书元数据 */
    char subject[128];          /* 证书主题 */
    char issuer[128];           /* 颁发者 */
    uint32_t not_before;        /* 生效时间（Unix时间戳） */
    uint32_t not_after;         /* 过期时间（Unix时间戳） */
    char serial_number[64];     /* 序列号 */
    
    /* 状态信息 */
    uint8_t loaded : 1;         /* 是否已加载 */
    uint8_t verified : 1;       /* 是否已验证 */
    uint8_t valid : 1;          /* 是否有效 */
    uint8_t reserved : 5;       /* 保留位 */
    
    /* 引用计数 */
    uint8_t ref_count;          /* 引用计数 */
} cert_info_t;

/* 证书管理器上下文 */
typedef struct {
    /* 证书存储 */
    // cert_info_t certs[CERT_MGR_MAX_CERTS];  /* 证书数组 */
    cert_info_t cert_ca;                    /* CA证书 */
    cert_info_t cert_key;                   /* 私钥证书 */
    cert_info_t cert_crt;                   /* 公钥证书 */
    uint8_t cert_count;                     /* 证书数量 */
    
    /* 内存管理 */
    void *memory_pool;                      /* 内存池句柄 */
    
    /* 统计信息 */
    uint32_t load_count;                    /* 加载次数 */
    uint32_t verify_count;                  /* 验证次数 */
    uint32_t verify_success;                /* 验证成功次数 */
    uint32_t verify_failed;                 /* 验证失败次数 */
    
    /* 状态信息 */
    uint8_t initialized : 1;                /* 是否已初始化 */
    uint8_t enabled : 1;                    /* 是否启用 */
    uint8_t reserved : 6;                   /* 保留位 */
    
    /* 互斥锁 */
    void *mutex;                            /* 线程安全互斥锁 */
} cert_mgr_ctx_t;

/* 证书验证配置 */
typedef struct {
    uint8_t verify_signature : 1;           /* 验证签名 */
    uint8_t verify_expiry : 1;              /* 验证有效期 */
    uint8_t verify_hostname : 1;            /* 验证主机名 */
    uint8_t check_revocation : 1;           /* 检查吊销状态 */
    uint8_t allow_self_signed : 1;          /* 允许自签名证书 */
    
    const char *expected_hostname;          /* 期望的主机名 */
    uint32_t current_time;                  /* 当前时间（Unix时间戳） */
    
    uint8_t reserved[3];                    /* 保留字节 */
} cert_verify_config_t;

/* 函数声明 */

/**
 * @brief   初始化证书管理器
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_cert_mgr_init(void);

/**
 * @brief   反初始化证书管理器
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_cert_mgr_deinit(void);

/**
 * @brief   加载证书
 * @param   type    证书类型
 * @param   format  证书格式
 * @param   data    证书数据
 * @param   len     数据长度
 * @return  int32_t 成功返回证书ID（>=0），失败返回错误码
 */
int32_t gostc_cert_mgr_load(cert_type_e type, cert_format_e format, 
                           const char *data, size_t len);

/**
 * @brief   卸载证书
 * @param   cert_id 证书ID
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_cert_mgr_unload(int32_t cert_id);

/**
 * @brief   验证证书
 * @param   cert_id 证书ID
 * @param   config  验证配置
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_cert_mgr_verify(int32_t cert_id, const cert_verify_config_t *config);

/**
 * @brief   获取证书信息
 * @param   cert_id 证书ID
 * @param   info    证书信息结构体指针
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_cert_mgr_get_info(int32_t cert_id, cert_info_t *info);

/**
 * @brief   查找证书
 * @param   type    证书类型
 * @param   subject 证书主题（可选）
 * @return  int32_t 成功返回证书ID（>=0），失败返回错误码
 */
int32_t gostc_cert_mgr_find(cert_type_e type, const char *subject);

/**
 * @brief   获取证书引用
 * @param   cert_id 证书ID
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_cert_mgr_add_ref(int32_t cert_id);

/**
 * @brief   释放证书引用
 * @param   cert_id 证书ID
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_cert_mgr_release(int32_t cert_id);

/**
 * @brief   清除所有证书
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_cert_mgr_clear_all(void);

/**
 * @brief   获取证书管理器统计信息
 * @param   ctx     证书管理器上下文指针
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_cert_mgr_get_stats(cert_mgr_ctx_t *ctx);

/**
 * @brief   重置证书管理器统计信息
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_cert_mgr_reset_stats(void);

/**
 * @brief   解析base64编码的证书
 * @param   base64_data base64编码的证书数据
 * @param   base64_len  base64数据长度
 * @param   output      输出缓冲区
 * @param   output_len  输出缓冲区长度
 * @return  int32_t 成功返回解码后的数据长度，失败返回错误码
 */
int32_t gostc_cert_mgr_decode_base64(const char *base64_data, size_t base64_len,
                                   uint8_t *output, size_t output_len);

/**
 * @brief   验证证书链
 * @param   cert_ids    证书ID数组
 * @param   cert_count  证书数量
 * @param   config      验证配置
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_cert_mgr_verify_chain(const int32_t *cert_ids, uint8_t cert_count,
                                  const cert_verify_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* __GOSTC_CERT_MGR_H__ */