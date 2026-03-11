/**
 * @file    gostc_cert_mgr.c
 * @brief   通信代理证书管理模块实现
 * @author  mosser
 * @date    2026-03-07
 * @version 1.0.0
 * 
 * @note    嵌入式环境证书管理，支持base64编码的证书字符串
 * @warning 嵌入式系统无文件系统，证书以字符串形式存储
 */

#include "gostc_cert_mgr.h"
#include "gostc_err.h"
#include "gostc_os.h"
#include <string.h>
#include <time.h>

/* mbedTLS头文件 */
#include "mbedtls/base64.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"

/* 模块内部全局变量 */
static cert_mgr_ctx_t g_cert_mgr_ctx;
static bool g_initialized = false;

/* 内存池名称 */
#define CERT_MGR_MEMORY_POOL_NAME "cert_mgr_pool"

/* 内部函数声明 */
static int32_t _cert_mgr_validate_params(cert_type_e type, cert_format_e format,
                                       const char *data, size_t len);
static int32_t _cert_mgr_parse_cert_info(cert_info_t *cert);
static int32_t _cert_mgr_decode_pem(const char *pem_data, size_t pem_len,
                                  uint8_t *der_output, size_t *der_len);
static int32_t _cert_mgr_base64_decode(const char *base64_data, size_t base64_len,
                                     uint8_t *output, size_t *output_len);
static int32_t _cert_mgr_verify_certificate(cert_info_t *cert,
                                          const cert_verify_config_t *config);

/* 内部函数实现 */

/**
 * @brief   验证参数有效性
 */
static int32_t _cert_mgr_validate_params(cert_type_e type, cert_format_e format,
                                       const char *data, size_t len)
{
    /* 检查证书类型 */
    if (type >= CERT_TYPE_MAX) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 检查证书格式 */
    if (format >= CERT_FORMAT_MAX) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 检查数据指针 */
    if (data == NULL) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 检查数据长度 */
    if (len == 0) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 检查数据长度限制 */
    if (len > CERT_MGR_MAX_CERT_SIZE) {
        return GOSTC_ERROR_BUFFER_TOO_SMALL;
    }
    
    return GOSTC_OK;
}

/**
 * @brief   解析证书信息
 */
static int32_t _cert_mgr_parse_cert_info(cert_info_t *cert)
{
    /* TODO: 实现证书信息解析
     * 需要解析证书的subject、issuer、有效期等信息
     * 由于嵌入式环境限制，这里先实现基本框架
     */
    
    if (cert == NULL) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 设置默认值 */
    memset(cert->subject, 0, sizeof(cert->subject));
    memset(cert->issuer, 0, sizeof(cert->issuer));
    memset(cert->serial_number, 0, sizeof(cert->serial_number));
    
    cert->not_before = 0;
    cert->not_after = 0;
    
    /* 根据证书类型设置默认主题 */
    switch (cert->type) {
        case CERT_TYPE_CA:
            strncpy(cert->subject, "CA Certificate", sizeof(cert->subject) - 1);
            break;
        case CERT_TYPE_CLIENT:
            strncpy(cert->subject, "Client Certificate", sizeof(cert->subject) - 1);
            break;
        case CERT_TYPE_PRIVATE_KEY:
            strncpy(cert->subject, "Private Key", sizeof(cert->subject) - 1);
            break;
        case CERT_TYPE_CRL:
            strncpy(cert->subject, "Certificate Revocation List", sizeof(cert->subject) - 1);
            break;
        default:
            break;
    }
    
    /* 设置默认有效期（1年） */
    cert->not_before = os_get_tick_count();
    cert->not_after = cert->not_before + 31536000; /* 365天 */
    
    return GOSTC_OK;
}

/**
 * @brief   解码PEM格式证书
 */
static int32_t _cert_mgr_decode_pem(const char *pem_data, size_t pem_len,
                                  uint8_t *der_output, size_t *der_len)
{
    /* TODO: 实现PEM到DER格式的转换
     * PEM格式以"-----BEGIN CERTIFICATE-----"开头
     * 以"-----END CERTIFICATE-----"结尾
     * 中间是base64编码的数据
     */
    
    (void)pem_data;
    (void)pem_len;
    (void)der_output;
    (void)der_len;
    
    return GOSTC_ERROR_NOT_SUPPORTED;
}

/**
 * @brief   Base64解码
 */
static int32_t _cert_mgr_base64_decode(const char *base64_data, size_t base64_len,
                                     uint8_t *output, size_t *output_len)
{
    size_t required_len = 0;
    int ret;
    
    if (base64_data == NULL || base64_len == 0 || output_len == NULL) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 计算解码后所需缓冲区大小 */
    ret = mbedtls_base64_decode(NULL, 0, &required_len,
                               (const unsigned char *)base64_data, base64_len);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        return GOSTC_ERROR_TLS_CERTIFICATE_INVALID;
    }
    
    /* 检查输出缓冲区是否足够 */
    if (output == NULL || *output_len < required_len) {
        *output_len = required_len;
        return GOSTC_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* 执行base64解码 */
    ret = mbedtls_base64_decode(output, *output_len, output_len,
                               (const unsigned char *)base64_data, base64_len);
    if (ret != 0) {
        /* 转换mbedTLS错误码为GOSTC错误码 */
        if (ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER) {
            return GOSTC_ERROR_TLS_CERTIFICATE_INVALID;
        }
        return GOSTC_ERROR_TLS_INTERNAL;
    }
    
    return GOSTC_OK;

}

static int _mbedtls_x509_crt_time_is_past(const mbedtls_x509_time *now, 
                                        const mbedtls_x509_time *valid_to)
{
    /* 如果 now >= valid_to，表示已过期 */
    if (now->year > valid_to->year) return 1;
    if (now->year < valid_to->year) return 0;
    
    if (now->mon > valid_to->mon) return 1;
    if (now->mon < valid_to->mon) return 0;
    
    if (now->day > valid_to->day) return 1;
    if (now->day < valid_to->day) return 0;
    
    if (now->hour > valid_to->hour) return 1;
    if (now->hour < valid_to->hour) return 0;
    
    if (now->min > valid_to->min) return 1;
    if (now->min < valid_to->min) return 0;
    
    if (now->sec >= valid_to->sec) return 1;
    return 0;
}

static int _mbedtls_x509_crt_time_is_future(const mbedtls_x509_time *now,
                                          const mbedtls_x509_time *valid_from)
{
    /* 如果 now < valid_from，表示尚未生效 */
    if (now->year < valid_from->year) return 1;
    if (now->year > valid_from->year) return 0;
    
    if (now->mon < valid_from->mon) return 1;
    if (now->mon > valid_from->mon) return 0;
    
    if (now->day < valid_from->day) return 1;
    if (now->day > valid_from->day) return 0;
    
    if (now->hour < valid_from->hour) return 1;
    if (now->hour > valid_from->hour) return 0;
    
    if (now->min < valid_from->min) return 1;
    if (now->min > valid_from->min) return 0;
    
    if (now->sec < valid_from->sec) return 1;
    return 0;
}

/**
 * @brief   验证证书
 */
static int32_t _cert_mgr_verify_certificate(cert_info_t *cert,
                                          const cert_verify_config_t *config)
{
    int ret;
    mbedtls_x509_crt x509_crt;
    const mbedtls_x509_crt_profile *profile = &mbedtls_x509_crt_profile_default;
    uint32_t flags = 0;
    
    if (cert == NULL || config == NULL) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    if (!cert->loaded) {
        return GOSTC_ERROR_TLS_CERTIFICATE_INVALID;
    }
    
    /* 初始化mbedTLS证书结构 */
    mbedtls_x509_crt_init(&x509_crt);
    
    /* 解析证书 */
    ret = mbedtls_x509_crt_parse(&x509_crt,
                                (const unsigned char *)cert->data,
                                cert->data_len);
    if (ret != 0) {
        mbedtls_x509_crt_free(&x509_crt);
        return GOSTC_ERROR_TLS_CERTIFICATE_INVALID;
    }
    
    /* 验证证书签名 */
    if (config->verify_signature) {
        ret = mbedtls_x509_crt_verify_with_profile(&x509_crt, 
                                                   config->trusted_ca,  /* 需要传入CA证书链 */
                                                   NULL,                /* 不需要CRL */
                                                   profile,
                                                   NULL,                /* 不需要CN检查 */
                                                   &flags,              /* 修正：传入uint32_t指针 */
                                                   NULL,                /* 不需要验证回调 */
                                                   NULL);               /* 回调上下文 */
        if (ret != 0 || flags != 0) {  /* 修正：同时检查返回值和验证标志 */
            mbedtls_x509_crt_free(&x509_crt);
            return GOSTC_ERROR_TLS_CERTIFICATE_INVALID;
        }
    }
    
    /* 验证证书有效期 */
    if (config->verify_expiry && config->current_time > 0) {
        /* 将当前时间转换为mbedTLS时间格式 */
        mbedtls_x509_time current_time;
        time_t t = (time_t)config->current_time;
        struct tm *tm_info = gmtime(&t);
        
        if (tm_info) {
            current_time.year = tm_info->tm_year + 1900;
            current_time.mon = tm_info->tm_mon + 1;
            current_time.day = tm_info->tm_mday;
            current_time.hour = tm_info->tm_hour;
            current_time.min = tm_info->tm_min;
            current_time.sec = tm_info->tm_sec;
            
            /* 检查证书是否过期 - 需要自己比较时间 */
            if (_mbedtls_x509_crt_time_is_past(&current_time, &x509_crt.valid_to) != 0) {
                mbedtls_x509_crt_free(&x509_crt);
                return GOSTC_ERROR_TLS_CERTIFICATE_EXPIRED;
            }
            
            /* 检查证书是否尚未生效 - 需要自己比较时间 */
            if (_mbedtls_x509_crt_time_is_future(&current_time, &x509_crt.valid_from) != 0) {
                mbedtls_x509_crt_free(&x509_crt);
                return GOSTC_ERROR_TLS_CERTIFICATE_INVALID;
            }
        }
    }
    
    /* 验证主机名 - 修正5：使用正确的函数 */
    if (config->verify_hostname && config->expected_hostname != NULL) {
        ret = mbedtls_x509_crt_check_expected_hostname(&x509_crt, config->expected_hostname);
        if (ret != 0) {
            mbedtls_x509_crt_free(&x509_crt);
            return GOSTC_ERROR_TLS_CERTIFICATE_UNTRUSTED;
        }
    }
    
    /* 检查自签名证书 */
    if (!config->allow_self_signed) {
        /* 检查证书是否自签名 - 修正6：使用正确的函数 */
        if (mbedtls_x509_crt_is_self_signed(&x509_crt) == 1) {
            mbedtls_x509_crt_free(&x509_crt);
            return GOSTC_ERROR_TLS_CERTIFICATE_UNTRUSTED;
        }
    }
    
    mbedtls_x509_crt_free(&x509_crt);
    return GOSTC_OK;
}

/* 公共函数实现 */

/**
 * @brief   初始化证书管理器
 */
int32_t gostc_cert_mgr_init(void)
{
    os_error_e os_err;
    
    if (g_initialized) {
        return GOSTC_OK;
    }
    
    /* 初始化上下文 */
    memset(&g_cert_mgr_ctx, 0, sizeof(cert_mgr_ctx_t));
    
    /* 初始化证书数组 */
    /* CA证书初始化 */
    memset(&g_cert_mgr_ctx.cert_ca, 0, sizeof(cert_info_t));
    g_cert_mgr_ctx.cert_ca.loaded = 0;
    g_cert_mgr_ctx.cert_ca.ref_count = 0;

    /* 私钥证书初始化 */
    memset(&g_cert_mgr_ctx.cert_key, 0, sizeof(cert_info_t));
    g_cert_mgr_ctx.cert_key.loaded = 0;
    g_cert_mgr_ctx.cert_key.ref_count = 0;

    /* 公钥证书初始化 */
    memset(&g_cert_mgr_ctx.cert_crt, 0, sizeof(cert_info_t));
    g_cert_mgr_ctx.cert_crt.loaded = 0;
    g_cert_mgr_ctx.cert_crt.ref_count = 0;
    
    /* 创建互斥锁 */
    os_err = os_mutex_create(&g_cert_mgr_ctx.mutex);
    if (os_err != OS_OK) {
        return GOSTC_ERROR;
    }
    
    g_cert_mgr_ctx.initialized = 1;
    g_cert_mgr_ctx.enabled = 1;
    g_initialized = true;
    
    return GOSTC_OK;
}

/**
 * @brief   反初始化证书管理器
 */
int32_t gostc_cert_mgr_deinit(void)
{
    if (!g_initialized) {
        return GOSTC_OK;
    }
    
    /* 清除所有证书 */
    gostc_cert_mgr_clear_all();
    
    /* 销毁互斥锁 */
    if (g_cert_mgr_ctx.mutex != NULL) {
        /* 注意：当前OS抽象层没有os_mutex_destroy函数 */
        /* 在嵌入式环境中，互斥锁通常不需要显式销毁 */
        g_cert_mgr_ctx.mutex = NULL;
    }
    
    /* 重置上下文 */
    memset(&g_cert_mgr_ctx, 0, sizeof(cert_mgr_ctx_t));
    g_initialized = false;
    
    return GOSTC_OK;
}

/**
 * @brief   加载证书
 */
int32_t gostc_cert_mgr_load(cert_type_e type, cert_format_e format, 
                           const char *data, size_t len)
{
    int32_t ret;
    int32_t slot;
    cert_info_t *cert;
    os_error_e os_err;
    
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* 验证参数 */
    ret = _cert_mgr_validate_params(type, format, data, len);
    if (ret != GOSTC_OK) {
        return ret;
    }
    
    os_err = os_mutex_lock(g_cert_mgr_ctx.mutex, OS_WAIT_FOREVER);
    if (os_err != OS_OK) {
        return GOSTC_ERROR;
    }
    
    switch (type)
    {
    case CERT_TYPE_CA:
        cert = &g_cert_mgr_ctx.cert_ca;
        break;
    case CERT_TYPE_CLIENT:
        cert = &g_cert_mgr_ctx.cert_crt;
        break;
    case CERT_TYPE_PRIVATE_KEY:
        cert = &g_cert_mgr_ctx.cert_key;
        break;
    default:
        return GOSTC_ERROR;
    }    

    /* 如果证书已存在则先卸载 */
    if(cert->data){
        gostc_cert_mgr_unload(cert);
    }
    
    /* 分配内存存储证书数据 */
    cert->data = (const char *)os_malloc(len);
    if (cert->data == NULL) {
        os_mutex_unlock(g_cert_mgr_ctx.mutex);
        return GOSTC_ERROR_NO_MEMORY;
    }
    
    /* 复制证书数据 */
    memcpy((void *)cert->data, data, len);
    cert->data_len = len;
    
    /* 设置证书信息 */
    cert->type = type;
    cert->format = format;
    cert->loaded = 1;
    cert->verified = 0;
    cert->valid = 0;
    cert->ref_count = 1;
    
    /* 解析证书信息 */
    ret = _cert_mgr_parse_cert_info(cert);
    if (ret != GOSTC_OK) {
        /* 即使解析失败，证书仍然可以加载 */
        cert->verified = 0;
        cert->valid = 0;
    }
    
    g_cert_mgr_ctx.cert_count++;
    g_cert_mgr_ctx.load_count++;
    
    os_mutex_unlock(g_cert_mgr_ctx.mutex);
    
    return slot; /* 返回证书ID */
}

/**
 * @brief   卸载证书
 */
int32_t gostc_cert_mgr_unload(cert_info_t *cert)
{
    cert_info_t *cert;
    os_error_e os_err;
    
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    if (!cert) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    os_err = os_mutex_lock(g_cert_mgr_ctx.mutex, OS_WAIT_FOREVER);
    if (os_err != OS_OK) {
        return GOSTC_ERROR;
    }
    
    if (!cert->loaded) {
        os_mutex_unlock(g_cert_mgr_ctx.mutex);
        return GOSTC_ERROR_HOST_NOT_FOUND;
    }
    
    /* 检查引用计数 */
    if (cert->ref_count > 1) {
        os_mutex_unlock(g_cert_mgr_ctx.mutex);
        return GOSTC_ERROR_BUSY;
    }
    
    /* 释放证书数据内存 */
    if (cert->data != NULL) {
        os_free((void *)cert->data);
    }
    
    /* 重置证书信息 */
    memset(cert, 0, sizeof(cert_info_t));
    cert->loaded = 0;
    cert->ref_count = 0;
    
    g_cert_mgr_ctx.cert_count--;
    
    os_mutex_unlock(g_cert_mgr_ctx.mutex);
    
    return GOSTC_OK;
}

/**
 * @brief   验证证书
 */
int32_t gostc_cert_mgr_verify(int32_t cert_id, const cert_verify_config_t *config)
{
    cert_info_t *cert;
    int32_t ret;
    os_error_e os_err;
    
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    if (cert_id < 0 || cert_id >= CERT_MGR_MAX_CERTS) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    os_err = os_mutex_lock(g_cert_mgr_ctx.mutex, OS_WAIT_FOREVER);
    if (os_err != OS_OK) {
        return GOSTC_ERROR;
    }
    
    cert = &g_cert_mgr_ctx.certs[cert_id];
    
    if (!cert->loaded) {
        os_mutex_unlock(g_cert_mgr_ctx.mutex);
        return GOSTC_ERROR_HOST_NOT_FOUND;
    }
    
    /* 验证证书 */
    ret = _cert_mgr_verify_certificate(cert, config);
    
    if (ret == GOSTC_OK) {
        cert->verified = 1;
        cert->valid = 1;
        g_cert_mgr_ctx.verify_success++;
    } else {
        cert->verified = 1;
        cert->valid = 0;
        g_cert_mgr_ctx.verify_failed++;
    }
    
    g_cert_mgr_ctx.verify_count++;
    
    os_mutex_unlock(g_cert_mgr_ctx.mutex);
    
    return ret;
}

/**
 * @brief   获取证书信息
 */
int32_t gostc_cert_mgr_get_info(int32_t cert_id, cert_info_t *info)
{
    cert_info_t *cert;
    os_error_e os_err;
    
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    if (cert_id < 0 || cert_id >= CERT_MGR_MAX_CERTS) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    if (info == NULL) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    os_err = os_mutex_lock(g_cert_mgr_ctx.mutex, OS_WAIT_FOREVER);
    if (os_err != OS_OK) {
        return GOSTC_ERROR;
    }
    
    cert = &g_cert_mgr_ctx.certs[cert_id];
    
    if (!cert->loaded) {
        os_mutex_unlock(g_cert_mgr_ctx.mutex);
        return GOSTC_ERROR_HOST_NOT_FOUND;
    }
    
    /* 复制证书信息 */
    memcpy(info, cert, sizeof(cert_info_t));
    
    os_mutex_unlock(g_cert_mgr_ctx.mutex);
    
    return GOSTC_OK;
}

/**
 * @brief   查找证书
 */
int32_t gostc_cert_mgr_find(cert_type_e type, const char *subject)
{
    uint8_t i;
    os_error_e os_err;
    
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    os_err = os_mutex_lock(g_cert_mgr_ctx.mutex, OS_WAIT_FOREVER);
    if (os_err != OS_OK) {
        return GOSTC_ERROR;
    }
    
    for (i = 0; i < CERT_MGR_MAX_CERTS; i++) {
        cert_info_t *cert = &g_cert_mgr_ctx.certs[i];
        
        if (cert->loaded && cert->type == type) {
            /* 如果指定了subject，需要匹配 */
            if (subject == NULL || strcmp(cert->subject, subject) == 0) {
                os_mutex_unlock(g_cert_mgr_ctx.mutex);
                return i;
            }
        }
    }
    
    os_mutex_unlock(g_cert_mgr_ctx.mutex);
    
    return GOSTC_ERROR_HOST_NOT_FOUND;
}

/**
 * @brief   获取证书引用
 */
int32_t gostc_cert_mgr_add_ref(int32_t cert_id)
{
    cert_info_t *cert;
    os_error_e os_err;
    
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    if (cert_id < 0 || cert_id >= CERT_MGR_MAX_CERTS) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    os_err = os_mutex_lock(g_cert_mgr_ctx.mutex, OS_WAIT_FOREVER);
    if (os_err != OS_OK) {
        return GOSTC_ERROR;
    }
    
    cert = &g_cert_mgr_ctx.certs[cert_id];
    
    if (!cert->loaded) {
        os_mutex_unlock(g_cert_mgr_ctx.mutex);
        return GOSTC_ERROR_HOST_NOT_FOUND;
    }
    
    cert->ref_count++;
    
    os_mutex_unlock(g_cert_mgr_ctx.mutex);
    
    return GOSTC_OK;
}

/**
 * @brief   释放证书引用
 */
int32_t gostc_cert_mgr_release(int32_t cert_id)
{
    cert_info_t *cert;
    os_error_e os_err;
    
    if (!g_initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    if (cert_id < 0 || cert_id >= CERT_MGR_MAX_CERTS) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    os_err = os_mutex_lock(g_cert_mgr_ctx.mutex, OS_WAIT_FOREVER);
    if (os_err != OS_OK) {
        return GOSTC_ERROR;
    }
    
    cert = &g_cert_mgr_ctx.certs[cert_id];
    
    if (!cert->loaded) {
        os_mutex_unlock(g_cert_mgr_ctx.mutex);
        return GOSTC_ERROR_HOST_NOT_FOUND;
    }
    
    if (cert->ref_count > 0) {
        cert->ref_count--;
    }
    
    /* 如果引用计数为0，自动卸载证书 */
    if (cert->ref_count == 0) {
        /* 这里不自动卸载，由调用者决定 */
    }
    
    os_mutex_unlock(g_cert_mgr_ctx.mutex);
    
    return GOSTC_OK;
}

/* EOF */
