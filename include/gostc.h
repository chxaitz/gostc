/**
 * @file    gostc.h
 * @brief   通信代理组件主头文件
 * @author  mosser
 * @date    2026-03-07
 * @version 1.0.0
 * 
 * @note    基于FreeRTOS 9.0.0a、lwIP 2.0.3和mbedTLS实现
 * @warning 需要在系统初始化后调用gostc_init()进行初始化
 */

#ifndef __GOSTC_H__
#define __GOSTC_H__

#ifdef __cplusplus
extern "C" {
#endif

/* 包含头文件 */
#include <stdint.h>
#include <stdbool.h>
#include "gostc_cfg.h"
#include "gostc_conn.h"
#include "gostc_tls.h"
#include "gostc_dns.h"
#include "gostc_os.h"
#include "gostc_err.h"

/* 宏定义 */
#define GOSTC_VERSION_MAJOR    1
#define GOSTC_VERSION_MINOR    0
#define GOSTC_VERSION_PATCH    0

#define GOSTC_VERSION          ((GOSTC_VERSION_MAJOR << 16) | \
                               (GOSTC_VERSION_MINOR << 8) | \
                               GOSTC_VERSION_PATCH)

#define GOSTC_MAGIC            0x474F5354  /* "GOST"的十六进制 */

/* 代理类型定义 */
typedef enum {
    PROXY_TYPE_NONE = 0,      /* 无代理 */
    PROXY_TYPE_SOCKS5,        /* SOCKS5代理 */
    PROXY_TYPE_HTTP,          /* HTTP代理 */
    PROXY_TYPE_RELAY,         /* 中继代理 */
    PROXY_TYPE_MAX
} proxy_type_e;

/* 协议类型定义 */
typedef enum {
    PROTOCOL_TCP = 0,         /* TCP协议 */
    PROTOCOL_UDP,             /* UDP协议 */
    PROTOCOL_RAW,             /* RAW协议 */
    PROTOCOL_MAX
} protocol_type_e;

/* 动作类型定义 */
typedef enum {
    ACTION_DIRECT = 0,        /* 直连 */
    ACTION_PROXY,             /* 代理 */
    ACTION_BLOCK,             /* 阻止 */
    ACTION_MAX
} action_type_e;

/* 连接状态定义 */
typedef enum {
    CONN_STATE_INIT = 0,      /* 初始化 */
    CONN_STATE_CONNECTING,    /* 连接中 */
    CONN_STATE_CONNECTED,     /* 已连接 */
    CONN_STATE_PROXYING,      /* 代理中 */
    CONN_STATE_CLOSING,       /* 关闭中 */
    CONN_STATE_CLOSED,        /* 已关闭 */
    CONN_STATE_ERROR,         /* 错误 */
    CONN_STATE_MAX
} conn_state_e;



/* 全局变量声明 */
extern gostc_config_t g_gostc_config;

/* 函数声明 */

/**
 * @brief   初始化通信代理组件
 * @param   config  配置结构体指针（如果为NULL则使用默认配置）
 * @return  int32_t 成功返回0，失败返回错误码
 * 
 * @note    必须在系统初始化后调用，且只能调用一次
 */
int32_t gostc_init(const gostc_config_t *config);

/**
 * @brief   反初始化通信代理组件
 * @return  int32_t 成功返回0，失败返回错误码
 * 
 * @note    释放所有资源，停止所有任务
 */
int32_t gostc_deinit(void);

/**
 * @brief   获取组件版本信息
 * @param   major   主版本号指针
 * @param   minor   次版本号指针
 * @param   patch   修订版本号指针
 * @return  void
 */
void gostc_get_version(uint8_t *major, uint8_t *minor, uint8_t *patch);

/**
 * @brief   获取组件状态
 * @return  int32_t 状态码
 * 
 * @retval  0       正常
 * @retval  <0      错误状态
 */
int32_t gostc_get_status(void);

/**
 * @brief   重新加载配置
 * @param   config  新的配置结构体指针
 * @return  int32_t 成功返回0，失败返回错误码
 * 
 * @note    运行时动态更新配置，部分配置可能需要重启生效
 */
int32_t gostc_reload_config(const gostc_config_t *config);

/**
 * @brief   获取当前配置
 * @param   config  配置结构体指针（用于接收配置）
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_get_config(gostc_config_t *config);

/**
 * @brief   重置统计信息
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_reset_stats(void);

/**
 * @brief   获取统计信息
 * @param   stats   统计信息结构体指针
 * @return  int32_t 成功返回0，失败返回错误码
 */
int32_t gostc_get_stats(runtime_stats_t *stats);

#ifdef __cplusplus
}
#endif

#endif /* __GOSTC_H__ */