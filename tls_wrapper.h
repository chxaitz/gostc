// tls_wrapper.h
#ifndef TLS_WRAPPER_H
#define TLS_WRAPPER_H

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

typedef struct {
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
} tls_wrapper_t;

// 初始化TLS上下文
int tls_wrapper_init(tls_wrapper_t *tls, const char *host, int port);

// 通过TLS发送数据
int tls_wrapper_send(tls_wrapper_t *tls, const void *buf, size_t len);

// 通过TLS接收数据
int tls_wrapper_recv(tls_wrapper_t *tls, void *buf, size_t len);

// 清理
void tls_wrapper_free(tls_wrapper_t *tls);

#endif