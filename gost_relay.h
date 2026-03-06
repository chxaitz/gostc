// gost_relay.h
#ifndef GOST_RELAY_H
#define GOST_RELAY_H

#include <stdint.h>

// Relay协议常量
#define RELAY_VERSION 0x01
#define RELAY_CMD_CONNECT 0x01
#define RELAY_CMD_BIND 0x02
#define RELAY_CMD_UDP 0x03

// 地址类型
#define RELAY_ATYP_IPV4 0x01
#define RELAY_ATYP_DOMAIN 0x03
#define RELAY_ATYP_IPV6 0x04

typedef struct {
    int fd;
    char *host;
    int port;
    char *key;  // 可选的加密密钥
} gost_relay_t;

// 初始化Relay连接
gost_relay_t* gost_relay_new(const char *host, int port);

// 发送Relay连接请求
int gost_relay_connect(gost_relay_t *relay, 
                      const char *target_host, 
                      int target_port);

// 发送Relay UDP请求
int gost_relay_udp(gost_relay_t *relay);

// 关闭连接
void gost_relay_close(gost_relay_t *relay);

#endif