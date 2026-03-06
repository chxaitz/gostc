// socks5_client.h
#ifndef SOCKS5_CLIENT_H
#define SOCKS5_CLIENT_H

#include <stdint.h>
#include <sys/socket.h>

// SOCKS5协议常量
#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

// 认证方法
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_PASSWORD 0x02

// 错误码
#define SOCKS5_SUCCESS 0x00
#define SOCKS5_GENERAL_FAILURE 0x01

typedef struct {
    int fd;                 // 代理服务器socket
    char *host;            // 代理服务器地址
    int port;              // 代理服务器端口
    char *username;        // 认证用户名（可选）
    char *password;        // 认证密码（可选）
} socks5_client_t;

// 初始化SOCKS5客户端
socks5_client_t* socks5_client_new(const char *host, int port);

// 设置认证
void socks5_client_set_auth(socks5_client_t *client, 
                           const char *username, 
                           const char *password);

// 通过代理连接目标
int socks5_client_connect(socks5_client_t *client, 
                         const char *target_host, 
                         int target_port);

// 关闭连接
void socks5_client_close(socks5_client_t *client);

#endif