// gost_client.c
#include "gost_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

gost_client_t* gost_client_new(const char *host, int port) {
    gost_client_t *client = calloc(1, sizeof(gost_client_t));
    client->host = strdup(host);
    client->port = port;
    client->fd = -1;
    return client;
}

void gost_client_set_auth(gost_client_t *client, 
                           const char *username, 
                           const char *password) {
    client->username = strdup(username);
    client->password = strdup(password);
}

// 核心功能：通过SOCKS5代理连接目标
int gost_client_connect(gost_client_t *client, 
                         const char *target_host, 
                         int target_port) {
    struct sockaddr_in addr;
    
    // 1. 连接到SOCKS5代理服务器
    client->fd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(client->port);
    inet_pton(AF_INET, client->host, &addr.sin_addr);
    
    if (connect(client->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect to proxy failed");
        return -1;
    }
    
    // 2. SOCKS5握手 - 协商认证方法
    unsigned char handshake[] = {
        0x05,           // SOCKS5版本
        0x02,           // 支持的认证方法数量
        0x00,           // 无认证
        0x02            // 用户名密码认证
    };
    
    if (send(client->fd, handshake, sizeof(handshake), 0) != sizeof(handshake)) {
        return -1;
    }
    
    // 3. 读取服务器选择的认证方法
    unsigned char response[2];
    if (recv(client->fd, response, 2, 0) != 2) {
        return -1;
    }
    
    if (response[0] != 0x05) {
        return -1;  // 版本不匹配
    }
    
    // 4. 如果需要认证
    if (response[1] == 0x02 && client->username && client->password) {
        unsigned char auth_pkt[3 + 255 + 255];
        int ulen = strlen(client->username);
        int plen = strlen(client->password);
        
        auth_pkt[0] = 0x01;  // 认证版本
        auth_pkt[1] = ulen;
        memcpy(auth_pkt + 2, client->username, ulen);
        auth_pkt[2 + ulen] = plen;
        memcpy(auth_pkt + 3 + ulen, client->password, plen);
        
        int auth_len = 3 + ulen + plen;
        if (send(client->fd, auth_pkt, auth_len, 0) != auth_len) {
            return -1;
        }
        
        unsigned char auth_resp[2];
        if (recv(client->fd, auth_resp, 2, 0) != 2) {
            return -1;
        }
        
        if (auth_resp[1] != 0x00) {
            return -1;  // 认证失败
        }
    }
    
    // 5. 发送CONNECT请求
    unsigned char request[1024];
    int req_len = 4;  // VER + CMD + RSV + ATYP
    
    request[0] = 0x05;  // 版本
    request[1] = 0x01;  // CONNECT命令
    request[2] = 0x00;  // 保留字段
    request[3] = 0x03;  // 域名类型
    
    // 添加目标域名
    int hostlen = strlen(target_host);
    request[4] = hostlen;
    memcpy(request + 5, target_host, hostlen);
    req_len += 1 + hostlen;
    
    // 添加目标端口
    uint16_t port_net = htons(target_port);
    memcpy(request + req_len, &port_net, 2);
    req_len += 2;
    
    if (send(client->fd, request, req_len, 0) != req_len) {
        return -1;
    }
    
    // 6. 读取服务器响应
    unsigned char resp[256];
    if (recv(client->fd, resp, 4, 0) != 4) {
        return -1;
    }
    
    if (resp[1] != 0x00) {
        return -1;  // 连接失败
    }
    
    // 7. 跳过剩余的BND.ADDR和BND.PORT
    int atyp = resp[3];
    int skip = 0;
    switch (atyp) {
        case 0x01: skip = 4 + 2; break;  // IPv4 + port
        case 0x03: 
            recv(client->fd, resp, 1, 0);
            skip = resp[0] + 2; 
            break;
        case 0x04: skip = 16 + 2; break; // IPv6 + port
    }
    
    if (skip > 0) {
        unsigned char buf[32];
        recv(client->fd, buf, skip, 0);
    }
    
    // 连接成功，返回socket
    return client->fd;
}

void gost_client_close(gost_client_t *client) {
    if (client->fd > 0) close(client->fd);
    free(client->host);
    if (client->username) free(client->username);
    if (client->password) free(client->password);
    free(client);
}
