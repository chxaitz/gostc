// gost_relay.c
#include "gost_relay.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

gost_relay_t* gost_relay_new(const char *host, int port) {
    gost_relay_t *relay = calloc(1, sizeof(gost_relay_t));
    relay->host = strdup(host);
    relay->port = port;
    
    // 建立TCP连接
    relay->fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    
    if (connect(relay->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect to relay failed");
        free(relay->host);
        free(relay);
        return NULL;
    }
    
    return relay;
}

int gost_relay_connect(gost_relay_t *relay, 
                      const char *target_host, 
                      int target_port) {
    unsigned char packet[1024];
    int pos = 0;
    
    // 1. Relay协议版本
    packet[pos++] = RELAY_VERSION;
    
    // 2. 命令
    packet[pos++] = RELAY_CMD_CONNECT;
    
    // 3. 地址类型和地址
    int hostlen = strlen(target_host);
    packet[pos++] = RELAY_ATYP_DOMAIN;
    packet[pos++] = hostlen;
    memcpy(packet + pos, target_host, hostlen);
    pos += hostlen;
    
    // 4. 端口
    uint16_t port_net = htons(target_port);
    memcpy(packet + pos, &port_net, 2);
    pos += 2;
    
    // 5. 发送请求
    if (send(relay->fd, packet, pos, 0) != pos) {
        return -1;
    }
    
    // 6. 读取响应
    unsigned char resp[16];
    if (recv(relay->fd, resp, 2, 0) != 2) {
        return -1;
    }
    
    if (resp[1] != 0x00) {
        return -1;  // 连接失败
    }
    
    return relay->fd;  // 返回已就绪的socket
}