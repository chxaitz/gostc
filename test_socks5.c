// test_socks5.c
#include "socks5_client.h"
#include <stdio.h>
#include <string.h>

int main() {
    // 1. 创建SOCKS5客户端，连接本地GOST代理
    socks5_client_t *client = socks5_client_new("127.0.0.1", 1080);
    
    // 2. 设置认证（如果需要）
    socks5_client_set_auth(client, "admin", "123456");
    
    // 3. 通过代理连接目标服务器
    int fd = socks5_client_connect(client, "www.example.com", 80);
    if (fd < 0) {
        printf("连接失败\n");
        return -1;
    }
    
    printf("连接成功！\n");
    
    // 4. 发送HTTP请求
    const char *http_req = 
        "GET / HTTP/1.1\r\n"
        "Host: www.example.com\r\n"
        "Connection: close\r\n"
        "\r\n";
    
    send(fd, http_req, strlen(http_req), 0);
    
    // 5. 接收响应
    char buf[4096];
    int n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
        buf[n] = '\0';
        printf("收到响应:\n%s\n", buf);
    }
    
    socks5_client_close(client);
    return 0;
}