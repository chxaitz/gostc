// gost_client.h - 统一接口
#ifndef GOST_CLIENT_H
#define GOST_CLIENT_H

// 代理链节点
typedef struct gost_node {
    char *protocol;      // socks5, http, relay, tls, ws...
    char *host;
    int port;
    char *username;
    char *password;
    struct gost_node *next;
} gost_node_t;

// GOST客户端
typedef struct {
    gost_node_t *chain;  // 代理链
    int timeout;         // 超时时间
    int debug;          // 调试模式
} gost_client_t;

// 初始化客户端
gost_client_t* gost_client_new();

// 添加节点到代理链
void gost_client_add_node(gost_client_t *client, 
                         const char *protocol,
                         const char *host, 
                         int port,
                         const char *username,
                         const char *password);

// 通过代理链连接目标
int gost_client_connect(gost_client_t *client,
                       const char *target_host,
                       int target_port);

// 发送数据
int gost_client_send(gost_client_t *client, int conn_id, 
                    const void *data, size_t len);

// 接收数据
int gost_client_recv(gost_client_t *client, int conn_id,
                    void *data, size_t *len);

#endif