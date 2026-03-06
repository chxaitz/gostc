// websocket_wrapper.h
#ifndef WEBSOCKET_WRAPPER_H
#define WEBSOCKET_WRAPPER_H

#include <stdint.h>

#define WS_OPCODE_CONTINUE 0x0
#define WS_OPCODE_TEXT 0x1
#define WS_OPCODE_BINARY 0x2
#define WS_OPCODE_CLOSE 0x8
#define WS_OPCODE_PING 0x9
#define WS_OPCODE_PONG 0xA

typedef struct {
    int fd;
    char *host;
    char *path;
    int is_client;
    int is_secure;  // wss
} websocket_t;

// 建立WebSocket连接
websocket_t* websocket_connect(const char *host, int port, const char *path);

// 发送WebSocket帧
int websocket_send_frame(websocket_t *ws, int opcode, const void *data, size_t len);

// 接收WebSocket帧
int websocket_recv_frame(websocket_t *ws, void *data, size_t *len);

#endif