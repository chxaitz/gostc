#include "gostc_log.h"
#include <stdio.h>

int main(void)
{
    printf("Testing GOSTC Log Interface...\n");
    
    // 测试调试级别日志
    gostc_log_debug("[INTERCEPT] DNS查询拦截: %s", "example.com");
    gostc_log_debug("调试信息: 值=%d, 状态=%s", 42, "正常");
    
    // 测试信息级别日志
    gostc_log_info("系统启动完成");
    gostc_log_info("连接数: %d, 内存使用: %.2f MB", 10, 12.5);
    
    // 测试警告级别日志
    gostc_log_warn("内存使用率超过阈值: %.1f%%", 85.5);
    gostc_log_warn("连接超时: %s:%d", "192.168.1.1", 8080);
    
    // 测试错误级别日志
    gostc_log_error("无法打开文件: %s", "/path/to/file.txt");
    gostc_log_error("TLS握手失败: 错误码=%d", 0x8001);
    
    printf("All log tests completed.\n");
    return 0;
}