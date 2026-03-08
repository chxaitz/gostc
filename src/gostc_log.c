#include "gostc_log.h"
#include "../3rd/inc/ol_log.h"
#include <stdarg.h>
#include <stdio.h>

/**
 * @brief 内部辅助函数：格式化字符串并调用日志宏
 * 
 * @param fmt 格式化字符串
 * @param args 可变参数列表
 * @return char* 格式化后的字符串（静态缓冲区，非线程安全）
 */
static const char* gostc_log_format(const char *fmt, va_list args)
{
    static char buffer[512];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    return buffer;
}

void gostc_log_debug(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    const char *formatted = gostc_log_format(fmt, args);
    OL_LOG_DEBUG("%s", formatted);
    va_end(args);
}

void gostc_log_info(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    const char *formatted = gostc_log_format(fmt, args);
    OL_LOG_INFO("%s", formatted);
    va_end(args);
}

void gostc_log_warn(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    const char *formatted = gostc_log_format(fmt, args);
    // ol_log.h中没有WARN级别，使用INFO级别输出
    OL_LOG_INFO("%s", formatted);
    va_end(args);
}

void gostc_log_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    const char *formatted = gostc_log_format(fmt, args);
    OL_LOG_ERROR("%s", formatted);
    va_end(args);
}