#ifndef __GOSTC_LOG_H__
#define __GOSTC_LOG_H__

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 调试级别日志输出
 * 
 * @param fmt 格式化字符串
 * @param ... 可变参数
 * 
 * @example
 * gostc_log_debug("[INTERCEPT] DNS查询拦截: %s", name);
 */
// void gostc_log_debug(const char *fmt, ...);
#define gostc_log_debug(fmt,...)     {printf(fmt, ##__VA_ARGS__);printf("\n");}while (0)

/**
 * @brief 信息级别日志输出
 * 
 * @param fmt 格式化字符串
 * @param ... 可变参数
 */
// void gostc_log_info(const char *fmt, ...);
#define gostc_log_info(fmt,...)      {printf(fmt, ##__VA_ARGS__);printf("\n");}while (0)

/**
 * @brief 警告级别日志输出
 * 
 * @param fmt 格式化字符串
 * @param ... 可变参数
 */
// void gostc_log_warn(const char *fmt, ...);
#define gostc_log_warn(fmt,...)    {printf(fmt, ##__VA_ARGS__);printf("\n");}while (0)

/**
 * @brief 错误级别日志输出
 * 
 * @param fmt 格式化字符串
 * @param ... 可变参数
 */
// void gostc_log_error(const char *fmt, ...);
#define gostc_log_error(fmt,...)     {printf(fmt, ##__VA_ARGS__);printf("\n");}while (0)

#ifdef __cplusplus
}
#endif

#endif /* __GOSTC_LOG_H__ */