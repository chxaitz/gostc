/**
 * @file    gostc_os.h
 * @brief   通信代理操作系统抽象层头文件
 * @author  mosser
 * @date    2026-03-07
 * @version 1.0.0
 * 
 * @note    提供操作系统相关功能的抽象接口，支持FreeRTOS
 * @warning 需要根据实际操作系统实现具体函数
 */

#ifndef __GOSTC_OS_H__
#define __GOSTC_OS_H__

#ifdef __cplusplus
extern "C" {
#endif

/* 包含头文件 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* 宏定义 */
#define OS_MAX_TASK_NAME_LEN    16      /* 最大任务名称长度 */
#define OS_MAX_QUEUE_SIZE       32      /* 最大队列大小 */
#define OS_MAX_SEMAPHORE_COUNT  65535   /* 最大信号量计数 */

#define OS_WAIT_FOREVER         0xFFFFFFFF  /* 永久等待 */
#define OS_NO_WAIT              0           /* 不等待 */

/* 错误码定义 */
typedef enum {
    OS_OK = 0,                      /* 成功 */
    OS_ERROR,                       /* 一般错误 */
    OS_ERROR_INVALID_PARAM,         /* 无效参数 */
    OS_ERROR_TIMEOUT,               /* 超时 */
    OS_ERROR_NO_MEMORY,             /* 内存不足 */
    OS_ERROR_NOT_INITIALIZED,       /* 未初始化 */
    OS_ERROR_ALREADY_INITIALIZED,   /* 已初始化 */
    OS_ERROR_RESOURCE_BUSY,         /* 资源忙 */
    OS_ERROR_NOT_FOUND,             /* 未找到 */
    OS_ERROR_NOT_SUPPORTED,         /* 不支持 */
    OS_ERROR_MAX
} os_error_e;

/* 任务优先级定义 */
typedef enum {
    OS_TASK_PRIORITY_IDLE = 0,      /* 空闲优先级 */
    OS_TASK_PRIORITY_LOW,           /* 低优先级 */
    OS_TASK_PRIORITY_NORMAL,        /* 正常优先级 */
    OS_TASK_PRIORITY_HIGH,          /* 高优先级 */
    OS_TASK_PRIORITY_REALTIME,      /* 实时优先级 */
    OS_TASK_PRIORITY_MAX
} os_task_priority_e;

/* 任务句柄 */
typedef void *os_task_handle_t;

/* 互斥锁句柄 */
typedef void *os_mutex_handle_t;

/* 信号量句柄 */
typedef void *os_semaphore_handle_t;

/* 队列句柄 */
typedef void *os_queue_handle_t;

/* 定时器句柄 */
typedef void *os_timer_handle_t;

/* 事件组句柄 */
typedef void *os_event_group_handle_t;

/* 内存池句柄 */
typedef void *os_memory_pool_handle_t;

/* 任务函数类型 */
typedef void (*os_task_function_t)(void *arg);

/* 定时器回调函数类型 */
typedef void (*os_timer_callback_t)(os_timer_handle_t timer, void *arg);

/* 任务配置结构体 */
typedef struct {
    char name[OS_MAX_TASK_NAME_LEN];    /* 任务名称 */
    os_task_function_t function;        /* 任务函数 */
    void *argument;                     /* 任务参数 */
    uint32_t stack_size;                /* 堆栈大小（字节） */
    os_task_priority_e priority;        /* 任务优先级 */
    uint32_t *stack_buffer;             /* 堆栈缓冲区（如果为NULL则动态分配） */
} os_task_config_t;

/* 队列配置结构体 */
typedef struct {
    uint32_t queue_size;                /* 队列大小（项目数） */
    uint32_t item_size;                 /* 项目大小（字节） */
} os_queue_config_t;

/* 定时器配置结构体 */
typedef struct {
    char name[OS_MAX_TASK_NAME_LEN];    /* 定时器名称 */
    os_timer_callback_t callback;       /* 回调函数 */
    void *argument;                     /* 回调参数 */
    uint32_t period_ms;                 /* 周期（毫秒） */
    bool auto_reload;                   /* 是否自动重载 */
    bool start_immediately;             /* 是否立即启动 */
} os_timer_config_t;

/* 内存池配置结构体 */
typedef struct {
    uint32_t block_size;                /* 块大小（字节） */
    uint32_t block_count;               /* 块数量 */
    uint8_t *memory_buffer;             /* 内存缓冲区（如果为NULL则动态分配） */
} os_memory_pool_config_t;

/* 系统信息结构体 */
typedef struct {
    uint32_t tick_count;                /* 系统tick计数 */
    uint32_t tick_rate_hz;              /* 系统tick频率（Hz） */
    uint32_t free_heap_size;            /* 空闲堆大小（字节） */
    uint32_t min_free_heap_size;        /* 最小空闲堆大小（字节） */
    uint32_t total_tasks;               /* 总任务数 */
    uint32_t running_tasks;             /* 运行中任务数 */
    uint32_t suspended_tasks;           /* 挂起任务数 */
    char kernel_version[32];            /* 内核版本 */
} os_system_info_t;

/* 任务信息结构体 */
typedef struct {
    char name[OS_MAX_TASK_NAME_LEN];    /* 任务名称 */
    os_task_handle_t handle;            /* 任务句柄 */
    os_task_priority_e priority;        /* 任务优先级 */
    uint32_t stack_size;                /* 堆栈大小（字节） */
    uint32_t stack_high_water_mark;     /* 堆栈高水位标记（字节） */
    uint32_t task_number;               /* 任务编号 */
    uint32_t run_time_counter;          /* 运行时间计数器 */
} os_task_info_t;

/* 函数声明 */

/* 系统管理函数 */
/**
 * @brief   获取系统tick计数
 * @return  uint32_t 系统tick计数
 */
uint32_t os_get_tick_count(void);

/**
 * @brief   延迟指定毫秒数
 * @param   ms  延迟时间（毫秒）
 */
void os_delay_ms(uint32_t ms);

/**
 * @brief   获取系统信息
 * @param   info  系统信息结构体指针
 * @return  os_error_e 错误码
 */
os_error_e os_get_system_info(os_system_info_t *info);

/**
 * @brief   进入临界区
 * @return  uint32_t 进入前的状态（用于恢复）
 */
uint32_t os_enter_critical(void);

/**
 * @brief   退出临界区
 * @param   state  进入临界区时返回的状态
 */
void os_exit_critical(uint32_t state);

/* 任务管理函数 */
/**
 * @brief   创建任务
 * @param   config  任务配置
 * @param   handle  任务句柄指针（输出）
 * @return  os_error_e 错误码
 */
os_error_e os_task_create(const os_task_config_t *config, os_task_handle_t *handle);

/**
 * @brief   删除任务
 * @param   handle  任务句柄
 * @return  os_error_e 错误码
 */
os_error_e os_task_delete(os_task_handle_t handle);

/**
 * @brief   挂起任务
 * @param   handle  任务句柄
 * @return  os_error_e 错误码
 */
os_error_e os_task_suspend(os_task_handle_t handle);

/**
 * @brief   恢复任务
 * @param   handle  任务句柄
 * @return  os_error_e 错误码
 */
os_error_e os_task_resume(os_task_handle_t handle);

/**
 * @brief   获取当前任务句柄
 * @return  os_task_handle_t 当前任务句柄
 */
os_task_handle_t os_task_get_current(void);

/**
 * @brief   获取任务信息
 * @param   handle  任务句柄
 * @param   info    任务信息结构体指针
 * @return  os_error_e 错误码
 */
os_error_e os_task_get_info(os_task_handle_t handle, os_task_info_t *info);

/**
 * @brief   设置任务优先级
 * @param   handle    任务句柄
 * @param   priority  新优先级
 * @return  os_error_e 错误码
 */
os_error_e os_task_set_priority(os_task_handle_t handle, os_task_priority_e priority);

/**
 * @brief   获取任务优先级
 * @param   handle  任务句柄
 * @return  os_task_priority_e 任务优先级
 */
os_task_priority_e os_task_get_priority(os_task_handle_t handle);

/* 互斥锁函数 */
/**
 * @brief   创建互斥锁
 * @param   handle  互斥锁句柄指针（输出）
 * @return  os_error_e 错误码
 */
os_error_e os_mutex_create(os_mutex_handle_t *handle);

/**
 * @brief   删除互斥锁
 * @param   handle  互斥锁句柄
 * @return  os_error_e 错误码
 */
os_error_e os_mutex_delete(os_mutex_handle_t handle);

/**
 * @brief   获取互斥锁
 * @param   handle  互斥锁句柄
 * @param   timeout_ms 超时时间（毫秒）
 * @return  os_error_e 错误码
 */
os_error_e os_mutex_lock(os_mutex_handle_t handle, uint32_t timeout_ms);

/**
 * @brief   释放互斥锁
 * @param   handle  互斥锁句柄
 * @return  os_error_e 错误码
 */
os_error_e os_mutex_unlock(os_mutex_handle_t handle);

/* 信号量函数 */
/**
 * @brief   创建二进制信号量
 * @param   handle  信号量句柄指针（输出）
 * @return  os_error_e 错误码
 */
os_error_e os_semaphore_create_binary(os_semaphore_handle_t *handle);

/**
 * @brief   创建计数信号量
 * @param   max_count  最大计数
 * @param   initial_count 初始计数
 * @param   handle     信号量句柄指针（输出）
 * @return  os_error_e 错误码
 */
os_error_e os_semaphore_create_counting(uint32_t max_count, uint32_t initial_count, 
                                       os_semaphore_handle_t *handle);

/**
 * @brief   删除信号量
 * @param   handle  信号量句柄
 * @return  os_error_e 错误码
 */
os_error_e os_semaphore_delete(os_semaphore_handle_t handle);

/**
 * @brief   获取信号量
 * @param   handle     信号量句柄
 * @param   timeout_ms 超时时间（毫秒）
 * @return  os_error_e 错误码
 */
os_error_e os_semaphore_take(os_semaphore_handle_t handle, uint32_t timeout_ms);

/**
 * @brief   释放信号量
 * @param   handle  信号量句柄
 * @return  os_error_e 错误码
 */
os_error_e os_semaphore_give(os_semaphore_handle_t handle);

/* 队列函数 */
/**
 * @brief   创建队列
 * @param   config  队列配置
 * @param   handle  队列句柄指针（输出）
 * @return  os_error_e 错误码
 */
os_error_e os_queue_create(const os_queue_config_t *config, os_queue_handle_t *handle);

/**
 * @brief   删除队列
 * @param   handle  队列句柄
 * @return  os_error_e 错误码
 */
os_error_e os_queue_delete(os_queue_handle_t handle);

/**
 * @brief   发送消息到队列
 * @param   handle     队列句柄
 * @param   item       消息指针
 * @param   timeout_ms 超时时间（毫秒）
 * @return  os_error_e 错误码
 */
os_error_e os_queue_send(os_queue_handle_t handle, const void *item, uint32_t timeout_ms);

/**
 * @brief   从队列接收消息
 * @param   handle     队列句柄
 * @param   buffer     接收缓冲区
 * @param   timeout_ms 超时时间（毫秒）
 * @return  os_error_e 错误码
 */
os_error_e os_queue_receive(os_queue_handle_t handle, void *buffer, uint32_t timeout_ms);

/* 定时器函数 */
/**
 * @brief   创建定时器
 * @param   config  定时器配置
 * @param   handle  定时器句柄指针（输出）
 * @return  os_error_e 错误码
 */
os_error_e os_timer_create(const os_timer_config_t *config, os_timer_handle_t *handle);

/**
 * @brief   删除定时器
 * @param   handle  定时器句柄
 * @return  os_error_e 错误码
 */
os_error_e os_timer_delete(os_timer_handle_t handle);

/**
 * @brief   启动定时器
 * @param   handle  定时器句柄
 * @return  os_error_e 错误码
 */
os_error_e os_timer_start(os_timer_handle_t handle);

/**
 * @brief   停止定时器
 * @param   handle  定时器句柄
 * @return  os_error_e 错误码
 */
os_error_e os_timer_stop(os_timer_handle_t handle);

/**
 * @brief   重置定时器
 * @param   handle  定时器句柄
 * @return  os_error_e 错误码
 */
os_error_e os_timer_reset(os_timer_handle_t handle);

/* 内存管理函数 */
/**
 * @brief   分配内存
 * @param   size  分配大小（字节）
 * @return  void* 分配的内存指针，失败返回NULL
 */
void *os_malloc(size_t size);

/**
 * @brief   释放内存
 * @param   ptr  内存指针
 */
void os_free(void *ptr);

/**
 * @brief   分配对齐内存
 * @param   alignment 对齐要求（字节）
 * @param   size      分配大小（字节）
 * @return  void*     分配的内存指针，失败返回NULL
 */
void *os_aligned_alloc(size_t alignment, size_t size);

/**
 * @brief   创建内存池
 * @param   config  内存池配置
 * @param   handle  内存池句柄指针（输出）
 * @return  os_error_e 错误码
 */
os_error_e os_memory_pool_create(const os_memory_pool_config_t *config, 
                                os_memory_pool_handle_t *handle);

/**
 * @brief   删除内存池
 * @param   handle  内存池句柄
 * @return  os_error_e 错误码
 */
os_error_e os_memory_pool_delete(os_memory_pool_handle_t handle);

/**
 * @brief   从内存池分配
 * @param   handle  内存池句柄
 * @param   timeout_ms 超时时间（毫秒）
 * @return  void*   分配的内存指针，失败返回NULL
 */
void *os_memory_pool_alloc(os_memory_pool_handle_t handle, uint32_t timeout_ms);

/**
 * @brief   释放内存到内存池
 * @param   handle  内存池句柄
 * @param   block   内存块指针
 * @return  os_error_e 错误码
 */
os_error_e os_memory_pool_free(os_memory_pool_handle_t handle, void *block);

/* 调试函数 */
/**
 * @brief   输出调试信息
 * @param   format  格式字符串
 * @param   ...     可变参数
 */
void os_debug_printf(const char *format, ...);

/**
 * @brief   断言失败处理
 * @param   file    文件名
 * @param   line    行号
 * @param   expr    断言表达式
 */
void os_assert_failed(const char *file, uint32_t line, const char *expr);

#ifdef __cplusplus
}
#endif

#endif /* __GOSTC_OS_H__ */