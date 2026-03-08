/**
 * @file    gostc_os_linux.c
 * @brief   通信代理操作系统抽象层实现（Linux适配）
 * @author  Kilo Code
 * @date    2026-03-07
 * @version 1.0.0
 * 
 * @note    基于Linux POSIX线程和系统调用实现的操作系统抽象层
 * @warning 需要Linux内核2.6.28+和glibc 2.17+
 */

#include "gostc_os.h"
#include "gostc_err.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#ifdef __linux__
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#endif

/* POSIX线程头文件 */
#include <pthread.h>
#include <semaphore.h>
#include <sched.h>

/* 内部宏定义 */
#define LINUX_TICK_HZ             1000    /* Linux tick频率（Hz） */
#define LINUX_DEFAULT_STACK_SIZE  (64*1024) /* 默认堆栈大小（字节） */
#define LINUX_MAX_THREAD_NAME_LEN 16      /* 最大线程名称长度 */

/* 内存统计信息 */
static size_t total_allocated = 0;
static size_t peak_allocated = 0;
static pthread_mutex_t mem_mutex = PTHREAD_MUTEX_INITIALIZER;

/* 系统启动时间（用于计算相对时间戳） */
static struct timespec startup_time;

/* 初始化函数（在库加载时自动调用） */
static void __attribute__((constructor)) _os_linux_init(void) {
    clock_gettime(CLOCK_MONOTONIC, &startup_time);
}

/* 清理函数（在库卸载时自动调用） */
static void __attribute__((destructor)) _os_linux_deinit(void) {
    /* 可以在这里添加资源清理代码 */
}

/* ========== 内部结构体定义 ========== */

/* 任务包装结构体 */
typedef struct {
    pthread_t thread;                    /* POSIX线程 */
    char name[OS_MAX_TASK_NAME_LEN];     /* 任务名称 */
    os_task_function_t function;         /* 任务函数 */
    void *argument;                      /* 任务参数 */
    uint32_t stack_size;                 /* 堆栈大小 */
    os_task_priority_e priority;         /* 任务优先级 */
    int running;                         /* 运行状态 */
    pthread_mutex_t mutex;               /* 状态保护互斥锁 */
} linux_task_wrapper_t;

/* 互斥锁包装结构体 */
typedef struct {
    pthread_mutex_t mutex;               /* POSIX互斥锁 */
} linux_mutex_wrapper_t;

/* 信号量包装结构体 */
typedef struct {
    sem_t sem;                           /* POSIX信号量 */
    bool is_binary;                      /* 是否为二进制信号量 */
} linux_semaphore_wrapper_t;

/* 队列包装结构体 */
typedef struct {
    pthread_mutex_t mutex;               /* 队列保护互斥锁 */
    pthread_cond_t cond_not_empty;       /* 非空条件变量 */
    pthread_cond_t cond_not_full;        /* 非满条件变量 */
    uint8_t *buffer;                     /* 队列缓冲区 */
    size_t item_size;                    /* 项目大小 */
    size_t queue_length;                 /* 队列长度 */
    size_t head;                         /* 队列头 */
    size_t tail;                         /* 队列尾 */
    size_t count;                        /* 当前项目数 */
} linux_queue_wrapper_t;

/* 定时器包装结构体 */
typedef struct {
    pthread_t thread;                    /* 定时器线程 */
    char name[OS_MAX_TASK_NAME_LEN];     /* 定时器名称 */
    os_timer_callback_t callback;        /* 用户回调函数 */
    void *argument;                      /* 用户参数 */
    uint32_t period_ms;                  /* 周期（毫秒） */
    bool auto_reload;                    /* 是否自动重载 */
    bool running;                        /* 运行状态 */
    pthread_mutex_t mutex;               /* 状态保护互斥锁 */
    pthread_cond_t cond;                 /* 条件变量 */
} linux_timer_wrapper_t;

/* 内存池包装结构体 */
typedef struct {
    uint32_t block_size;                 /* 块大小 */
    uint32_t block_count;                /* 块数量 */
    uint8_t *memory_buffer;              /* 内存缓冲区 */
    uint8_t *free_list;                  /* 空闲链表 */
    pthread_mutex_t mutex;               /* 保护互斥锁 */
} linux_memory_pool_wrapper_t;

/* 事件组包装结构体 */
typedef struct {
    pthread_mutex_t mutex;               /* 保护互斥锁 */
    pthread_cond_t cond;                 /* 条件变量 */
    uint32_t bits;                       /* 事件位 */
} linux_event_group_wrapper_t;

/* ========== 内部函数声明 ========== */

static void *_task_thread_wrapper(void *arg);
static void *_timer_thread_wrapper(void *arg);
static int _priority_to_sched_policy(os_task_priority_e priority);
static int _priority_to_nice_value(os_task_priority_e priority);

/* ========== 系统管理函数实现 ========== */

uint32_t os_get_tick_count(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    /* 转换为毫秒 */
    return (uint32_t)((ts.tv_sec * 1000) + (ts.tv_nsec / 1000000));
}

void os_delay_ms(uint32_t ms)
{
    struct timespec req, rem;
    req.tv_sec = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000;
    
    while (nanosleep(&req, &rem) == -1 && errno == EINTR) {
        req = rem;
    }
}

os_error_e os_get_system_info(os_system_info_t *info)
{
    if (info == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 获取系统tick信息 */
    info->tick_count = os_get_tick_count();
    info->tick_rate_hz = LINUX_TICK_HZ;
    
    /* 获取系统内存信息 */
#ifdef __linux__
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        info->free_heap_size = si.freeram * si.mem_unit;
        info->min_free_heap_size = 0; /* Linux不提供此信息 */
    } else {
        info->free_heap_size = 0;
        info->min_free_heap_size = 0;
    }
#else
    /* 非Linux环境，返回默认值 */
    info->free_heap_size = 0;
    info->min_free_heap_size = 0;
#endif
    
    /* 获取任务信息（简化实现） */
    info->total_tasks = 0;
    info->running_tasks = 0;
    info->suspended_tasks = 0;
    
    /* 内核版本信息 */
#ifdef __linux__
    struct utsname uts;
    if (uname(&uts) == 0) {
        snprintf(info->kernel_version, sizeof(info->kernel_version),
                 "Linux %s %s", uts.release, uts.machine);
    } else {
        strncpy(info->kernel_version, "Linux unknown", sizeof(info->kernel_version) - 1);
        info->kernel_version[sizeof(info->kernel_version) - 1] = '\0';
    }
#else
    strncpy(info->kernel_version, "Linux (simulated)", sizeof(info->kernel_version) - 1);
    info->kernel_version[sizeof(info->kernel_version) - 1] = '\0';
#endif
    
    return OS_OK;
}

uint32_t os_enter_critical(void)
{
    /* Linux下没有直接的临界区概念，使用线程取消禁用 */
    int old_state;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state);
    return (uint32_t)old_state;
}

void os_exit_critical(uint32_t state)
{
    /* 恢复线程取消状态 */
    pthread_setcancelstate((int)state, NULL);
}

/* ========== 内存管理函数实现 ========== */

void *os_malloc(size_t size)
{
    void *ptr = malloc(size);
    if (ptr) {
        pthread_mutex_lock(&mem_mutex);
        total_allocated += size;
        if (total_allocated > peak_allocated) {
            peak_allocated = total_allocated;
        }
        pthread_mutex_unlock(&mem_mutex);
    }
    return ptr;
}

void os_free(void *ptr)
{
    if (ptr) {
        free(ptr);
        /* 注意：无法准确统计释放的内存大小 */
    }
}

void *os_aligned_alloc(size_t alignment, size_t size)
{
    void *ptr = NULL;
#ifdef _POSIX_C_SOURCE
    if (posix_memalign(&ptr, alignment, size) != 0) {
        return NULL;
    }
#else
    /* 回退到标准malloc，不保证对齐 */
    ptr = malloc(size);
#endif
    return ptr;
}

/* ========== 任务管理函数实现 ========== */

/* 线程启动函数 */
static void *_task_thread_wrapper(void *arg)
{
    linux_task_wrapper_t *wrapper = (linux_task_wrapper_t *)arg;
    
    /* 设置线程名称（如果支持） */
#ifdef __GLIBC__
    pthread_setname_np(wrapper->thread, wrapper->name);
#endif
    
    /* 执行用户任务函数 */
    wrapper->function(wrapper->argument);
    
    /* 标记任务结束 */
    pthread_mutex_lock(&wrapper->mutex);
    wrapper->running = 0;
    pthread_mutex_unlock(&wrapper->mutex);
    
    return NULL;
}

/* 优先级转换函数 */
static int _priority_to_sched_policy(os_task_priority_e priority)
{
    switch (priority) {
        case OS_TASK_PRIORITY_IDLE:
        case OS_TASK_PRIORITY_LOW:
        case OS_TASK_PRIORITY_NORMAL:
            return SCHED_OTHER;
        case OS_TASK_PRIORITY_HIGH:
        case OS_TASK_PRIORITY_REALTIME:
            return SCHED_RR;  /* 实时轮转调度 */
        default:
            return SCHED_OTHER;
    }
}

static int _priority_to_nice_value(os_task_priority_e priority)
{
    switch (priority) {
        case OS_TASK_PRIORITY_IDLE:      return 19;
        case OS_TASK_PRIORITY_LOW:       return 10;
        case OS_TASK_PRIORITY_NORMAL:    return 0;
        case OS_TASK_PRIORITY_HIGH:      return -10;
        case OS_TASK_PRIORITY_REALTIME:  return -20;
        default:                         return 0;
    }
}

os_error_e os_task_create(const os_task_config_t *config, os_task_handle_t *handle)
{
    if (config == NULL || handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    if (strlen(config->name) == 0 || config->function == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 创建任务包装结构体 */
    linux_task_wrapper_t *wrapper = malloc(sizeof(linux_task_wrapper_t));
    if (wrapper == NULL) {
        return OS_ERROR_NO_MEMORY;
    }
    
    /* 初始化包装结构体 */
    memset(wrapper, 0, sizeof(linux_task_wrapper_t));
    strncpy(wrapper->name, config->name, OS_MAX_TASK_NAME_LEN - 1);
    wrapper->name[OS_MAX_TASK_NAME_LEN - 1] = '\0';
    wrapper->function = config->function;
    wrapper->argument = config->argument;
    wrapper->stack_size = config->stack_size > 0 ? config->stack_size : LINUX_DEFAULT_STACK_SIZE;
    wrapper->priority = config->priority;
    wrapper->running = 1;
    
    if (pthread_mutex_init(&wrapper->mutex, NULL) != 0) {
        free(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    /* 设置线程属性 */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    
    /* 设置堆栈大小 */
    pthread_attr_setstacksize(&attr, wrapper->stack_size);
    
    /* 设置调度策略和优先级 */
    int policy = _priority_to_sched_policy(config->priority);
    pthread_attr_setschedpolicy(&attr, policy);
    
    if (policy == SCHED_RR || policy == SCHED_FIFO) {
        /* 实时调度策略需要设置优先级 */
        struct sched_param param;
        param.sched_priority = _priority_to_nice_value(config->priority);
        pthread_attr_setschedparam(&attr, &param);
        pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
    }
    
    /* 创建线程 */
    int result = pthread_create(&wrapper->thread, &attr, 
                               _task_thread_wrapper, wrapper);
    pthread_attr_destroy(&attr);
    
    if (result != 0) {
        pthread_mutex_destroy(&wrapper->mutex);
        free(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    *handle = (os_task_handle_t)wrapper;
    return OS_OK;
}

os_error_e os_task_delete(os_task_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_task_wrapper_t *wrapper = (linux_task_wrapper_t *)handle;
    
    pthread_mutex_lock(&wrapper->mutex);
    if (wrapper->running) {
        /* 取消线程 */
        pthread_cancel(wrapper->thread);
        wrapper->running = 0;
    }
    pthread_mutex_unlock(&wrapper->mutex);
    
    /* 等待线程结束 */
    pthread_join(wrapper->thread, NULL);
    
    /* 清理资源 */
    pthread_mutex_destroy(&wrapper->mutex);
    free(wrapper);
    
    return OS_OK;
}

os_error_e os_task_suspend(os_task_handle_t handle)
{
    /* Linux下没有直接的线程挂起API，这里使用简化实现 */
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 注意：这个实现不完美，实际应用中可能需要更复杂的机制 */
    return OS_ERROR_NOT_SUPPORTED;
}

os_error_e os_task_resume(os_task_handle_t handle)
{
    /* Linux下没有直接的线程恢复API */
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    return OS_ERROR_NOT_SUPPORTED;
}

os_task_handle_t os_task_get_current(void)
{
    /* Linux下获取当前任务包装结构体较复杂，这里返回NULL */
    return NULL;
}

os_error_e os_task_get_info(os_task_handle_t handle, os_task_info_t *info)
{
    if (handle == NULL || info == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_task_wrapper_t *wrapper = (linux_task_wrapper_t *)handle;
    
    /* 填充任务信息 */
    strncpy(info->name, wrapper->name, OS_MAX_TASK_NAME_LEN - 1);
    info->name[OS_MAX_TASK_NAME_LEN - 1] = '\0';
    info->handle = handle;
    info->priority = wrapper->priority;
    info->stack_size = wrapper->stack_size;
    
    /* Linux下获取堆栈信息较复杂，这里返回简化信息 */
    info->stack_high_water_mark = 0;
    info->task_number = (uint32_t)wrapper->thread;
    info->run_time_counter = 0;
    
    return OS_OK;
}

os_error_e os_task_set_priority(os_task_handle_t handle, os_task_priority_e priority)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_task_wrapper_t *wrapper = (linux_task_wrapper_t *)handle;
    
    int policy = _priority_to_sched_policy(priority);
    struct sched_param param;
    
    if (policy == SCHED_RR || policy == SCHED_FIFO) {
        param.sched_priority = _priority_to_nice_value(priority);
    } else {
        param.sched_priority = 0;
    }
    
    if (pthread_setschedparam(wrapper->thread, policy, &param) != 0) {
        return OS_ERROR_NOT_SUPPORTED;
    }
    
    wrapper->priority = priority;
    return OS_OK;
}

os_task_priority_e os_task_get_priority(os_task_handle_t handle)
{
    if (handle == NULL) {
        return OS_TASK_PRIORITY_NORMAL;
    }
    
    linux_task_wrapper_t *wrapper = (linux_task_wrapper_t *)handle;
    return wrapper->priority;
}

/* ========== 互斥锁函数实现 ========== */

os_error_e os_mutex_create(os_mutex_handle_t *handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 创建互斥锁包装结构体 */
    linux_mutex_wrapper_t *wrapper = malloc(sizeof(linux_mutex_wrapper_t));
    if (wrapper == NULL) {
        return OS_ERROR_NO_MEMORY;
    }
    
    /* 初始化POSIX互斥锁 */
    if (pthread_mutex_init(&wrapper->mutex, NULL) != 0) {
        free(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    *handle = (os_mutex_handle_t)wrapper;
    return OS_OK;
}

os_error_e os_mutex_delete(os_mutex_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_mutex_wrapper_t *wrapper = (linux_mutex_wrapper_t *)handle;
    
    /* 销毁POSIX互斥锁 */
    pthread_mutex_destroy(&wrapper->mutex);
    
    /* 释放包装结构体 */
    free(wrapper);
    
    return OS_OK;
}

os_error_e os_mutex_lock(os_mutex_handle_t handle, uint32_t timeout_ms)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_mutex_wrapper_t *wrapper = (linux_mutex_wrapper_t *)handle;
    
    if (timeout_ms == 0) {
        /* 非阻塞尝试 */
        return (pthread_mutex_trylock(&wrapper->mutex) == 0) ? OS_OK : OS_ERROR_TIMEOUT;
    } else if (timeout_ms == OS_WAIT_FOREVER) {
        /* 无限等待 */
        return (pthread_mutex_lock(&wrapper->mutex) == 0) ? OS_OK : OS_ERROR_RESOURCE_BUSY;
    } else {
        /* 超时等待 - POSIX没有直接的超时锁，这里使用简化实现 */
        /* 注意：这不是精确的超时实现 */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000;
        }
        
        return (pthread_mutex_timedlock(&wrapper->mutex, &ts) == 0) ? OS_OK : OS_ERROR_TIMEOUT;
    }
}

os_error_e os_mutex_unlock(os_mutex_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_mutex_wrapper_t *wrapper = (linux_mutex_wrapper_t *)handle;
    
    return (pthread_mutex_unlock(&wrapper->mutex) == 0) ? OS_OK : OS_ERROR_RESOURCE_BUSY;
}

/* ========== 信号量函数实现 ========== */

os_error_e os_semaphore_create_binary(os_semaphore_handle_t *handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 创建信号量包装结构体 */
    linux_semaphore_wrapper_t *wrapper = malloc(sizeof(linux_semaphore_wrapper_t));
    if (wrapper == NULL) {
        return OS_ERROR_NO_MEMORY;
    }
    
    /* 初始化POSIX信号量 */
    if (sem_init(&wrapper->sem, 0, 0) != 0) {
        free(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    wrapper->is_binary = true;
    *handle = (os_semaphore_handle_t)wrapper;
    return OS_OK;
}

os_error_e os_semaphore_create_counting(uint32_t max_count, uint32_t initial_count, 
                                       os_semaphore_handle_t *handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 创建信号量包装结构体 */
    linux_semaphore_wrapper_t *wrapper = malloc(sizeof(linux_semaphore_wrapper_t));
    if (wrapper == NULL) {
        return OS_ERROR_NO_MEMORY;
    }
    
    /* 初始化POSIX计数信号量 */
    if (sem_init(&wrapper->sem, 0, initial_count) != 0) {
        free(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    wrapper->is_binary = false;
    *handle = (os_semaphore_handle_t)wrapper;
    return OS_OK;
}

os_error_e os_semaphore_delete(os_semaphore_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_semaphore_wrapper_t *wrapper = (linux_semaphore_wrapper_t *)handle;
    
    /* 销毁POSIX信号量 */
    sem_destroy(&wrapper->sem);
    
    /* 释放包装结构体 */
    free(wrapper);
    
    return OS_OK;
}

os_error_e os_semaphore_take(os_semaphore_handle_t handle, uint32_t timeout_ms)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_semaphore_wrapper_t *wrapper = (linux_semaphore_wrapper_t *)handle;
    
    if (timeout_ms == 0) {
        /* 非阻塞尝试 */
        return (sem_trywait(&wrapper->sem) == 0) ? OS_OK : OS_ERROR_TIMEOUT;
    } else if (timeout_ms == OS_WAIT_FOREVER) {
        /* 无限等待 */
        while (sem_wait(&wrapper->sem) == -1 && errno == EINTR) {
            /* 被信号中断，重试 */
        }
        return OS_OK;
    } else {
        /* 超时等待 */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000;
        }
        
        return (sem_timedwait(&wrapper->sem, &ts) == 0) ? OS_OK : OS_ERROR_TIMEOUT;
    }
}

os_error_e os_semaphore_give(os_semaphore_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_semaphore_wrapper_t *wrapper = (linux_semaphore_wrapper_t *)handle;
    
    return (sem_post(&wrapper->sem) == 0) ? OS_OK : OS_ERROR_RESOURCE_BUSY;
}

/* ========== 队列函数实现 ========== */

os_error_e os_queue_create(const os_queue_config_t *config, os_queue_handle_t *handle)
{
    if (config == NULL || handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    if (config->queue_size == 0 || config->item_size == 0) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 创建队列包装结构体 */
    linux_queue_wrapper_t *wrapper = malloc(sizeof(linux_queue_wrapper_t));
    if (wrapper == NULL) {
        return OS_ERROR_NO_MEMORY;
    }
    
    memset(wrapper, 0, sizeof(linux_queue_wrapper_t));
    
    /* 分配队列缓冲区 */
    wrapper->buffer = malloc(config->item_size * config->queue_size);
    if (wrapper->buffer == NULL) {
        free(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    /* 初始化互斥锁和条件变量 */
    if (pthread_mutex_init(&wrapper->mutex, NULL) != 0) {
        free(wrapper->buffer);
        free(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    if (pthread_cond_init(&wrapper->cond_not_empty, NULL) != 0) {
        pthread_mutex_destroy(&wrapper->mutex);
        free(wrapper->buffer);
        free(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    if (pthread_cond_init(&wrapper->cond_not_full, NULL) != 0) {
        pthread_cond_destroy(&wrapper->cond_not_empty);
        pthread_mutex_destroy(&wrapper->mutex);
        free(wrapper->buffer);
        free(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    wrapper->item_size = config->item_size;
    wrapper->queue_length = config->queue_size;
    wrapper->head = 0;
    wrapper->tail = 0;
    wrapper->count = 0;
    
    *handle = (os_queue_handle_t)wrapper;
    return OS_OK;
}

os_error_e os_queue_delete(os_queue_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_queue_wrapper_t *wrapper = (linux_queue_wrapper_t *)handle;
    
    /* 销毁条件变量和互斥锁 */
    pthread_cond_destroy(&wrapper->cond_not_full);
    pthread_cond_destroy(&wrapper->cond_not_empty);
    pthread_mutex_destroy(&wrapper->mutex);
    
    /* 释放缓冲区 */
    free(wrapper->buffer);
    
    /* 释放包装结构体 */
    free(wrapper);
    
    return OS_OK;
}

os_error_e os_queue_send(os_queue_handle_t handle, const void *item, uint32_t timeout_ms)
{
    if (handle == NULL || item == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_queue_wrapper_t *wrapper = (linux_queue_wrapper_t *)handle;
    struct timespec ts;
    int result = 0;
    
    pthread_mutex_lock(&wrapper->mutex);
    
    if (timeout_ms != OS_WAIT_FOREVER) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000;
        }
    }
    
    /* 等待队列有空位 */
    while (wrapper->count >= wrapper->queue_length) {
        if (timeout_ms == 0) {
            /* 不等待 */
            pthread_mutex_unlock(&wrapper->mutex);
            return OS_ERROR_TIMEOUT;
        } else if (timeout_ms == OS_WAIT_FOREVER) {
            /* 无限等待 */
            pthread_cond_wait(&wrapper->cond_not_full, &wrapper->mutex);
        } else {
            /* 超时等待 */
            result = pthread_cond_timedwait(&wrapper->cond_not_full, 
                                           &wrapper->mutex, &ts);
            if (result == ETIMEDOUT) {
                pthread_mutex_unlock(&wrapper->mutex);
                return OS_ERROR_TIMEOUT;
            }
        }
    }
    
    /* 复制数据到队列 */
    uint8_t *dest = wrapper->buffer + (wrapper->tail * wrapper->item_size);
    memcpy(dest, item, wrapper->item_size);
    
    /* 更新队列指针 */
    wrapper->tail = (wrapper->tail + 1) % wrapper->queue_length;
    wrapper->count++;
    
    /* 通知等待接收的线程 */
    pthread_cond_signal(&wrapper->cond_not_empty);
    pthread_mutex_unlock(&wrapper->mutex);
    
    return OS_OK;
}

os_error_e os_queue_receive(os_queue_handle_t handle, void *buffer, uint32_t timeout_ms)
{
    if (handle == NULL || buffer == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_queue_wrapper_t *wrapper = (linux_queue_wrapper_t *)handle;
    struct timespec ts;
    int result = 0;
    
    pthread_mutex_lock(&wrapper->mutex);
    
    if (timeout_ms != OS_WAIT_FOREVER) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000;
        }
    }
    
    /* 等待队列有数据 */
    while (wrapper->count == 0) {
        if (timeout_ms == 0) {
            /* 不等待 */
            pthread_mutex_unlock(&wrapper->mutex);
            return OS_ERROR_TIMEOUT;
        } else if (timeout_ms == OS_WAIT_FOREVER) {
            /* 无限等待 */
            pthread_cond_wait(&wrapper->cond_not_empty, &wrapper->mutex);
        } else {
            /* 超时等待 */
            result = pthread_cond_timedwait(&wrapper->cond_not_empty,
                                           &wrapper->mutex, &ts);
            if (result == ETIMEDOUT) {
                pthread_mutex_unlock(&wrapper->mutex);
                return OS_ERROR_TIMEOUT;
            }
        }
    }
    
    /* 从队列复制数据 */
    uint8_t *src = wrapper->buffer + (wrapper->head * wrapper->item_size);
    memcpy(buffer, src, wrapper->item_size);
    
    /* 更新队列指针 */
    wrapper->head = (wrapper->head + 1) % wrapper->queue_length;
    wrapper->count--;
    
    /* 通知等待发送的线程 */
    pthread_cond_signal(&wrapper->cond_not_full);
    pthread_mutex_unlock(&wrapper->mutex);
    
    return OS_OK;
}

/* ========== 定时器函数实现 ========== */

/* 定时器线程函数 */
static void *_timer_thread_wrapper(void *arg)
{
    linux_timer_wrapper_t *wrapper = (linux_timer_wrapper_t *)arg;
    
    pthread_mutex_lock(&wrapper->mutex);
    
    while (wrapper->running) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += wrapper->period_ms / 1000;
        ts.tv_nsec += (wrapper->period_ms % 1000) * 1000000;
        
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000;
        }
        
        /* 等待定时器到期 */
        int result = pthread_cond_timedwait(&wrapper->cond, &wrapper->mutex, &ts);
        
        if (result == ETIMEDOUT && wrapper->running) {
            /* 定时器到期，执行回调 */
            wrapper->callback((os_timer_handle_t)wrapper, wrapper->argument);
            
            if (!wrapper->auto_reload) {
                wrapper->running = false;
                break;
            }
        }
    }
    
    pthread_mutex_unlock(&wrapper->mutex);
    return NULL;
}

os_error_e os_timer_create(const os_timer_config_t *config, os_timer_handle_t *handle)
{
    if (config == NULL || handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    if (config->callback == NULL || config->period_ms == 0) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 创建定时器包装结构体 */
    linux_timer_wrapper_t *wrapper = malloc(sizeof(linux_timer_wrapper_t));
    if (wrapper == NULL) {
        return OS_ERROR_NO_MEMORY;
    }
    
    memset(wrapper, 0, sizeof(linux_timer_wrapper_t));
    strncpy(wrapper->name, config->name, OS_MAX_TASK_NAME_LEN - 1);
    wrapper->name[OS_MAX_TASK_NAME_LEN - 1] = '\0';
    wrapper->callback = config->callback;
    wrapper->argument = config->argument;
    wrapper->period_ms = config->period_ms;
    wrapper->auto_reload = config->auto_reload;
    wrapper->running = false;
    
    if (pthread_mutex_init(&wrapper->mutex, NULL) != 0) {
        free(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    if (pthread_cond_init(&wrapper->cond, NULL) != 0) {
        pthread_mutex_destroy(&wrapper->mutex);
        free(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    *handle = (os_timer_handle_t)wrapper;
    
    /* 如果需要立即启动 */
    if (config->start_immediately) {
        return os_timer_start(*handle);
    }
    
    return OS_OK;
}

os_error_e os_timer_delete(os_timer_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_timer_wrapper_t *wrapper = (linux_timer_wrapper_t *)handle;
    
    /* 停止定时器 */
    os_timer_stop(handle);
    
    /* 等待定时器线程结束 */
    if (wrapper->thread) {
        pthread_join(wrapper->thread, NULL);
    }
    
    /* 清理资源 */
    pthread_cond_destroy(&wrapper->cond);
    pthread_mutex_destroy(&wrapper->mutex);
    free(wrapper);
    
    return OS_OK;
}

os_error_e os_timer_start(os_timer_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_timer_wrapper_t *wrapper = (linux_timer_wrapper_t *)handle;
    
    pthread_mutex_lock(&wrapper->mutex);
    
    if (!wrapper->running) {
        wrapper->running = true;
        
        /* 创建定时器线程 */
        if (pthread_create(&wrapper->thread, NULL, _timer_thread_wrapper, wrapper) != 0) {
            wrapper->running = false;
            pthread_mutex_unlock(&wrapper->mutex);
            return OS_ERROR_NO_MEMORY;
        }
    }
    
    pthread_mutex_unlock(&wrapper->mutex);
    return OS_OK;
}

os_error_e os_timer_stop(os_timer_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_timer_wrapper_t *wrapper = (linux_timer_wrapper_t *)handle;
    
    pthread_mutex_lock(&wrapper->mutex);
    
    if (wrapper->running) {
        wrapper->running = false;
        pthread_cond_signal(&wrapper->cond);
    }
    
    pthread_mutex_unlock(&wrapper->mutex);
    return OS_OK;
}

os_error_e os_timer_reset(os_timer_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 停止然后重新启动定时器 */
    os_timer_stop(handle);
    return os_timer_start(handle);
}

/* ========== 内存池函数实现 ========== */

os_error_e os_memory_pool_create(const os_memory_pool_config_t *config, 
                                os_memory_pool_handle_t *handle)
{
    if (config == NULL || handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    if (config->block_size == 0 || config->block_count == 0) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 创建内存池包装结构体 */
    linux_memory_pool_wrapper_t *wrapper = malloc(sizeof(linux_memory_pool_wrapper_t));
    if (wrapper == NULL) {
        return OS_ERROR_NO_MEMORY;
    }
    
    memset(wrapper, 0, sizeof(linux_memory_pool_wrapper_t));
    wrapper->block_size = config->block_size;
    wrapper->block_count = config->block_count;
    
    /* 分配内存缓冲区 */
    if (config->memory_buffer != NULL) {
        wrapper->memory_buffer = config->memory_buffer;
    } else {
        wrapper->memory_buffer = malloc(config->block_size * config->block_count);
        if (wrapper->memory_buffer == NULL) {
            free(wrapper);
            return OS_ERROR_NO_MEMORY;
        }
    }
    
    /* 初始化空闲链表 */
    wrapper->free_list = malloc(config->block_count * sizeof(uint8_t *));
    if (wrapper->free_list == NULL) {
        if (config->memory_buffer == NULL) {
            free(wrapper->memory_buffer);
        }
        free(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    /* 初始化互斥锁 */
    if (pthread_mutex_init(&wrapper->mutex, NULL) != 0) {
        free(wrapper->free_list);
        if (config->memory_buffer == NULL) {
            free(wrapper->memory_buffer);
        }
        free(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    /* 初始化空闲链表 */
    for (uint32_t i = 0; i < config->block_count; i++) {
        wrapper->free_list[i] = wrapper->memory_buffer + (i * config->block_size);
    }
    
    *handle = (os_memory_pool_handle_t)wrapper;
    return OS_OK;
}

os_error_e os_memory_pool_delete(os_memory_pool_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_memory_pool_wrapper_t *wrapper = (linux_memory_pool_wrapper_t *)handle;
    
    /* 销毁互斥锁 */
    pthread_mutex_destroy(&wrapper->mutex);
    
    /* 释放资源 */
    free(wrapper->free_list);
    free(wrapper);
    
    return OS_OK;
}

void *os_memory_pool_alloc(os_memory_pool_handle_t handle, uint32_t timeout_ms)
{
    if (handle == NULL) {
        return NULL;
    }
    
    linux_memory_pool_wrapper_t *wrapper = (linux_memory_pool_wrapper_t *)handle;
    struct timespec ts;
    int result = 0;
    
    pthread_mutex_lock(&wrapper->mutex);
    
    /* 简化实现：总是立即返回，不实现超时 */
    /* 在实际实现中，这里应该实现等待逻辑 */
    
    void *block = NULL;
    /* 这里应该从空闲链表中分配内存块 */
    /* 简化实现：总是返回NULL */
    
    pthread_mutex_unlock(&wrapper->mutex);
    return block;
}

os_error_e os_memory_pool_free(os_memory_pool_handle_t handle, void *block)
{
    if (handle == NULL || block == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    linux_memory_pool_wrapper_t *wrapper = (linux_memory_pool_wrapper_t *)handle;
    
    pthread_mutex_lock(&wrapper->mutex);
    
    /* 简化实现：不实际释放，只是返回成功 */
    /* 在实际实现中，这里应该将内存块返回到空闲链表 */
    
    pthread_mutex_unlock(&wrapper->mutex);
    return OS_OK;
}

/* ========== 调试函数实现 ========== */

void os_debug_printf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);
}

void os_assert_failed(const char *file, uint32_t line, const char *expr)
{
    fprintf(stderr, "Assertion failed: %s, file %s, line %u\n", 
            expr, file, line);
    abort();
}

/* ========== 文件结束 ========== */
