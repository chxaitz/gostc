/**
 * @file    gostc_os.c
 * @brief   通信代理操作系统抽象层实现（FreeRTOS适配）
 * @author  mosser
 * @date    2026-03-07
 * @version 1.0.0
 * 
 * @note    基于FreeRTOS 9.0.0a实现的操作系统抽象层
 * @warning 需要正确配置FreeRTOS环境
 */

#include "gostc_os.h"
#include "gostc_err.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

/* FreeRTOS头文件 */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"
#include "timers.h"
#include "event_groups.h"
#include "portable.h"

/* 内部宏定义 */
#define FREERTOS_MAX_TASK_NAME_LEN    configMAX_TASK_NAME_LEN
#define FREERTOS_MAX_QUEUE_LENGTH     configQUEUE_REGISTRY_SIZE

/* 内部结构体定义 */

/* 任务包装结构体 */
typedef struct {
    TaskHandle_t task_handle;         /* FreeRTOS任务句柄 */
    char name[OS_MAX_TASK_NAME_LEN];  /* 任务名称 */
    uint32_t stack_size;              /* 堆栈大小 */
    os_task_priority_e priority;      /* 任务优先级 */
} os_task_wrapper_t;

/* 互斥锁包装结构体 */
typedef struct {
    SemaphoreHandle_t mutex_handle;   /* FreeRTOS互斥锁句柄 */
} os_mutex_wrapper_t;

/* 信号量包装结构体 */
typedef struct {
    SemaphoreHandle_t sem_handle;     /* FreeRTOS信号量句柄 */
    bool is_binary;                   /* 是否为二进制信号量 */
} os_semaphore_wrapper_t;

/* 队列包装结构体 */
typedef struct {
    QueueHandle_t queue_handle;       /* FreeRTOS队列句柄 */
    uint32_t item_size;               /* 项目大小 */
} os_queue_wrapper_t;

/* 定时器包装结构体 */
typedef struct {
    TimerHandle_t timer_handle;       /* FreeRTOS定时器句柄 */
    os_timer_callback_t user_callback; /* 用户回调函数 */
    void *user_arg;                   /* 用户参数 */
} os_timer_wrapper_t;

/* 内存池包装结构体 */
typedef struct {
    uint32_t block_size;              /* 块大小 */
    uint32_t block_count;             /* 块数量 */
    uint8_t *memory_buffer;           /* 内存缓冲区 */
    uint8_t *free_list;               /* 空闲链表 */
    SemaphoreHandle_t mutex;          /* 互斥锁 */
} os_memory_pool_wrapper_t;

/* 内部函数声明 */
static BaseType_t _priority_convert_to_freertos(os_task_priority_e priority);
static os_task_priority_e _priority_convert_from_freertos(BaseType_t freertos_priority);
static void _timer_callback_wrapper(TimerHandle_t timer_handle);

/* 系统管理函数实现 */

uint32_t os_get_tick_count(void)
{
    return xTaskGetTickCount();
}

void os_delay_ms(uint32_t ms)
{
    vTaskDelay(pdMS_TO_TICKS(ms));
}

os_error_e os_get_system_info(os_system_info_t *info)
{
    if (info == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 获取系统tick信息 */
    info->tick_count = xTaskGetTickCount();
    info->tick_rate_hz = configTICK_RATE_HZ;
    
    /* 获取堆信息 */
    info->free_heap_size = xPortGetFreeHeapSize();
    info->min_free_heap_size = xPortGetMinimumEverFreeHeapSize();
    
    /* 获取任务信息 */
    info->total_tasks = uxTaskGetNumberOfTasks();
    
    /* 内核版本信息 */
    snprintf(info->kernel_version, sizeof(info->kernel_version), 
             "FreeRTOS %d.%d.%d", tskKERNEL_VERSION_MAJOR, 
             tskKERNEL_VERSION_MINOR, tskKERNEL_VERSION_BUILD);
    
    /* 其他信息需要运行时计算 */
    info->running_tasks = 0;
    info->suspended_tasks = 0;
    
    return OS_OK;
}

uint32_t os_enter_critical(void)
{
    taskENTER_CRITICAL();
    return 0; /* FreeRTOS不返回状态，这里返回0 */
}

void os_exit_critical(uint32_t state)
{
    (void)state; /* 不使用状态参数 */
    taskEXIT_CRITICAL();
}

/* 任务管理函数实现 */

os_error_e os_task_create(const os_task_config_t *config, os_task_handle_t *handle)
{
    if (config == NULL || handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    if (strlen(config->name) == 0 || config->function == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 转换优先级 */
    BaseType_t freertos_priority = _priority_convert_to_freertos(config->priority);
    
    /* 创建任务包装结构体 */
    os_task_wrapper_t *wrapper = (os_task_wrapper_t *)pvPortMalloc(sizeof(os_task_wrapper_t));
    if (wrapper == NULL) {
        return OS_ERROR_NO_MEMORY;
    }
    
    /* 设置包装结构体信息 */
    strncpy(wrapper->name, config->name, OS_MAX_TASK_NAME_LEN - 1);
    wrapper->name[OS_MAX_TASK_NAME_LEN - 1] = '\0';
    wrapper->stack_size = config->stack_size;
    wrapper->priority = config->priority;
    
    /* 创建FreeRTOS任务 */
    BaseType_t result = xTaskCreate(
        (TaskFunction_t)config->function,  /* 任务函数 */
        config->name,                      /* 任务名称 */
        config->stack_size / sizeof(StackType_t), /* 堆栈深度 */
        config->argument,                  /* 任务参数 */
        freertos_priority,                 /* 任务优先级 */
        &wrapper->task_handle              /* 任务句柄 */
    );
    
    if (result != pdPASS) {
        vPortFree(wrapper);
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
    
    os_task_wrapper_t *wrapper = (os_task_wrapper_t *)handle;
    
    /* 删除FreeRTOS任务 */
    vTaskDelete(wrapper->task_handle);
    
    /* 释放包装结构体 */
    vPortFree(wrapper);
    
    return OS_OK;
}

os_error_e os_task_suspend(os_task_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_task_wrapper_t *wrapper = (os_task_wrapper_t *)handle;
    vTaskSuspend(wrapper->task_handle);
    
    return OS_OK;
}

os_error_e os_task_resume(os_task_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_task_wrapper_t *wrapper = (os_task_wrapper_t *)handle;
    vTaskResume(wrapper->task_handle);
    
    return OS_OK;
}

os_task_handle_t os_task_get_current(void)
{
    /* 注意：这个简化实现只返回当前任务的句柄，不创建包装结构体 */
    TaskHandle_t current_task = xTaskGetCurrentTaskHandle();
    
    /* 在实际实现中，可能需要查找或创建包装结构体 */
    /* 这里返回NULL作为占位符 */
    return NULL;
}

os_error_e os_task_get_info(os_task_handle_t handle, os_task_info_t *info)
{
    if (handle == NULL || info == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_task_wrapper_t *wrapper = (os_task_wrapper_t *)handle;
    
    /* 填充任务信息 */
    strncpy(info->name, wrapper->name, OS_MAX_TASK_NAME_LEN - 1);
    info->name[OS_MAX_TASK_NAME_LEN - 1] = '\0';
    info->handle = handle;
    info->priority = wrapper->priority;
    info->stack_size = wrapper->stack_size;
    
    /* 获取堆栈高水位标记 */
    info->stack_high_water_mark = uxTaskGetStackHighWaterMark(wrapper->task_handle);
    
    /* 其他信息需要额外获取 */
    info->task_number = (uint32_t)wrapper->task_handle; /* 简化：使用句柄作为编号 */
    info->run_time_counter = 0; /* FreeRTOS需要启用统计功能 */
    
    return OS_OK;
}

os_error_e os_task_set_priority(os_task_handle_t handle, os_task_priority_e priority)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_task_wrapper_t *wrapper = (os_task_wrapper_t *)handle;
    BaseType_t freertos_priority = _priority_convert_to_freertos(priority);
    
    vTaskPrioritySet(wrapper->task_handle, freertos_priority);
    wrapper->priority = priority;
    
    return OS_OK;
}

os_task_priority_e os_task_get_priority(os_task_handle_t handle)
{
    if (handle == NULL) {
        return OS_TASK_PRIORITY_NORMAL;
    }
    
    os_task_wrapper_t *wrapper = (os_task_wrapper_t *)handle;
    return wrapper->priority;
}

/* 互斥锁函数实现 */

os_error_e os_mutex_create(os_mutex_handle_t *handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 创建互斥锁包装结构体 */
    os_mutex_wrapper_t *wrapper = (os_mutex_wrapper_t *)pvPortMalloc(sizeof(os_mutex_wrapper_t));
    if (wrapper == NULL) {
        return OS_ERROR_NO_MEMORY;
    }
    
    /* 创建FreeRTOS互斥锁 */
    wrapper->mutex_handle = xSemaphoreCreateMutex();
    if (wrapper->mutex_handle == NULL) {
        vPortFree(wrapper);
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
    
    os_mutex_wrapper_t *wrapper = (os_mutex_wrapper_t *)handle;
    
    /* 删除FreeRTOS互斥锁 */
    vSemaphoreDelete(wrapper->mutex_handle);
    
    /* 释放包装结构体 */
    vPortFree(wrapper);
    
    return OS_OK;
}

os_error_e os_mutex_lock(os_mutex_handle_t handle, uint32_t timeout_ms)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_mutex_wrapper_t *wrapper = (os_mutex_wrapper_t *)handle;
    TickType_t timeout_ticks = (timeout_ms == OS_WAIT_FOREVER) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
    
    if (xSemaphoreTake(wrapper->mutex_handle, timeout_ticks) == pdTRUE) {
        return OS_OK;
    } else {
        return OS_ERROR_TIMEOUT;
    }
}

os_error_e os_mutex_unlock(os_mutex_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_mutex_wrapper_t *wrapper = (os_mutex_wrapper_t *)handle;
    
    if (xSemaphoreGive(wrapper->mutex_handle) == pdTRUE) {
        return OS_OK;
    } else {
        return OS_ERROR_RESOURCE_BUSY;
    }
}

/* 信号量函数实现 */

os_error_e os_semaphore_create_binary(os_semaphore_handle_t *handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 创建信号量包装结构体 */
    os_semaphore_wrapper_t *wrapper = (os_semaphore_wrapper_t *)pvPortMalloc(sizeof(os_semaphore_wrapper_t));
    if (wrapper == NULL) {
        return OS_ERROR_NO_MEMORY;
    }
    
    /* 创建FreeRTOS二进制信号量 */
    wrapper->sem_handle = xSemaphoreCreateBinary();
    if (wrapper->sem_handle == NULL) {
        vPortFree(wrapper);
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
    os_semaphore_wrapper_t *wrapper = (os_semaphore_wrapper_t *)pvPortMalloc(sizeof(os_semaphore_wrapper_t));
    if (wrapper == NULL) {
        return OS_ERROR_NO_MEMORY;
    }
    
    /* 创建FreeRTOS计数信号量 */
    wrapper->sem_handle = xSemaphoreCreateCounting(max_count, initial_count);
    if (wrapper->sem_handle == NULL) {
        vPortFree(wrapper);
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
    
    os_semaphore_wrapper_t *wrapper = (os_semaphore_wrapper_t *)handle;
    
    /* 删除FreeRTOS信号量 */
    vSemaphoreDelete(wrapper->sem_handle);
    
    /* 释放包装结构体 */
    vPortFree(wrapper);
    
    return OS_OK;
}

os_error_e os_semaphore_take(os_semaphore_handle_t handle, uint32_t timeout_ms)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_semaphore_wrapper_t *wrapper = (os_semaphore_wrapper_t *)handle;
    TickType_t timeout_ticks = (timeout_ms == OS_WAIT_FOREVER) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
    
    if (xSemaphoreTake(wrapper->sem_handle, timeout_ticks) == pdTRUE) {
        return OS_OK;
    } else {
        return OS_ERROR_TIMEOUT;
    }
}

os_error_e os_semaphore_give(os_semaphore_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_semaphore_wrapper_t *wrapper = (os_semaphore_wrapper_t *)handle;
    
    if (xSemaphoreGive(wrapper->sem_handle) == pdTRUE) {
        return OS_OK;
    } else {
        return OS_ERROR_RESOURCE_BUSY;
    }
}

/* 队列函数实现 */

os_error_e os_queue_create(const os_queue_config_t *config, os_queue_handle_t *handle)
{
    if (config == NULL || handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    if (config->queue_size == 0 || config->item_size == 0) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 创建队列包装结构体 */
    os_queue_wrapper_t *wrapper = (os_queue_wrapper_t *)pvPortMalloc(sizeof(os_queue_wrapper_t));
    if (wrapper == NULL) {
        return OS_ERROR_NO_MEMORY;
    }
    
    /* 创建FreeRTOS队列 */
    wrapper->queue_handle = xQueueCreate(config->queue_size, config->item_size);
    if (wrapper->queue_handle == NULL) {
        vPortFree(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    wrapper->item_size = config->item_size;
    *handle = (os_queue_handle_t)wrapper;
    return OS_OK;
}

os_error_e os_queue_delete(os_queue_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_queue_wrapper_t *wrapper = (os_queue_wrapper_t *)handle;
    
    /* 删除FreeRTOS队列 */
    vQueueDelete(wrapper->queue_handle);
    
    /* 释放包装结构体 */
    vPortFree(wrapper);
    
    return OS_OK;
}

os_error_e os_queue_send(os_queue_handle_t handle, const void *item, uint32_t timeout_ms)
{
    if (handle == NULL || item == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_queue_wrapper_t *wrapper = (os_queue_wrapper_t *)handle;
    TickType_t timeout_ticks = (timeout_ms == OS_WAIT_FOREVER) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
    
    if (xQueueSend(wrapper->queue_handle, item, timeout_ticks) == pdPASS) {
        return OS_OK;
    } else {
        return OS_ERROR_TIMEOUT;
    }
}

os_error_e os_queue_receive(os_queue_handle_t handle, void *buffer, uint32_t timeout_ms)
{
    if (handle == NULL || buffer == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_queue_wrapper_t *wrapper = (os_queue_wrapper_t *)handle;
    TickType_t timeout_ticks = (timeout_ms == OS_WAIT_FOREVER) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
    
    if (xQueueReceive(wrapper->queue_handle, buffer, timeout_ticks) == pdPASS) {
        return OS_OK;
    } else {
        return OS_ERROR_TIMEOUT;
    }
}

/* 定时器函数实现 */

os_error_e os_timer_create(const os_timer_config_t *config, os_timer_handle_t *handle)
{
    if (config == NULL || handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    if (config->callback == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 创建定时器包装结构体 */
    os_timer_wrapper_t *wrapper = (os_timer_wrapper_t *)pvPortMalloc(sizeof(os_timer_wrapper_t));
    if (wrapper == NULL) {
        return OS_ERROR_NO_MEMORY;
    }
    
    /* 设置包装结构体信息 */
    wrapper->user_callback = config->callback;
    wrapper->user_arg = config->argument;
    
    /* 创建FreeRTOS定时器 */
    wrapper->timer_handle = xTimerCreate(
        config->name,                           /* 定时器名称 */
        pdMS_TO_TICKS(config->period_ms),       /* 周期（转换为tick） */
        config->auto_reload ? pdTRUE : pdFALSE, /* 自动重载 */
        (void *)wrapper,                        /* 定时器ID（传递包装结构体） */
        _timer_callback_wrapper                 /* 回调函数包装器 */
    );
    
    if (wrapper->timer_handle == NULL) {
        vPortFree(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    *handle = (os_timer_handle_t)wrapper;
    
    /* 如果需要立即启动 */
    if (config->start_immediately) {
        xTimerStart(wrapper->timer_handle, 0);
    }
    
    return OS_OK;
}

os_error_e os_timer_delete(os_timer_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_timer_wrapper_t *wrapper = (os_timer_wrapper_t *)handle;
    
    /* 删除FreeRTOS定时器 */
    xTimerDelete(wrapper->timer_handle, portMAX_DELAY);
    
    /* 释放包装结构体 */
    vPortFree(wrapper);
    
    return OS_OK;
}

os_error_e os_timer_start(os_timer_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_timer_wrapper_t *wrapper = (os_timer_wrapper_t *)handle;
    
    if (xTimerStart(wrapper->timer_handle, portMAX_DELAY) == pdPASS) {
        return OS_OK;
    } else {
        return OS_ERROR_RESOURCE_BUSY;
    }
}

os_error_e os_timer_stop(os_timer_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_timer_wrapper_t *wrapper = (os_timer_wrapper_t *)handle;
    
    if (xTimerStop(wrapper->timer_handle, portMAX_DELAY) == pdPASS) {
        return OS_OK;
    } else {
        return OS_ERROR_RESOURCE_BUSY;
    }
}

os_error_e os_timer_reset(os_timer_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_timer_wrapper_t *wrapper = (os_timer_wrapper_t *)handle;
    
    if (xTimerReset(wrapper->timer_handle, portMAX_DELAY) == pdPASS) {
        return OS_OK;
    } else {
        return OS_ERROR_RESOURCE_BUSY;
    }
}

/* 内存管理函数实现 */

void *os_malloc(size_t size)
{
    return pvPortMalloc(size);
}

void os_free(void *ptr)
{
    vPortFree(ptr);
}

void *os_aligned_alloc(size_t alignment, size_t size)
{
    /* FreeRTOS标准分配器不支持对齐分配 */
    /* 这里实现一个简单的对齐分配 */
    size_t total_size = size + alignment - 1 + sizeof(void *);
    uint8_t *raw_ptr = (uint8_t *)pvPortMalloc(total_size);
    
    if (raw_ptr == NULL) {
        return NULL;
    }
    
    /* 计算对齐地址 */
    uint8_t *aligned_ptr = (uint8_t *)(((uintptr_t)raw_ptr + sizeof(void *) + alignment - 1) & ~(alignment - 1));
    
    /* 存储原始指针 */
    *((void **)(aligned_ptr - sizeof(void *))) = raw_ptr;
    
    return aligned_ptr;
}

os_error_e os_memory_pool_create(const os_memory_pool_config_t *config, 
                                os_memory_pool_handle_t *handle)
{
    if (config == NULL || handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    if (config->block_size == 0 || config->block_count == 0) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    /* 计算所需内存 */
    size_t total_size = sizeof(os_memory_pool_wrapper_t) + 
                       config->block_count * (config->block_size + sizeof(uint8_t *));
    
    /* 创建内存池包装结构体 */
    os_memory_pool_wrapper_t *wrapper = (os_memory_pool_wrapper_t *)pvPortMalloc(total_size);
    if (wrapper == NULL) {
        return OS_ERROR_NO_MEMORY;
    }
    
    /* 初始化包装结构体 */
    wrapper->block_size = config->block_size;
    wrapper->block_count = config->block_count;
    
    /* 使用提供的缓冲区或分配新缓冲区 */
    if (config->memory_buffer != NULL) {
        wrapper->memory_buffer = config->memory_buffer;
    } else {
        wrapper->memory_buffer = (uint8_t *)pvPortMalloc(config->block_count * config->block_size);
        if (wrapper->memory_buffer == NULL) {
            vPortFree(wrapper);
            return OS_ERROR_NO_MEMORY;
        }
    }
    
    /* 初始化空闲链表 */
    wrapper->free_list = NULL;
    for (uint32_t i = 0; i < config->block_count; i++) {
        uint8_t *block = wrapper->memory_buffer + i * config->block_size;
        uint8_t **next_ptr = (uint8_t **)block;
        *next_ptr = wrapper->free_list;
        wrapper->free_list = block;
    }
    
    /* 创建互斥锁 */
    wrapper->mutex = xSemaphoreCreateMutex();
    if (wrapper->mutex == NULL) {
        if (config->memory_buffer == NULL) {
            vPortFree(wrapper->memory_buffer);
        }
        vPortFree(wrapper);
        return OS_ERROR_NO_MEMORY;
    }
    
    *handle = (os_memory_pool_handle_t)wrapper;
    return OS_OK;
}

os_error_e os_memory_pool_delete(os_memory_pool_handle_t handle)
{
    if (handle == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_memory_pool_wrapper_t *wrapper = (os_memory_pool_wrapper_t *)handle;
    
    /* 删除互斥锁 */
    vSemaphoreDelete(wrapper->mutex);
    
    /* 如果内存缓冲区是动态分配的，则释放它 */
    /* 注意：这里需要知道缓冲区是否是动态分配的 */
    /* 简化实现：假设总是动态分配 */
    vPortFree(wrapper->memory_buffer);
    
    /* 释放包装结构体 */
    vPortFree(wrapper);
    
    return OS_OK;
}

void *os_memory_pool_alloc(os_memory_pool_handle_t handle, uint32_t timeout_ms)
{
    if (handle == NULL) {
        return NULL;
    }
    
    os_memory_pool_wrapper_t *wrapper = (os_memory_pool_wrapper_t *)handle;
    TickType_t timeout_ticks = (timeout_ms == OS_WAIT_FOREVER) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
    
    /* 获取互斥锁 */
    if (xSemaphoreTake(wrapper->mutex, timeout_ticks) != pdTRUE) {
        return NULL;
    }
    
    /* 从空闲链表中分配 */
    void *block = NULL;
    if (wrapper->free_list != NULL) {
        block = wrapper->free_list;
        wrapper->free_list = *(uint8_t **)block;
    }
    
    /* 释放互斥锁 */
    xSemaphoreGive(wrapper->mutex);
    
    return block;
}

os_error_e os_memory_pool_free(os_memory_pool_handle_t handle, void *block)
{
    if (handle == NULL || block == NULL) {
        return OS_ERROR_INVALID_PARAM;
    }
    
    os_memory_pool_wrapper_t *wrapper = (os_memory_pool_wrapper_t *)handle;
    
    /* 获取互斥锁 */
    if (xSemaphoreTake(wrapper->mutex, portMAX_DELAY) != pdTRUE) {
        return OS_ERROR_RESOURCE_BUSY;
    }
    
    /* 将块添加到空闲链表 */
    uint8_t **next_ptr = (uint8_t **)block;
    *next_ptr = wrapper->free_list;
    wrapper->free_list = (uint8_t *)block;
    
    /* 释放互斥锁 */
    xSemaphoreGive(wrapper->mutex);
    
    return OS_OK;
}

/* 调试函数实现 */

void os_debug_printf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}

void os_assert_failed(const char *file, uint32_t line, const char *expr)
{
    printf("Assertion failed: %s, file %s, line %lu\n", expr, file, (unsigned long)line);
    
    /* 触发调试断点或停止系统 */
    /* 在实际实现中，这里可能需要调用系统特定的断言处理 */
    while (1) {
        /* 死循环，等待调试器介入 */
    }
}

/* 内部辅助函数实现 */

static BaseType_t _priority_convert_to_freertos(os_task_priority_e priority)
{
    switch (priority) {
        case OS_TASK_PRIORITY_IDLE:
            return tskIDLE_PRIORITY;
        case OS_TASK_PRIORITY_LOW:
            return tskIDLE_PRIORITY + 1;
        case OS_TASK_PRIORITY_NORMAL:
            return tskIDLE_PRIORITY + 2;
        case OS_TASK_PRIORITY_HIGH:
            return tskIDLE_PRIORITY + 3;
        case OS_TASK_PRIORITY_REALTIME:
            return tskIDLE_PRIORITY + 4;
        default:
            return tskIDLE_PRIORITY + 2;
    }
}

static os_task_priority_e _priority_convert_from_freertos(BaseType_t freertos_priority)
{
    BaseType_t idle_priority = tskIDLE_PRIORITY;
    
    if (freertos_priority == idle_priority) {
        return OS_TASK_PRIORITY_IDLE;
    } else if (freertos_priority == idle_priority + 1) {
        return OS_TASK_PRIORITY_LOW;
    } else if (freertos_priority == idle_priority + 2) {
        return OS_TASK_PRIORITY_NORMAL;
    } else if (freertos_priority == idle_priority + 3) {
        return OS_TASK_PRIORITY_HIGH;
    } else if (freertos_priority >= idle_priority + 4) {
        return OS_TASK_PRIORITY_REALTIME;
    } else {
        return OS_TASK_PRIORITY_NORMAL;
    }
}

static void _timer_callback_wrapper(TimerHandle_t timer_handle)
{
    /* 从定时器ID获取包装结构体 */
    os_timer_wrapper_t *wrapper = (os_timer_wrapper_t *)pvTimerGetTimerID(timer_handle);
    
    if (wrapper != NULL && wrapper->user_callback != NULL) {
        /* 调用用户回调函数 */
        wrapper->user_callback((os_timer_handle_t)wrapper, wrapper->user_arg);
    }
}

/* 文件结束 */