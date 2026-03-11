/**
 * @file    test_os_linux.c
 * @brief   Linux操作系统适配层测试程序
 * @author  mosser
 * @date    2026-03-07
 * @version 1.0.0
 */

#include "gostc_os.h"
#include <stdio.h>
#include <string.h>

/* 测试任务函数 */
static void test_task_function(void *arg)
{
    const char *task_name = (const char *)arg;
    printf("Test task '%s' started\n", task_name);
    
    /* 延时一段时间 */
    os_delay_ms(100);
    
    printf("Test task '%s' finished\n", task_name);
}

/* 测试定时器回调 */
static void test_timer_callback(os_timer_handle_t timer, void *arg)
{
    static int count = 0;
    printf("Timer callback called: count = %d\n", ++count);
    
    if (count >= 3) {
        printf("Stopping timer after 3 calls\n");
        os_timer_stop(timer);
    }
}

/* 主测试函数 */
int main(int argc, char *argv[])
{
    printf("=== Linux OS Adapter Layer Test ===\n\n");
    
    /* 测试1: 内存管理 */
    printf("Test 1: Memory Management\n");
    printf("-------------------------\n");
    
    void *ptr1 = os_malloc(100);
    if (ptr1) {
        printf("  os_malloc(100) succeeded: %p\n", ptr1);
        memset(ptr1, 0xAA, 100);
        os_free(ptr1);
        printf("  os_free() succeeded\n");
    } else {
        printf("  os_malloc(100) failed\n");
    }
    
    void *ptr2 = os_calloc(10, 20);
    if (ptr2) {
        printf("  os_calloc(10, 20) succeeded: %p\n", ptr2);
        os_free(ptr2);
        printf("  os_free() succeeded\n");
    } else {
        printf("  os_calloc(10, 20) failed\n");
    }
    
    printf("\n");
    
    /* 测试2: 时间管理 */
    printf("Test 2: Time Management\n");
    printf("-----------------------\n");
    
    uint32_t tick1 = os_get_tick_count();
    printf("  Initial tick count: %u\n", tick1);
    
    printf("  Delaying 500ms...\n");
    os_delay_ms(500);
    
    uint32_t tick2 = os_get_tick_count();
    printf("  Tick count after delay: %u\n", tick2);
    printf("  Elapsed time: %u ms\n", tick2 - tick1);
    
    printf("\n");
    
    /* 测试3: 系统信息 */
    printf("Test 3: System Information\n");
    printf("--------------------------\n");
    
    os_system_info_t sys_info;
    if (os_get_system_info(&sys_info) == OS_OK) {
        printf("  Kernel version: %s\n", sys_info.kernel_version);
        printf("  Tick rate: %u Hz\n", sys_info.tick_rate_hz);
        printf("  Free heap: %u bytes\n", sys_info.free_heap_size);
    } else {
        printf("  Failed to get system info\n");
    }
    
    printf("\n");
    
    /* 测试4: 任务管理 */
    printf("Test 4: Task Management\n");
    printf("-----------------------\n");
    
    os_task_config_t task_config = {
        .name = "TestTask",
        .function = test_task_function,
        .argument = (void *)"TestTask",
        .stack_size = 4096,
        .priority = OS_TASK_PRIORITY_NORMAL,
        .stack_buffer = NULL
    };
    
    os_task_handle_t task_handle;
    os_error_e result = os_task_create(&task_config, &task_handle);
    
    if (result == OS_OK) {
        printf("  Task created successfully\n");
        
        /* 等待任务完成 */
        os_delay_ms(200);
        
        /* 删除任务 */
        result = os_task_delete(task_handle);
        if (result == OS_OK) {
            printf("  Task deleted successfully\n");
        } else {
            printf("  Failed to delete task: error %d\n", result);
        }
    } else {
        printf("  Failed to create task: error %d\n", result);
    }
    
    printf("\n");
    
    /* 测试5: 互斥锁 */
    printf("Test 5: Mutex\n");
    printf("-------------\n");
    
    os_mutex_handle_t mutex_handle;
    result = os_mutex_create(&mutex_handle);
    
    if (result == OS_OK) {
        printf("  Mutex created successfully\n");
        
        /* 获取互斥锁 */
        result = os_mutex_lock(mutex_handle, OS_WAIT_FOREVER);
        if (result == OS_OK) {
            printf("  Mutex locked successfully\n");
            
            /* 释放互斥锁 */
            result = os_mutex_unlock(mutex_handle);
            if (result == OS_OK) {
                printf("  Mutex unlocked successfully\n");
            } else {
                printf("  Failed to unlock mutex: error %d\n", result);
            }
        } else {
            printf("  Failed to lock mutex: error %d\n", result);
        }
        
        /* 删除互斥锁 */
        result = os_mutex_delete(mutex_handle);
        if (result == OS_OK) {
            printf("  Mutex deleted successfully\n");
        } else {
            printf("  Failed to delete mutex: error %d\n", result);
        }
    } else {
        printf("  Failed to create mutex: error %d\n", result);
    }
    
    printf("\n");
    
    /* 测试6: 信号量 */
    printf("Test 6: Semaphore\n");
    printf("-----------------\n");
    
    os_semaphore_handle_t sem_handle;
    result = os_semaphore_create_binary(&sem_handle);
    
    if (result == OS_OK) {
        printf("  Binary semaphore created successfully\n");
        
        /* 释放信号量 */
        result = os_semaphore_give(sem_handle);
        if (result == OS_OK) {
            printf("  Semaphore given successfully\n");
        } else {
            printf("  Failed to give semaphore: error %d\n", result);
        }
        
        /* 获取信号量 */
        result = os_semaphore_take(sem_handle, 1000); /* 1秒超时 */
        if (result == OS_OK) {
            printf("  Semaphore taken successfully\n");
        } else {
            printf("  Failed to take semaphore: error %d\n", result);
        }
        
        /* 删除信号量 */
        result = os_semaphore_delete(sem_handle);
        if (result == OS_OK) {
            printf("  Semaphore deleted successfully\n");
        } else {
            printf("  Failed to delete semaphore: error %d\n", result);
        }
    } else {
        printf("  Failed to create semaphore: error %d\n", result);
    }
    
    printf("\n");
    
    /* 测试7: 队列 */
    printf("Test 7: Queue\n");
    printf("-------------\n");
    
    os_queue_config_t queue_config = {
        .queue_size = 10,
        .item_size = sizeof(int)
    };
    
    os_queue_handle_t queue_handle;
    result = os_queue_create(&queue_config, &queue_handle);
    
    if (result == OS_OK) {
        printf("  Queue created successfully\n");
        
        /* 发送数据到队列 */
        int send_data = 42;
        result = os_queue_send(queue_handle, &send_data, 1000);
        if (result == OS_OK) {
            printf("  Data sent to queue: %d\n", send_data);
        } else {
            printf("  Failed to send data to queue: error %d\n", result);
        }
        
        /* 从队列接收数据 */
        int recv_data;
        result = os_queue_receive(queue_handle, &recv_data, 1000);
        if (result == OS_OK) {
            printf("  Data received from queue: %d\n", recv_data);
        } else {
            printf("  Failed to receive data from queue: error %d\n", result);
        }
        
        /* 删除队列 */
        result = os_queue_delete(queue_handle);
        if (result == OS_OK) {
            printf("  Queue deleted successfully\n");
        } else {
            printf("  Failed to delete queue: error %d\n", result);
        }
    } else {
        printf("  Failed to create queue: error %d\n", result);
    }
    
    printf("\n");
    
    /* 测试8: 定时器 */
    printf("Test 8: Timer\n");
    printf("-------------\n");
    
    os_timer_config_t timer_config = {
        .name = "TestTimer",
        .callback = test_timer_callback,
        .argument = NULL,
        .period_ms = 500,  /* 500ms周期 */
        .auto_reload = true,
        .start_immediately = true
    };
    
    os_timer_handle_t timer_handle;
    result = os_timer_create(&timer_config, &timer_handle);
    
    if (result == OS_OK) {
        printf("  Timer created and started successfully\n");
        printf("  Timer will run for 3 cycles (1.5 seconds)\n");
        
        /* 等待定时器完成 */
        os_delay_ms(2000);
        
        /* 删除定时器 */
        result = os_timer_delete(timer_handle);
        if (result == OS_OK) {
            printf("  Timer deleted successfully\n");
        } else {
            printf("  Failed to delete timer: error %d\n", result);
        }
    } else {
        printf("  Failed to create timer: error %d\n", result);
    }
    
    printf("\n");
    printf("=== All Tests Completed ===\n");
    
    return 0;
}