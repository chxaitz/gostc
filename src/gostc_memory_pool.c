/**
 * @file    gostc_memory_pool.c
 * @brief   通信代理内存池管理模块实现
 * @author  Kilo Code
 * @date    2026-03-07
 * @version 1.0.0
 * 
 * @note    提供固定大小的内存块分配，减少内存碎片
 * @warning 内存池大小在初始化时确定，无法动态调整
 */

#include "gostc_err.h"
#include "gostc_os.h"
#include <string.h>

/* 内存块结构体 */
typedef struct memory_block {
    struct memory_block *next;      /* 下一个空闲块 */
    uint8_t data[];                 /* 数据区域（柔性数组） */
} memory_block_t;

/* 内存池结构体 */
typedef struct {
    char name[16];                  /* 内存池名称 */
    uint32_t block_size;            /* 块大小（字节） */
    uint32_t block_count;           /* 块数量 */
    uint32_t free_count;            /* 空闲块数量 */
    uint32_t used_count;            /* 已用块数量 */
    
    uint8_t *memory_buffer;         /* 内存缓冲区 */
    memory_block_t *free_list;      /* 空闲块链表 */
    
    os_mutex_handle_t mutex;        /* 互斥锁 */
    bool initialized;               /* 初始化标志 */
} memory_pool_t;

/* 模块内部全局变量 */
static memory_pool_t g_memory_pools[4]; /* 支持最多4个内存池 */
static uint8_t g_pool_count = 0;        /* 已创建的内存池数量 */

/* 内部函数声明 */
static memory_pool_t *_find_pool_by_name(const char *name);
static int32_t _pool_validate_params(const char *name, uint32_t block_size, uint32_t block_count);
static void _pool_init_blocks(memory_pool_t *pool);

/* 内部函数实现 */

/**
 * @brief   通过名称查找内存池
 */
static memory_pool_t *_find_pool_by_name(const char *name)
{
    for (uint8_t i = 0; i < g_pool_count; i++) {
        if (strcmp(g_memory_pools[i].name, name) == 0) {
            return &g_memory_pools[i];
        }
    }
    return NULL;
}

/**
 * @brief   验证内存池参数
 */
static int32_t _pool_validate_params(const char *name, uint32_t block_size, uint32_t block_count)
{
    if (name == NULL || strlen(name) == 0 || strlen(name) >= 16) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    if (block_size == 0 || block_size > 65536) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    if (block_count == 0 || block_count > 1024) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 检查是否已存在同名内存池 */
    if (_find_pool_by_name(name) != NULL) {
        return GOSTC_ERROR_ALREADY_INITIALIZED;
    }
    
    /* 检查是否还有空闲的内存池槽位 */
    if (g_pool_count >= sizeof(g_memory_pools) / sizeof(g_memory_pools[0])) {
        return GOSTC_ERROR_NO_MEMORY;
    }
    
    return GOSTC_OK;
}

/**
 * @brief   初始化内存块链表
 */
static void _pool_init_blocks(memory_pool_t *pool)
{
    GOSTC_ASSERT(pool != NULL);
    
    /* 计算每个块的总大小（包括块头） */
    size_t block_total_size = sizeof(memory_block_t) + pool->block_size;
    
    /* 初始化空闲链表 */
    pool->free_list = NULL;
    
    /* 将缓冲区划分为块并加入空闲链表 */
    for (uint32_t i = 0; i < pool->block_count; i++) {
        memory_block_t *block = (memory_block_t *)(pool->memory_buffer + i * block_total_size);
        block->next = pool->free_list;
        pool->free_list = block;
    }
    
    pool->free_count = pool->block_count;
    pool->used_count = 0;
}

/* 公共函数实现 */

int32_t gostc_memory_pool_create(const char *name, uint32_t block_size, uint32_t block_count, 
                                uint8_t *buffer)
{
    /* 验证参数 */
    int32_t ret = _pool_validate_params(name, block_size, block_count);
    if (ret != GOSTC_OK) {
        return ret;
    }
    
    /* 获取内存池指针 */
    memory_pool_t *pool = &g_memory_pools[g_pool_count];
    
    /* 初始化内存池结构 */
    memset(pool, 0, sizeof(memory_pool_t));
    strncpy(pool->name, name, sizeof(pool->name) - 1);
    pool->name[sizeof(pool->name) - 1] = '\0';
    
    pool->block_size = block_size;
    pool->block_count = block_count;
    
    /* 分配内存缓冲区 */
    if (buffer != NULL) {
        /* 使用提供的缓冲区 */
        pool->memory_buffer = buffer;
    } else {
        /* 动态分配内存 */
        size_t block_total_size = sizeof(memory_block_t) + block_size;
        size_t total_size = block_total_size * block_count;
        
        pool->memory_buffer = (uint8_t *)os_malloc(total_size);
        if (pool->memory_buffer == NULL) {
            return GOSTC_ERROR_NO_MEMORY;
        }
        
        /* 清零缓冲区 */
        memset(pool->memory_buffer, 0, total_size);
    }
    
    /* 创建互斥锁 */
    os_error_e os_err = os_mutex_create(&pool->mutex);
    if (os_err != OS_OK) {
        if (buffer == NULL) {
            os_free(pool->memory_buffer);
        }
        return GOSTC_ERROR_OS_MUTEX_CREATE_FAILED;
    }
    
    /* 初始化内存块 */
    _pool_init_blocks(pool);
    
    pool->initialized = true;
    g_pool_count++;
    
    return GOSTC_OK;
}

int32_t gostc_memory_pool_destroy(const char *name)
{
    if (name == NULL) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 查找内存池 */
    memory_pool_t *pool = _find_pool_by_name(name);
    if (pool == NULL) {
        return GOSTC_ERROR_CONN_NOT_FOUND;
    }
    
    if (!pool->initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* 检查是否还有已分配的内存块 */
    if (pool->used_count > 0) {
        return GOSTC_ERROR_BUSY;
    }
    
    /* 删除互斥锁 */
    if (pool->mutex != NULL) {
        os_mutex_delete(pool->mutex);
        pool->mutex = NULL;
    }
    
    /* 释放内存缓冲区（如果是动态分配的） */
    /* 注意：我们不知道缓冲区是否是动态分配的，所以由调用者负责释放 */
    
    /* 重置内存池 */
    memset(pool, 0, sizeof(memory_pool_t));
    
    /* 重新排列内存池数组 */
    for (uint8_t i = 0; i < g_pool_count - 1; i++) {
        if (strlen(g_memory_pools[i].name) == 0) {
            /* 找到空槽，用后面的内存池填充 */
            memcpy(&g_memory_pools[i], &g_memory_pools[i + 1], sizeof(memory_pool_t));
            memset(&g_memory_pools[i + 1], 0, sizeof(memory_pool_t));
        }
    }
    
    g_pool_count--;
    
    return GOSTC_OK;
}

void *gostc_memory_pool_alloc(const char *name, uint32_t timeout_ms)
{
    if (name == NULL) {
        return NULL;
    }
    
    /* 查找内存池 */
    memory_pool_t *pool = _find_pool_by_name(name);
    if (pool == NULL) {
        return NULL;
    }
    
    if (!pool->initialized) {
        return NULL;
    }
    
    /* 获取互斥锁 */
    os_error_e os_err = os_mutex_lock(pool->mutex, timeout_ms);
    if (os_err != OS_OK) {
        return NULL;
    }
    
    /* 检查是否有空闲块 */
    if (pool->free_list == NULL) {
        os_mutex_unlock(pool->mutex);
        return NULL;
    }
    
    /* 分配一个块 */
    memory_block_t *block = pool->free_list;
    pool->free_list = block->next;
    
    pool->free_count--;
    pool->used_count++;
    
    os_mutex_unlock(pool->mutex);
    
    /* 返回数据区域指针 */
    return block->data;
}

int32_t gostc_memory_pool_free(const char *name, void *ptr)
{
    if (name == NULL || ptr == NULL) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 查找内存池 */
    memory_pool_t *pool = _find_pool_by_name(name);
    if (pool == NULL) {
        return GOSTC_ERROR_CONN_NOT_FOUND;
    }
    
    if (!pool->initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* 计算块头指针 */
    memory_block_t *block = (memory_block_t *)((uint8_t *)ptr - sizeof(memory_block_t));
    
    /* 验证指针是否在内存池范围内 */
    size_t block_total_size = sizeof(memory_block_t) + pool->block_size;
    uint8_t *pool_start = pool->memory_buffer;
    uint8_t *pool_end = pool_start + block_total_size * pool->block_count;
    
    if ((uint8_t *)block < pool_start || (uint8_t *)block >= pool_end) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 检查对齐 */
    if ((((uintptr_t)block - (uintptr_t)pool_start) % block_total_size) != 0) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 获取互斥锁 */
    os_error_e os_err = os_mutex_lock(pool->mutex, OS_WAIT_FOREVER);
    if (os_err != OS_OK) {
        return GOSTC_ERROR_OS;
    }
    
    /* 将块加入空闲链表 */
    block->next = pool->free_list;
    pool->free_list = block;
    
    pool->free_count++;
    pool->used_count--;
    
    os_mutex_unlock(pool->mutex);
    
    return GOSTC_OK;
}

int32_t gostc_memory_pool_get_stats(const char *name, uint32_t *block_size, 
                                   uint32_t *block_count, uint32_t *free_count, 
                                   uint32_t *used_count)
{
    if (name == NULL) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 查找内存池 */
    memory_pool_t *pool = _find_pool_by_name(name);
    if (pool == NULL) {
        return GOSTC_ERROR_CONN_NOT_FOUND;
    }
    
    if (!pool->initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* 获取互斥锁 */
    os_error_e os_err = os_mutex_lock(pool->mutex, OS_WAIT_FOREVER);
    if (os_err != OS_OK) {
        return GOSTC_ERROR_OS;
    }
    
    if (block_size != NULL) {
        *block_size = pool->block_size;
    }
    
    if (block_count != NULL) {
        *block_count = pool->block_count;
    }
    
    if (free_count != NULL) {
        *free_count = pool->free_count;
    }
    
    if (used_count != NULL) {
        *used_count = pool->used_count;
    }
    
    os_mutex_unlock(pool->mutex);
    
    return GOSTC_OK;
}

int32_t gostc_memory_pool_reset(const char *name)
{
    if (name == NULL) {
        return GOSTC_ERROR_INVALID_PARAM;
    }
    
    /* 查找内存池 */
    memory_pool_t *pool = _find_pool_by_name(name);
    if (pool == NULL) {
        return GOSTC_ERROR_CONN_NOT_FOUND;
    }
    
    if (!pool->initialized) {
        return GOSTC_ERROR_NOT_INITIALIZED;
    }
    
    /* 获取互斥锁 */
    os_error_e os_err = os_mutex_lock(pool->mutex, OS_WAIT_FOREVER);
    if (os_err != OS_OK) {
        return GOSTC_ERROR_OS;
    }
    
    /* 重新初始化内存块 */
    _pool_init_blocks(pool);
    
    os_mutex_unlock(pool->mutex);
    
    return GOSTC_OK;
}

int32_t gostc_memory_pool_get_total_stats(uint32_t *total_pools, uint32_t *total_blocks,
                                         uint32_t *total_free, uint32_t *total_used)
{
    uint32_t pools = 0;
    uint32_t blocks = 0;
    uint32_t free = 0;
    uint32_t used = 0;
    
    for (uint8_t i = 0; i < g_pool_count; i++) {
        memory_pool_t *pool = &g_memory_pools[i];
        
        if (!pool->initialized) {
            continue;
        }
        
        os_error_e os_err = os_mutex_lock(pool->mutex, OS_WAIT_FOREVER);
        if (os_err != OS_OK) {
            continue;
        }
        
        pools++;
        blocks += pool->block_count;
        free += pool->free_count;
        used += pool->used_count;
        
        os_mutex_unlock(pool->mutex);
    }
    
    if (total_pools != NULL) {
        *total_pools = pools;
    }
    
    if (total_blocks != NULL) {
        *total_blocks = blocks;
    }
    
    if (total_free != NULL) {
        *total_free = free;
    }
    
    if (total_used != NULL) {
        *total_used = used;
    }
    
    return GOSTC_OK;
}

int32_t gostc_memory_pool_destroy_all(void)
{
    int32_t ret = GOSTC_OK;
    
    for (uint8_t i = 0; i < g_pool_count; i++) {
        memory_pool_t *pool = &g_memory_pools[i];
        
        if (!pool->initialized) {
            continue;
        }
        
        /* 检查是否还有已分配的内存块 */
        if (pool->used_count > 0) {
            ret = GOSTC_ERROR_BUSY;
            continue;
        }
        
        /* 删除互斥锁 */
        if (pool->mutex != NULL) {
            os_mutex_delete(pool->mutex);
            pool->mutex = NULL;
        }
        
        /* 重置内存池 */
        memset(pool, 0, sizeof(memory_pool_t));
    }
    
    g_pool_count = 0;
    
    return ret;
}