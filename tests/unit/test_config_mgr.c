/**
 * @file    test_config_mgr.c
 * @brief   配置管理模块单元测试
 * @author  Kilo Code
 * @date    2026-03-07
 * @version 1.0.0
 */

#include "gostc_cfg.h"
#include "gostc_err.h"
#include <stdio.h>
#include <string.h>

/* 测试用例函数 */
static int test_config_init_deinit(void)
{
    printf("测试: 配置管理初始化和反初始化\n");
    
    int32_t ret = gostc_config_init();
    if (ret != GOSTC_OK) {
        printf("  失败: gostc_config_init 返回 %d\n", ret);
        return -1;
    }
    
    ret = gostc_config_deinit();
    if (ret != GOSTC_OK) {
        printf("  失败: gostc_config_deinit 返回 %d\n", ret);
        return -1;
    }
    
    printf("  通过\n");
    return 0;
}

static int test_config_load_default(void)
{
    printf("测试: 加载默认配置\n");
    
    int32_t ret = gostc_config_init();
    if (ret != GOSTC_OK) {
        printf("  失败: 初始化失败\n");
        return -1;
    }
    
    gostc_config_t config;
    ret = gostc_config_load_default(&config);
    if (ret != GOSTC_OK) {
        printf("  失败: gostc_config_load_default 返回 %d\n", ret);
        gostc_config_deinit();
        return -1;
    }
    
    /* 验证默认配置 */
    if (config.version != CONFIG_VERSION_1_0) {
        printf("  失败: 版本号不正确\n");
        gostc_config_deinit();
        return -1;
    }
    
    if (config.magic != CONFIG_MAGIC) {
        printf("  失败: 魔数不正确\n");
        gostc_config_deinit();
        return -1;
    }
    
    gostc_config_deinit();
    printf("  通过\n");
    return 0;
}

static int test_config_validate(void)
{
    printf("测试: 配置验证\n");
    
    int32_t ret = gostc_config_init();
    if (ret != GOSTC_OK) {
        printf("  失败: 初始化失败\n");
        return -1;
    }
    
    gostc_config_t config;
    ret = gostc_config_load_default(&config);
    if (ret != GOSTC_OK) {
        printf("  失败: 加载默认配置失败\n");
        gostc_config_deinit();
        return -1;
    }
    
    /* 验证有效配置 */
    ret = gostc_config_validate(&config);
    if (ret != GOSTC_OK) {
        printf("  失败: 有效配置验证失败: %d\n", ret);
        gostc_config_deinit();
        return -1;
    }
    
    /* 测试无效配置 */
    gostc_config_t invalid_config = config;
    invalid_config.version = 0xFFFFFFFF; /* 无效版本 */
    
    ret = gostc_config_validate(&invalid_config);
    if (ret == GOSTC_OK) {
        printf("  失败: 无效配置验证通过\n");
        gostc_config_deinit();
        return -1;
    }
    
    gostc_config_deinit();
    printf("  通过\n");
    return 0;
}

/* 主测试函数 */
int main(void)
{
    printf("=== 配置管理模块单元测试 ===\n\n");
    
    int passed = 0;
    int total = 0;
    
    /* 运行测试用例 */
    if (test_config_init_deinit() == 0) passed++;
    total++;
    
    if (test_config_load_default() == 0) passed++;
    total++;
    
    if (test_config_validate() == 0) passed++;
    total++;
    
    printf("\n=== 测试结果 ===\n");
    printf("通过: %d/%d\n", passed, total);
    
    return (passed == total) ? 0 : 1;
}