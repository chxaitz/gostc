/**
 * @file    test_dns_regex.c
 * @brief   DNS正则表达式功能测试
 * @author  mosser
 * @date    2026-03-08
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include "include/gostc_dns.h"
#include "include/gostc_log.h"
#include "include/gostc_os.h"

/* 测试函数 */
void test_regex_matching(void) {
    printf("\n=== 测试正则表达式匹配功能 ===\n");
    
    /* 测试数据：域名和正则表达式 */
    struct {
        const char *domain;
        const char *regex_pattern;
        int expected_match;  /* 0表示匹配，-1表示不匹配 */
    } test_cases[] = {
        /* 基本正则表达式测试 */
        {"www.example.com", "^www\\..*\\.com$", 0},
        {"www.example.com", "^www\\..*\\.net$", -1},
        {"test123.com", "^test[0-9]+\\.com$", 0},
        {"testabc.com", "^test[0-9]+\\.com$", -1},
        {"mail.google.com", "^.*\\.google\\.com$", 0},
        {"drive.google.com", "^.*\\.google\\.com$", 0},
        {"example.net", "^.*\\.google\\.com$", -1},
        
        /* 通配符风格的正则表达式 */
        {"*.example.com", "\\*\\..*\\.com", 0},  /* 注意：这里测试的是模式本身，不是匹配 */
    };
    
    /* 为每个测试用例单独测试 */
    printf("\n添加正则表达式规则...\n");
    for (int i = 0; i < sizeof(test_cases)/sizeof(test_cases[0]); i++) {
        /* 为每个测试用例单独初始化DNS过滤器 */
        gostc_dns_config_t config = {
            .default_action = DNS_ACTION_DENY,
            .enable_precompile = false
        };
        
        int32_t ret = gostc_dns_init(&config);
        if (ret != GOSTC_OK) {
            printf("测试用例 %d: DNS初始化失败: %d\n", i+1, ret);
            continue;
        }
        
        /* 添加当前测试用例的规则 */
        uint32_t rule_id = gostc_dns_add_rule(
            test_cases[i].regex_pattern,
            DNS_ACTION_ALLOW,
            DNS_RULE_REGEX
        );
        
        if (rule_id != 0) {
            printf("  规则 %d 添加成功: ID=%u, 模式='%s'\n", 
                   i+1, rule_id, test_cases[i].regex_pattern);
        } else {
            printf("  规则 %d 添加失败: 模式='%s'\n", 
                   i+1, test_cases[i].regex_pattern);
            gostc_dns_deinit();
            continue;
        }
        
        /* 测试域名匹配 */
        int32_t result = gostc_dns_query(test_cases[i].domain);
        
        printf("  域名 '%s' 匹配结果: %s (预期: %s)\n",
               test_cases[i].domain,
               (result == GOSTC_OK) ? "允许" : "拒绝",
               (test_cases[i].expected_match == 0) ? "允许" : "拒绝");
        
        if ((result == GOSTC_OK && test_cases[i].expected_match == 0) ||
            (result != GOSTC_OK && test_cases[i].expected_match != 0)) {
            printf("    ✓ 测试通过\n");
        } else {
            printf("    ✗ 测试失败\n");
        }
        
        /* 清理当前测试用例的环境 */
        gostc_dns_deinit();
    }
    
    printf("\nDNS过滤器反初始化完成\n");
}

void test_rule_parsing(void) {
    printf("\n=== 测试规则解析功能 ===\n");
    
    /* 测试规则文本 */
    const char *rule_text = 
        "# DNS白名单规则\n"
        "ALW,EXAC,www.baidu.com\n"
        "DEN,EXAC,www.malicious.com\n"
        "ALW,WILD,*.google.com\n"
        "ALW,REGX,^api\\..*\\.com$\n"
        "ALW,SUFF,.example.com\n"
        "# 注释行\n"
        "DEN,REGX,^.*\\.bad\\.com$\n";
    
    printf("规则文本:\n%s\n", rule_text);
    
    /* 初始化DNS过滤器 */
    gostc_dns_config_t config = {
        .default_action = DNS_ACTION_DENY,
        .enable_precompile = false
    };
    
    int32_t ret = gostc_dns_init(&config);
    if (ret != GOSTC_OK) {
        printf("DNS初始化失败: %d\n", ret);
        return;
    }
    
    /* 加载规则 */
    ret = gostc_dns_load_rules(rule_text);
    if (ret != GOSTC_OK) {
        printf("规则加载失败: %d\n", ret);
    } else {
        printf("规则加载成功\n");
    }
    
    /* 测试域名 */
    const char *test_domains[] = {
        "www.baidu.com",      /* 应该允许 */
        "www.malicious.com",  /* 应该拒绝 */
        "mail.google.com",    /* 应该允许（通配符） */
        "api.test.com",       /* 应该允许（正则） */
        "test.example.com",   /* 应该允许（后缀） */
        "evil.bad.com",       /* 应该拒绝（正则） */
        "unknown.com",        /* 应该拒绝（默认） */
    };
    
    printf("\n域名测试结果:\n");
    for (int i = 0; i < sizeof(test_domains)/sizeof(test_domains[0]); i++) {
        int32_t result = gostc_dns_query(test_domains[i]);
        printf("  %-20s: %s\n", test_domains[i], 
               (result == GOSTC_OK) ? "✓ 允许" : "✗ 拒绝");
    }
    
    /* 清理 */
    gostc_dns_deinit();
}

int main(void) {
    printf("DNS正则表达式功能测试程序\n");
    printf("========================\n");
    
    test_regex_matching();
    test_rule_parsing();
    
    printf("\n所有测试完成\n");
    return 0;
}