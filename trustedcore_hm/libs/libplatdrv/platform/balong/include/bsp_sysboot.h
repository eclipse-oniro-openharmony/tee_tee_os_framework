/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 */

#ifndef __BSP_SYSBOOT_H__
#define __BSP_SYSBOOT_H__

#include <bsp_modem_product_config.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * @brief 获取tsp启动参数需要注册的回调函数格式
 */
typedef int (*parse_para_cb)(const char *value);

/**
 * @brief 启动参数名字最大长度
 */
#define SYSBOOT_PARA_NAME_LEN 32

/**
 * @brief 启动参数回调函数名字
 */
#define SYSBOOT_PARA_FUNC_NAME_LEN 40

/**
 * @brief 启动参数解析结构信息
 */
struct sysboot_parse_para_info
{
    const char  name[SYSBOOT_PARA_NAME_LEN]; /**<启动参数名字，长度不超过31个字符,应与添加方的添加启动参数名字匹配 */
    parse_para_cb init_fun;      /**<获取启动参数回调函数 */
    int result; /**<获取启动参数回调函数执行结果，默认值为0x5a5a5a5a */
};

#ifdef CONFIG_SYSBOOT_PARA_DEBUG
extern int parse_secureos_debug(const char *p);
#endif

/*
 * 增加的启动参数解析回调函数在g_sysboot_parse_para_info结构体中追加
 */
struct sysboot_parse_para_info g_sysboot_parse_para_info[] = {
#ifdef CONFIG_SYSBOOT_PARA_DEBUG
    {"secure_os_test_debug", parse_secureos_debug, 0x5a5a5a5a},
#endif
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif

