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
 * @brief ��ȡtsp����������Ҫע��Ļص�������ʽ
 */
typedef int (*parse_para_cb)(const char *value);

/**
 * @brief ��������������󳤶�
 */
#define SYSBOOT_PARA_NAME_LEN 32

/**
 * @brief ���������ص���������
 */
#define SYSBOOT_PARA_FUNC_NAME_LEN 40

/**
 * @brief �������������ṹ��Ϣ
 */
struct sysboot_parse_para_info
{
    const char  name[SYSBOOT_PARA_NAME_LEN]; /**<�����������֣����Ȳ�����31���ַ�,Ӧ����ӷ������������������ƥ�� */
    parse_para_cb init_fun;      /**<��ȡ���������ص����� */
    int result; /**<��ȡ���������ص�����ִ�н����Ĭ��ֵΪ0x5a5a5a5a */
};

#ifdef CONFIG_SYSBOOT_PARA_DEBUG
extern int parse_secureos_debug(const char *p);
#endif

/*
 * ���ӵ��������������ص�������g_sysboot_parse_para_info�ṹ����׷��
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

