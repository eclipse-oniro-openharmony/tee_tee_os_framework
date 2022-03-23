/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: secflash operation config
 * Author: hemuyang1@huawei.com
 * Create: 2021-11-25
 */
#ifndef SEC_FLASH_CONFIG_H
#define SEC_FLASH_CONFIG_H

#include <ta_framework.h>
#include <sre_access_control.h>
#include "product_uuid_public.h"

static const struct ta_permission g_secflash_permission_config[] = {
    { TEE_SERVICE_SSA,            0, SECFLASH_GENERIC_PERMISSION | SECFLASH_SPECIFIC_PERMISSION },
#ifdef DEF_ENG
    { TEE_SERVICE_DEMO,           0, SECFLASH_GENERIC_PERMISSION },
    { TEE_SERVICE_ECHO,           0, SECFLASH_GENERIC_PERMISSION | SECFLASH_SPECIFIC_PERMISSION },
    { TEE_SERVICE_UT,             0, SECFLASH_GENERIC_PERMISSION | SECFLASH_SPECIFIC_PERMISSION },
    { TEE_SERVICE_TEST_API,       0, SECFLASH_GENERIC_PERMISSION | SECFLASH_SPECIFIC_PERMISSION },
    { TEE_SERVICE_KERNELMEMUSAGE, 0, SECFLASH_GENERIC_PERMISSION | SECFLASH_SPECIFIC_PERMISSION },
#endif
};

static const uint32_t g_secflash_permission_number = sizeof(g_secflash_permission_config) /
    sizeof(g_secflash_permission_config[0]);

#define SECFLASH_THRESHOLD_SIZE (40U * 1024U)
#define UT_THRESHOLD_SIZE 0x100000U
#define TEST_API_THRESHOLD_SIZE (32U * 1024U)
static const struct ta_sec_fs_threshold g_ta_secflash_threshold_config[] = {
    { TEE_SERVICE_SSA,             SECFLASH_THRESHOLD_SIZE },
/* DO NOT EDIT */
#ifdef DEF_ENG
    { TEE_SERVICE_UT,              UT_THRESHOLD_SIZE },
    { TEE_SERVICE_TEST_API,        TEST_API_THRESHOLD_SIZE },
    { TEE_SERVICE_KERNELMEMUSAGE,  UT_THRESHOLD_SIZE },
#endif
};
static const uint32_t g_secflash_ta_number = sizeof(g_ta_secflash_threshold_config) /
    sizeof(g_ta_secflash_threshold_config[0]);

#endif
