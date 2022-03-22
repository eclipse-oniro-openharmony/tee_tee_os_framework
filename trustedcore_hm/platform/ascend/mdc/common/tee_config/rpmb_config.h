/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: rpmb operation config
 * Author: pengshuai@huawei.com
 * Create: 2020-02-13
 */
#ifndef RPMB_CONFIG_H
#define RPMB_CONFIG_H

#include <tee_config.h>
#include <product_uuid.h>
#include "product_uuid_public.h"
#include <sre_access_control.h>

static const struct ta_permission g_rpmb_permission_config[] = {
    { TEE_SERVICE_RPMB,           0, RPMB_GENERIC_PERMISSION | RPMB_SPECIFIC_PERMISSION },
#ifdef DEF_ENG
    { TEE_SERVICE_DEMO,      0, RPMB_GENERIC_PERMISSION },
    { TEE_SERVICE_ECHO,           0, RPMB_GENERIC_PERMISSION | RPMB_SPECIFIC_PERMISSION },
    { TEE_SERVICE_UT,             0, RPMB_GENERIC_PERMISSION | RPMB_SPECIFIC_PERMISSION },
    { TEE_SERVICE_TEST_API,       0, RPMB_GENERIC_PERMISSION | RPMB_SPECIFIC_PERMISSION },
    { TEE_SERVICE_KERNELMEMUSAGE, 0, RPMB_GENERIC_PERMISSION | RPMB_SPECIFIC_PERMISSION },
#endif
#ifdef TEE_SUPPORT_HSM
    { TEE_SERVICE_HSM_RPMBKEY,    0, RPMB_GENERIC_PERMISSION | RPMB_SPECIFIC_PERMISSION },
#endif
};

static const uint32_t g_rpmb_permission_number = sizeof(g_rpmb_permission_config) / sizeof(g_rpmb_permission_config[0]);

#define RPMB_THRESHOLD_SIZE (40U * 1024U)
#define UT_THRESHOLD_SIZE 0x100000U
#define TEST_API_THRESHOLD_SIZE (32U * 1024U)
#define HSM_RPMB_KEY_THRESHOLD_SIZE (2U * 1024U)
static const struct ta_sec_fs_threshold g_ta_rpmb_threshold_config[] = {
    { TEE_SERVICE_RPMB, RPMB_THRESHOLD_SIZE },
/* DO NOT EDIT */
#ifdef DEF_ENG
    { TEE_SERVICE_UT,              UT_THRESHOLD_SIZE },
    { TEE_SERVICE_TEST_API,        TEST_API_THRESHOLD_SIZE },
    { TEE_SERVICE_KERNELMEMUSAGE,  UT_THRESHOLD_SIZE },
#endif
#ifdef TEE_SUPPORT_HSM
    { TEE_SERVICE_HSM_RPMBKEY, HSM_RPMB_KEY_THRESHOLD_SIZE },
#endif
};
static const uint32_t g_rpmb_ta_number = sizeof(g_ta_rpmb_threshold_config) / sizeof(g_ta_rpmb_threshold_config[0]);

#endif
