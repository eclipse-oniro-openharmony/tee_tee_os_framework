/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: symbles export for use
 * Author: w00414120 wangzhuochen1@huawei.com
 * Create: 2020-03-20
 */
#include <stdbool.h>
#include <stdint.h>

#define SE_CRYPTO_SUPPORT     0x1U
#define SE_CRYPTO_NOT_SUPPORT 0x0U
#define SKYTONE_VERSION         10000U

uint32_t TEE_inSE_support()
{
#ifdef FEATURE_SE_CRYPTO
    return SE_CRYPTO_SUPPORT;
#else
    return SE_CRYPTO_NOT_SUPPORT;
#endif
}

uint32_t TEE_EXT_Get_Skytone_Version()
{
    return SKYTONE_VERSION;
}