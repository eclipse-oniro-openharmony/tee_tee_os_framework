/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee test ta code
 * Author: Hisilicon
 * Create: 2020-04-16
 */

#ifndef __TEE_TEST_TA_H
#define __TEE_TEST_TA_H

#include "hi_tee_hal.h"

#ifdef __cplusplus
#if __cplusplus
extern "C"
{
#endif /* __cplusplus */
#endif /* __cplusplus */

/* test cmd for invoke, the 0 ~ 2 is for demo */
enum tee_test_cmd {
    TEE_TEST_CMD_PARAMS_VALUE = 3,
    TEE_TEST_CMD_PARAMS_TMPREF,
    TEE_TEST_CMD_PARAMS_MEMREF,
    TEE_TEST_CMD_PARAMS_MEM_HAND,
    TEE_TEST_CMD_MEM_API,
    TEE_TEST_CMD_STORAGE,
    TEE_TEST_CMD_TIME,
    TEE_TEST_CMD_DRV_HAL,
};

TEE_Result tee_test_main(unsigned int cmd, unsigned int param_types, TEE_Param params[4]); /* 4 params */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif    /* #ifndef __TEE_TEST_TA_H */
