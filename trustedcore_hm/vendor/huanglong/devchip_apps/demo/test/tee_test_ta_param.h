/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee test TA code for invoke param test
 * Author: Hisilicon
 * Created: 2020-04-16
 */

#ifndef _TEE_TEST_TA_PARAM_H
#define _TEE_TEST_TA_PARAM_H

#include "tee_internal_api.h"

#ifdef __cplusplus
#if __cplusplus
extern "C"
{
#endif /* __cplusplus */
#endif /* __cplusplus */

/* here these define must be same as the define in test CA */
#define TEE_TEST_VALUE_FROM_REE     0x12345678
#define TEE_TEST_VALUE_TO_REE       0x87654321

#define TEE_TEST_MEM_SIZE           128
#define TEE_TEST_STR_FROM_REE       "this is the test string from ree"
#define TEE_TEST_STR_TO_REE         "this is the test string from TEE"

TEE_Result ta_test_params_value(unsigned int param_types, TEE_Param params[4]);  /* 4 params */
TEE_Result ta_test_params_memref(unsigned int param_types, TEE_Param params[4]); /* 4 params */
TEE_Result ta_test_params_expand(unsigned int param_types, TEE_Param params[4]); /* 4 params */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* _TEE_TEST_TA_PARAM_H */

