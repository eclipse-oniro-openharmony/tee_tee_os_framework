/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: test ta code for gp mem api
 * Author: Hisilicon
 * Created: 2020-04-17
 */

#ifndef _TEE_TEST_TA_MEM_API_H
#define _TEE_TEST_TA_MEM_API_H

#include "tee_internal_api.h"

#ifdef __cplusplus
#if __cplusplus
extern "C"
{
#endif /* __cplusplus */
#endif /* __cplusplus */

enum tee_test_cmd_mem_api {
    TEE_MEM_API_CMD_ALLOC_FREE = 0x100,
    TEE_MEM_API_CMD_FILL,
    TEE_MEM_API_CMD_MOVE,
    TEE_MEM_API_CMD_CMP,
};

TEE_Result ta_test_mem_api(unsigned int cmd, unsigned int size);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* _TEE_TEST_TA_MEM_API_H */

