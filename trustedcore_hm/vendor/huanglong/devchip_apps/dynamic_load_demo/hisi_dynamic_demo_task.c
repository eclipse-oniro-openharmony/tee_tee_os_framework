/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: TA demo
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#include "hi_tee_hal.h"

#define HISI_DEMO_CMD_HELLO         0

TEE_Result TA_CreateEntryPoint(void)
{
    return AddCaller_CA_exec((char *)"default", 0);
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4], void **sessionContext) /* 4, param num */
{
    (void)paramTypes;
    (void)params;
    (void)sessionContext;
    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
                                      uint32_t paramTypes, TEE_Param params[4]) /* 4, param num */
{
    TEE_Result ret;
    int data = 0x234;
    char buf[256] = "hisilicon ioctl test!"; /* test buffer max size 256 */

    (void)paramTypes;
    (void)sessionContext;

    switch (commandID) {
        case HISI_DEMO_CMD_HELLO: {
            hi_tee_printf("TA DEMO, Hello, Secure World! \n");
            hi_tee_printf("TA DEMO, params[3].value.a = 0x%x, params[3].value.b = 0x%x \n",
                          params[3].value.a, params[3].value.b); /* 3, 4th param */
            params[3].value.a = 0x12345678;  /* 0x12345678, test data */
            params[3].value.b = 0x87654321;  /* 0x87654321, test data */
            ret = TEE_SUCCESS;
            break;
        }
        default:
            tloge("Invalid command!\n");
            break;
    }

    if (ret == TEE_SUCCESS) {
        tloge("TA DEMO, Invoke command[0x%x] suc\n", commandID);
    } else {
        tloge("Invoke command[0x%x] failed, ret[0x%x]\n", commandID, ret);
    }

    return  ret;
}

void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;
}

void TA_DestroyEntryPoint(void)
{
}

