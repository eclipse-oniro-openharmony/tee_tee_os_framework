/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: TA demo
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#include "tee_log.h"
#include "hi_tee_demo.h"
#include "hi_tee_hal.h"
#include "tee_test_ta.h"

#define HISI_DEMO_CMD_HELLO         0
#define HISI_DEMO_CMD_SYSCALL       1
#define HISI_DEMO_CMD_IOCTL         2

__DEFAULT TEE_Result TA_CreateEntryPoint(void)
{
    return AddCaller_CA_exec((char *)"default", 0);
}

__DEFAULT TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4],  /* 4, param num */
                                              void **sessionContext)
{
    (void)paramTypes;
    (void)params;
    (void)sessionContext;
    return TEE_SUCCESS;
}

__DEFAULT TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
                                                uint32_t paramTypes, TEE_Param params[4]) /* 4, param num */
{
    TEE_Result ret;
    int data = 0x234;
    char buf[256] = "hisilicon ioctl test!"; /* test buffer max size is 256 */

    (void)sessionContext;

    switch (commandID) {
        case HISI_DEMO_CMD_HELLO:
            hi_tee_printf("TA DEMO, Hello, Secure World! \n");
            ret = TEE_SUCCESS;
            break;
        case HISI_DEMO_CMD_SYSCALL:
            ret = hi_tee_demo_hello(params[3].value.a, &data); /* param 3 */
            if (ret != 0) {
                hi_tee_printf("[TA DEMO][ERROR], cmd[0x%X], ret[0x%X], data(0x1234) = 0x%X\n", commandID, ret, data);
            }
            break;
        case HISI_DEMO_CMD_IOCTL:
            ret = hi_tee_demo_ioctl(params[3].value.a, buf, sizeof(buf)); /* param 3 */
            if (ret != 0) {
                hi_tee_printf("[TA DEMO][ERROR], cmd[0x%X], ret[0x%X], buf: %s\n", commandID, ret, buf);
            }
            break;
        default:
            ret = tee_test_main(commandID, paramTypes, params);
            break;
    }

    if (ret == TEE_SUCCESS) {
        hi_tee_printf("[TA DEMO] Invoke command[0x%x] suc\n", commandID);
    }

    return ret;
}

__DEFAULT void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;
}

__DEFAULT void TA_DestroyEntryPoint(void)
{
}
