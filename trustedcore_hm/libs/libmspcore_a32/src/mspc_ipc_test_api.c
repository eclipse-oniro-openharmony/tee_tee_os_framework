/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Driver for mspc cc certifivation
 * Author : z00452790
 * Create: 2020/06/09
 */
#ifdef CONFIG_HISI_MSPC_IPC_TEST
#include "mspc_ipc_test_api.h"
#include "msp_service_status.h"
#include "sre_syscalls_ext.h"
#include "hisi_mspc_ipc_test.h"

#define MSPC_OK              0x5A5A
#define MSPC_ERROR           0xA5A5

TEE_Result TEE_EXT_MspcIpcTest(struct mspc_ipc_test_msg *msg)
{
    int32_t ret;

    ret = __mspc_ipc_test((uint8_t *)msg, sizeof(struct mspc_ipc_test_msg));
    if (ret != MSPC_OK) {
        tloge("%s ipc test fail\n", ret);
        return TEE_ERROR_COMMUNICATION;
    }

    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_MspcDdrRead(uint32_t addr, uint32_t len, uint8_t *buff, uint32_t *buffLen)
{
    int32_t ret;

    ret = __mspc_ddr_read(addr, len, buff, buffLen);
    if (ret != MSPC_OK) {
        tloge("%s ddr read fail\n", ret);
        return TEE_ERROR_COMMUNICATION;
    }

    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_MspcDdrWrite(uint8_t *buff, uint32_t buffLen, uint32_t addr)
{
    int32_t ret;

    ret = __mspc_ddr_write(buff, buffLen, addr);
    if (ret != MSPC_OK) {
        tloge("%s ddr write fail\n", ret);
        return TEE_ERROR_COMMUNICATION;
    }

    return TEE_SUCCESS;
}
#endif
