/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: test ta code for gp mem api
 * Author: Hisilicon
 * Created: 2020-04-17
 */

#include "tee_test_ta_mem_api.h"
#include "tee_log.h"

static TEE_Result ta_test_mem_api_all(unsigned int cmd, unsigned int size)
{
    char *buf = NULL;
    char test_str[32] = "this is a test string"; /* test str max length is 32 */
    TEE_Result ret = TEE_SUCCESS;

    buf = TEE_Malloc(size, 0); /* clean befor return */
    if (buf == NULL) {
        tloge("TEE_Malloc failed!\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (cmd == TEE_MEM_API_CMD_ALLOC_FREE) {
        goto out;
    }

    TEE_MemFill(buf, 1, size);
    if (cmd == TEE_MEM_API_CMD_FILL) {
        if (buf[size / 2] != 1) { /* Divide by 2, get the middle data */
            tloge("TEE_MemFill failed!\n");
            ret = TEE_ERROR_GENERIC;
        }
        goto out;
    }

    TEE_MemFill(buf, 0, size);
    TEE_MemMove(buf, test_str, strlen(test_str));
    if (cmd == TEE_MEM_API_CMD_MOVE) {
        if (strcmp(buf, test_str)) {
            tloge("TEE_MemMove failed!\n");
            ret = TEE_ERROR_GENERIC;
        }
        goto out;
    }

    if (TEE_MemCompare(buf, test_str, strlen(test_str))) {
        tloge("TEE_MemCompare failed!\n");
        ret = TEE_ERROR_GENERIC;
    }

out:
    TEE_Free(buf);
    return ret;
}

TEE_Result ta_test_mem_api(unsigned int cmd, unsigned int size)
{
    TEE_Result ret;

    switch (cmd) {
        case TEE_MEM_API_CMD_ALLOC_FREE:
        case TEE_MEM_API_CMD_FILL:
        case TEE_MEM_API_CMD_MOVE:
        case TEE_MEM_API_CMD_CMP:
            ret = ta_test_mem_api_all(cmd, size);
            break;
        default:
            tloge("Invalud cmd[0x%X]\n", cmd);
            ret = TEE_ERROR_INVALID_CMD;
            break;
    }

    return ret;
}

