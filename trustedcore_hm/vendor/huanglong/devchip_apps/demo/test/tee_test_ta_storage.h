/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: TA test code for storage
 * Author: Hisilicon
 * Created: 2020-04-17
 */

#ifndef _TEE_TEST_TA_STORAGE_H
#define _TEE_TEST_TA_STORAGE_H

#include "tee_internal_api.h"

#ifdef __cplusplus
#if __cplusplus
extern "C"
{
#endif /* __cplusplus */
#endif /* __cplusplus */

#define TEE_TEST_STORAGE_OBJ_ID         "test_file.txt"
#define TEE_TEST_STORAGE_OBJ_IDX        "test_file_x.txt"

#define TEE_TEST_STORAGE_INIT_DATA      "1234567890"

enum tee_test_cmd_storage {
    TEE_STORAGE_CMD_CREAT = 0x200,
    TEE_STORAGE_CMD_CREAT_EXIST,
    TEE_STORAGE_CMD_OPEN,
    TEE_STORAGE_CMD_OPEN_NONEXISTENT,
    TEE_STORAGE_CMD_WRITE,
    TEE_STORAGE_CMD_READ,
    TEE_STORAGE_CMD_READ_NONEXISTENT,
};

TEE_Result ta_test_storage(unsigned int cmd);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* _TEE_TEST_TA_STORAGE_H */
