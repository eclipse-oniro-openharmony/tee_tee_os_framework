/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Secure flash msg communication management.
 * Author: Tian Jianliang tianjianliang@huawei.com
 * Create: 2019-10-15
 * Notes:
 * History: 2019-10-15 lvtaolong create sf_xxx functions.
 *          2019-10-15 lvtaolong add TEE_EXT_SecFlashxxx functions.
 */
#include "sec_flash_ext_api.h"
#include <stdarg.h>
#include "tee_log.h"

/* if secure flash feature is diable, stub these TEE_EXT_xxx functions */
TEE_Result TEE_EXT_SecFlashIsAvailable(uint32_t *status_info)
{
    if (status_info == NULL) {
        tloge("invalid params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *status_info = SECFLASH_IS_ABSENCE_MAGIC;
    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_SecFlashFactoryRecovery(uint32_t flags)
{
    (void)flags;
    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_SecFlashPowerSaving(void)
{
    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_SecFlashReset(uint32_t reset_type)
{
    (void)reset_type;
    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_SecFlashGetBindingKey(uint8_t *key_buf, uint32_t buf_len)
{
    (void)key_buf;
    (void)buf_len;
    return TEE_SUCCESS;
}


TEE_Result TEE_EXT_SecFlashWriteLockEnable(bool is_set_operation)
{
    (void)is_set_operation;
    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_MspcRecovery(uint32_t flags)
{
    (void)flags;
    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_MSPIsAvailable(uint32_t *status)
{
    if (status == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    *status = 0xB3;
    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_MspcPowerOn(uint32_t vote_id)
{
    (void)vote_id;
    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_MspcPowerOff(uint32_t vote_id)
{
    (void)vote_id;
    return TEE_SUCCESS;
}

