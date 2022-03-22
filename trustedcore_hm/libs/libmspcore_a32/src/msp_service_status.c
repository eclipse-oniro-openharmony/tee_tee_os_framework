/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: get msp hardware status.
 * Author : y00362156
 * Create: 2020/05/19
 */
#include "msp_service_status.h"
#include "mspc_ext_api.h"
#include "sec_flash_ext_api.h"

uint8_t g_sa_table[MSP_SERVICE_MAX_COUNT] = {
    MSP_SERVICE_IS_SUPPORTED,   /* secure storage */
    MSP_SERVICE_IS_SUPPORTED,   /* file encryption system */
    MSP_SERVICE_IS_SUPPORTED,   /* root of trust */
    MSP_SERVICE_IS_SUPPORTED,   /* weaver */
    MSP_SERVICE_IS_SUPPORTED,   /* antiroll token */
    MSP_SERVICE_NOT_SUPPORTED,
    MSP_SERVICE_NOT_SUPPORTED,
    MSP_SERVICE_NOT_SUPPORTED,
    MSP_SERVICE_NOT_SUPPORTED,
    MSP_SERVICE_NOT_SUPPORTED,
    MSP_SERVICE_NOT_SUPPORTED,
    MSP_SERVICE_NOT_SUPPORTED,
    MSP_SERVICE_NOT_SUPPORTED,
    MSP_SERVICE_NOT_SUPPORTED,
    MSP_SERVICE_NOT_SUPPORTED,
    MSP_SERVICE_NOT_SUPPORTED,
};

TEE_Result mspcore_get_service_status(uint32_t service_id, uint8_t *status)
{
    TEE_Result result = TEE_SUCCESS;
    uint32_t index = service_id & 0xff; /* the LSB 8 BITS  are service ID */

    if (index >= MSP_SERVICE_MAX_COUNT || status == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

#ifdef CONFIG_HISI_MSPC
    *status = g_sa_table[index];
#else
    *status = MSP_SERVICE_NOT_SUPPORTED;
#endif

    return result;
}

TEE_Result mspcore_get_hw_status(uint32_t *status)
{
    TEE_Result result = TEE_SUCCESS;

    if (status == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
#ifdef CONFIG_HISI_MSPC
    uint32_t secflash_status;
    uint32_t msp_status;

    result = TEE_EXT_SecFlashIsAvailable(&secflash_status);
    if (result != TEE_SUCCESS) {
        tloge("get SecFlash status fail, ret=0x%x\n", result);
        return result;
    }

    result = TEE_EXT_MSPIsAvailable(&msp_status);
    if (result != TEE_SUCCESS) {
        tloge("get msp status fail, ret=0x%x\n", result);
        return result;
    }

    if (secflash_status == SECFLASH_IS_ABSENCE_MAGIC || msp_status == MSPC_NOT_AVAILABLE_MAGIC) {
        *status = MSP_HW_UNAVAILABLE;
    } else {
        *status = MSP_HW_AVAILABLE;
    }
#else
    *status = MSP_HW_UNAVAILABLE;
#endif

    return result;
}
