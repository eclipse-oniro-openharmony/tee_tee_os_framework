/* $$$!!Warning: Huawei key information asset. No spread without permission.$$$ */
/* CODEMARK:G45B5tAhAurX3Fjv5w5YrnvEBsxawGU4sQTa6eXHOFkC1Mfvbai6ssLiuF4skCy23hW+xgyXJaVN
2jIjipr/cpauHINx1FQyMyereaY2ZKz1AEk16KBYT3zrrVcV/zYZa+SM7KtAIjQaXRQOuxkCVCHR
djsuW3qvWZbQ3ZjHygm+9Z7Zon2QkYjMt+j1ajp+5u25sy0tND3u8XRRTFLYIcPN3a00GwLwzcWQ
hFfZjUw=# */
/* $$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tee crypto api hmac algorithm implementation
 * Create: 2022-04-06
 */
#include "tee_crypto_api.h"
#include <string.h>
#include <tee_log.h>
#include <crypto_driver_adaptor.h>
#include <crypto_inner_defines.h>
#include <crypto_hal_hmac.h>
#include <tee_property_inner.h>
#include <tee_object_api.h>
#include "tee_operation.h"

TEE_Result TEE_MACCompareFinal(TEE_OperationHandle operation, const void *message, size_t messageLen,
        const void *mac, const size_t macLen)
{
    uint8_t hmac_result_buff_temp[MAX_HMAC_LEN] = { 0 };
    size_t size = macLen;

    TEE_Result ret = TEE_MACComputeFinal(operation, message, messageLen, hmac_result_buff_temp, &size);
    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    if (ret != TEE_SUCCESS) {
        tloge("MAC compute final failed\n");
        goto error;
    }

    bool check = (size != macLen || TEE_MemCompare((void *)hmac_result_buff_temp, mac, (uint32_t)size) != 0);
    if (check) {
        tloge("size 0x%x != macLen 0x%x or compare failed!\n", size, macLen);
        ret = TEE_ERROR_MAC_INVALID;
        goto error;
    }

    free_operation_ctx(operation);
    crypto_unlock_operation(operation);
    return ret;
error:
    free_operation_ctx(operation);
    crypto_unlock_operation(operation);
    if (ret != TEE_ERROR_MAC_INVALID)
        TEE_Panic(ret);
    return ret;
}
