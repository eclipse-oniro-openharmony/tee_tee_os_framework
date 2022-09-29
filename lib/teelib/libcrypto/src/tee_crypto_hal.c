/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:lBRwzWIfWflpkuvEPG9oHU2mxP0IzvCfvv+i+/xvfe6PT8VRR+8jz7b5YQbqzI49/C6xSBgi
2fFxGZUs+G3nkUIkBkfRerjPcgJTCLqrXspNkFCGTLklL/GZHRhiXBwGnNKhh0MAXEOVfrQU
iukZUWJ4vidruSf/U7e9gpUyQAooCWCSaeb3aIYEst5WD1qne8GcO+5QGB0g7/S8T09ixUGT
nR+osDAHaIEfyoPHfIFAJAQLD0ohh2OwUozrcXB/#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: For crypto hal
 * Author: Jialingyu j00430229
 * Create: 2019-01-31
 */
#include "tee_crypto_hal.h"
#include <tee_log.h>
#include <tee_defines.h>
#include <crypto_hal.h>
#include <tee_object_api.h>
#include <crypto_inner_defines.h>
#include "tee_crypto_api.h"

TEE_Result TEE_SetCryptoFlag(TEE_OperationHandle operation, uint32_t crypto)
{
    if (operation == NULL) {
        tloge("operation is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    crypto_hal_info *crypto_hal_data = (crypto_hal_info *)(operation->hal_info);
    if (crypto_hal_data == NULL) {
        tloge("Crypto hal info is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    bool check =
        (((operation->operationClass == TEE_OPERATION_DIGEST) && (crypto_hal_data->digestalloc_flag == 1)) ||
         ((operation->operationClass != TEE_OPERATION_DIGEST) &&
          ((operation->handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
           (operation->handleState & TEE_HANDLE_FLAG_KEY_SET))));
    if (check) {
        tloge("operation state is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    crypto_hal_data->crypto_flag = crypto;
    return TEE_SUCCESS;
}
TEE_Result TEE_SetObjectFlag(TEE_ObjectHandle object, uint32_t crypto)
{
    if (object == NULL) {
        tloge("object is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (crypto >= CRYPTO_ENGINE_MAX) {
        tloge("flag is invalid!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    object->generate_flag = crypto;
    return TEE_SUCCESS;
}

TEE_Result TEE_IsHardWareSupportAlgorithm(uint32_t alg_type)
{
    TEE_Result ret;

    ret = (TEE_Result)tee_crypto_check_alg_support(alg_type);
    if (ret == 0)
        return TEE_SUCCESS;

    return TEE_ERROR_NOT_SUPPORTED;
}
