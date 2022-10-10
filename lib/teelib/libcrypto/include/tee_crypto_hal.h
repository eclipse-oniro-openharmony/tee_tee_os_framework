/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Create: 2019-01-20
 * Description: crypto hal info function
 */

#ifndef TEE_CRYPTO_HAL_H
#define TEE_CRYPTO_HAL_H
#include "tee_crypto_api.h"
enum CRYPTO_ENGINE {
    DX_CRYPTO = 0,
    EPS_CRYPTO = 1,
    SOFT_CRYPTO = 2,
    SEC_CRYPTO = 3,
    CRYPTO_ENGINE_MAX = 1024,
};

/*
 * Set the encryption and decryption engine to operation
 *
 * @param operation [IN/OUT] The handle of operation
 * @param crypto    [IN]The engine to be set
 *
 * @retval TEE_SUCCESS: Set crypto engine success
 * @retval TEE_ERROR_BAD_PARAMETERS: Operation is NULLi or crypto is invalid
 */
TEE_Result TEE_SetCryptoFlag(TEE_OperationHandle operation, uint32_t crypto);

/*
 * Set the encryption and decryption engine to object
 *
 * @param operation [IN/OUT] The handle of object
 * @param crypto    [IN]The engine to be set
 *
 * @retval TEE_SUCCESS: Set crypto engine success
 * @retval TEE_ERROR_BAD_PARAMETERS: Operation is NULLi or crypto is invalid
 */
TEE_Result TEE_SetObjectFlag(TEE_ObjectHandle object, uint32_t crypto);
#endif
