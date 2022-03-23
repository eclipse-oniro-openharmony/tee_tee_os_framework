/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: This file contains the function required for deriving HUK
 * Author: Xu Hangyu x00447026
 * Create: 2018-08-30
 */
#include "bdkernel_hardware.h"
#include "tee_ext_api.h"
#include "tee_log.h"
#include "bdkernel_utils.h"

/* This function is used to derive device key. */
static TEE_Result DeriveDeviceKey(uint32_t keySize, uint8_t *out)
{
    uint8_t salt[SALT_SIZE] = {0};
    uint32_t size = SALT_SIZE;
    uint8_t key[HWAA_KEY_SEED_KEY_LEN] = {0};
    TEE_Result ret;

    if ((out == NULL) || (keySize != HWAA_KEY_SEED_KEY_LEN)) {
        SLogError("param invalid, keysize:%d,out:%x", keySize, out);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = TEE_EXT_DeriveTARootKey(salt, size, key, keySize);
    if (ret != TEE_SUCCESS) {
        SLogError("UuidDeriveKey faild:%x", ret);
        return ret;
    }
    if (memcpy_s(out, keySize, key, HWAA_KEY_SEED_KEY_LEN) != EOK) {
        SLogError("memcpy failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return ret;
}

/*
 *   This function reads device-specific bits that can be used as the key seed.
 *   @param outBytes             [out] Destination of device-specific bits
 *   @param outBytesSize         [out] number of bytes read
 *   @return 0 if successful
 */
TEE_Result ReadTeeDeviceUniqueBytes(uint8_t **outBytes, uint32_t *outBytesSize)
{
    TEE_Result teeRet = TEE_SUCCESS;
    uint32_t availableBytes = HWAA_KEY_SEED_KEY_LEN;
    uint8_t *rawBytes;

    if ((outBytes == NULL) || (outBytesSize == NULL)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    rawBytes = TEE_Malloc(availableBytes, 0);
    if (rawBytes == NULL) {
        SLogError("TEE_Malloc failed");
        *outBytesSize = 0;
        return TEE_ERROR_BAD_PARAMETERS;
    } else {
        teeRet = DeriveDeviceKey(availableBytes, rawBytes);
        if (teeRet != TEE_SUCCESS) {
            SLogError("DeriveDeviceKey failed");
            TEE_Free(rawBytes);
            rawBytes = NULL;
            *outBytesSize = 0;
            return teeRet;
        }

        *outBytesSize = availableBytes;
        *outBytes = rawBytes;
    }

    return TEE_SUCCESS;
}
