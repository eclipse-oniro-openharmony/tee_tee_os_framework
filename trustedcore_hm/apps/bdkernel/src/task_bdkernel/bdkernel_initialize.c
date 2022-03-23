/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: This file contains the definition required for Initialiazation and Destroy
 * Author: Xu Hangyu x00447026
 * Create: 2018-08-30
 */

#include "bdkernel_initialize.h"
#include "tee_log.h"
#include "bdkernel_hardware.h"
#include "bdkernel_utils.h"

uint8_t *g_hwaaKeySeed;

/* Invoke the TEE interface to generate the random key seed */
TEE_Result InitializeTee(void)
{
    uint8_t *secretKey = NULL;
    uint32_t secretKeySize = 0;
    TEE_Result ret = ReadTeeDeviceUniqueBytes(&secretKey, &secretKeySize);

    if ((ret != TEE_SUCCESS) || (secretKeySize != HWAA_KEY_SEED_KEY_LEN)) {
        SLogError("ReadTeeDeviceUniqueBytes failed");
        if (secretKey != NULL) {
            TEE_Free(secretKey);
            secretKey = NULL;
        }
        return TEE_ERROR_BAD_PARAMETERS;
    }

    g_hwaaKeySeed = secretKey;
    return TEE_SUCCESS;
}

/* Invoke the TEE interface to destory the key seed */
void DestroyTee(void)
{
    if (g_hwaaKeySeed != NULL) {
        SecureFree(g_hwaaKeySeed, HWAA_KEY_SEED_KEY_LEN);
        g_hwaaKeySeed = NULL;
    }
}

/* Invoke the TEE interface to get the key seed */
TEE_Result GetKeySeed(uint8_t **keySeed, uint32_t *keySize)
{
    TEE_Result ret = TEE_SUCCESS;
    if ((keySeed == NULL) || (keySize == NULL)) {
        SLogError("Bad Param!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (g_hwaaKeySeed == NULL) {
        ret = InitializeTee();
        if (ret != TEE_SUCCESS) {
            SLogError("Initialize tee failed");
            return ret;
        }
    }

    *keySeed = TEE_Malloc(HWAA_KEY_SEED_KEY_LEN, 0);
    if (*keySeed == NULL) {
        SLogError("keySeed malloc failed!");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memcpy_s(*keySeed, HWAA_KEY_SEED_KEY_LEN, g_hwaaKeySeed, HWAA_KEY_SEED_KEY_LEN) != EOK) {
        SLogError("memcpy failed");
        SecureFree(*keySeed, HWAA_KEY_SEED_KEY_LEN);
        *keySeed = NULL;
        *keySize = 0;
        return TEE_ERROR_BAD_PARAMETERS;
    }
    *keySize = HWAA_KEY_SEED_KEY_LEN;
    return TEE_SUCCESS;
}
