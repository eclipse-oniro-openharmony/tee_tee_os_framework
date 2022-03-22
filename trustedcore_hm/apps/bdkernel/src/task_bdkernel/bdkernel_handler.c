/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: This file contains the function required for initializing user
 * Author: Xu Hangyu x00447026
 * Create: 2018-08-30
 */

#include "bdkernel_handler.h"
#include "tee_log.h"
#include "bdkernel_hardware.h"
#include "bdkernel_initialize.h"
#include "bdkernel_kdf.h"

#define CRED_SHAMEM_SIZE (sizeof(uint64_t) + sizeof(uint32_t) + KERNEL_CRED_SECRET_LENGTH)
#define CRED_HARDWARE_KEY_SIZE (2 * KERNEL_CRED_SECRET_LENGTH)

const uint32_t TA_EXPECTED_PARAM_TYPES = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_VALUE_INOUT,
                                                         TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

/* HandlerCleanUp to handle the kernel user init */
static void HandlerCleanUp(uint8_t **hardwareCred, uint8_t **keySeed, uint32_t keySize, TEE_ObjectHandle *phase1Key)
{
    if (*hardwareCred != NULL) {
        SecureFree(*hardwareCred, CRED_HARDWARE_KEY_SIZE);
        *hardwareCred = NULL;
    }
    if (*keySeed != NULL) {
        SecureFree(*keySeed, keySize);
        *keySeed = NULL;
    }
    if (*phase1Key != NULL) {
        TEE_FreeTransientObject(*phase1Key);
        *phase1Key = NULL;
    }
}

/* CheckParam to handle the kernel user init */
static TEE_Result CheckParam(uint32_t paramTypes, TEE_Param *params)
{
    if (params == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((paramTypes != TA_EXPECTED_PARAM_TYPES) || (params[0].memref.buffer == NULL)) {
        SLogError("params[0] is null or paramTypes not match");
        return TEE_ERROR_BAD_PARAMETERS;
    } else if (params[0].memref.size != CRED_SHAMEM_SIZE) {
        SLogError("params[0] size is wrong");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

/* HandleMemcpy to handle the kernel user init */
static TEE_Result HandleMemcpy(uint64_t *profileId, uint32_t *credSize, uint8_t * const p)
{
    if (memcpy_s(profileId, sizeof(uint64_t), p, sizeof(uint64_t)) != EOK) {
        SLogError("memcpy failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (memcpy_s(credSize, sizeof(uint32_t), p + sizeof(uint64_t), sizeof(uint32_t)) != EOK) {
        SLogError("memcpy failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (*credSize != KERNEL_CRED_SECRET_LENGTH) {
        SLogError("cred length (%d) is wrong", *credSize);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

/* generate the TEE key seed to handle the kernel user init */
static TEE_Result HandleKeySeed(uint8_t *hardwareCred, uint8_t **keySeed,
                                uint32_t *keySize, uint8_t * const cred, uint32_t credSize)
{
    TEE_Result teeRet = GetKeySeed(keySeed, keySize);
    if ((teeRet != TEE_SUCCESS) || (*keySeed == NULL)) {
        SLogError("GetKeySeed failed");
        return teeRet;
    }
    if (memcpy_s(hardwareCred, CRED_HARDWARE_KEY_SIZE, cred, credSize) != EOK) {
        SLogError("memcpy failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (memcpy_s(hardwareCred + credSize, CRED_HARDWARE_KEY_SIZE - credSize, *keySeed, *keySize) != EOK) {
        SLogError("memcpy failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

/* invoke the TEE interface to handle the kernel user init */
TEE_Result HandleKernelInitUser(uint32_t paramTypes, TEE_Param *params)
{
    uint32_t credSize = 0;
    uint8_t *keySeed = NULL;
    uint32_t keySize = 0;
    uint64_t profileId = 0;
    TEE_ObjectHandle phase1Key = NULL;
    TEE_Result teeRet = CheckParam(paramTypes, params);
    if (teeRet != TEE_SUCCESS) {
        return teeRet;
    }
    uint8_t *p = params[0].memref.buffer;
    teeRet = HandleMemcpy(&profileId, &credSize, p);
    if (teeRet != TEE_SUCCESS) {
        return teeRet;
    }
    uint8_t * const cred = p + sizeof(uint64_t) + sizeof(uint32_t);
    uint8_t *hardwareCred = TEE_Malloc(CRED_HARDWARE_KEY_SIZE, 0);
    if (hardwareCred == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    do {
        teeRet = HandleKeySeed(hardwareCred, &keySeed, &keySize, cred, credSize);
        if (teeRet != TEE_SUCCESS) {
            break;
        }
        teeRet = KdfAllocateKeySeed(hardwareCred, CRED_HARDWARE_KEY_SIZE, &phase1Key);
        if (teeRet != TEE_SUCCESS) {
            SLogError("KdfAllocateKeySeed return 0x%x", teeRet);
            break;
        }
        uint8_t *phase1KeyData = phase1Key->Attribute->content.ref.buffer;
        uint32_t phase1KeyDataSize = phase1Key->Attribute->content.ref.length;
        if (phase1KeyDataSize != KERNEL_CRED_SECRET_LENGTH) {
            SLogError("phase1Key bad size (%d)", phase1KeyDataSize);
            teeRet = TEE_ERROR_BAD_PARAMETERS;
            break;
        }
        if (memcpy_s((uint8_t *)p, params[0].memref.size, phase1KeyData, phase1KeyDataSize) != EOK) {
            SLogError("memcpy failed");
            teeRet = TEE_ERROR_BAD_PARAMETERS;
            break;
        }
        params[0].memref.size = phase1KeyDataSize;
        SLogTrace("set cred success");
    } while (0);
    HandlerCleanUp(&hardwareCred, &keySeed, keySize, &phase1Key);
    return teeRet;
}
