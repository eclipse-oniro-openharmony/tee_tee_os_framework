/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: This file contains the function required for creating PHASE 1 KEY
 * Author: Xu Hangyu x00447026
 * Create: 2018-08-30
 */
#include "bdkernel_kdf.h"
#include "tee_internal_api.h"
#include "tee_log.h"

/*
 * What ever you do, DON'T change these constants once this code is in production.
 * It will prevent existing devices from decrypting properly.
 */
static const uint8_t KDF_INFO[] = { 'H', 'W', 'A', 'A', ' ', 'P', 'H', 'A', 'S', 'E', '1', '!' };
static const uint32_t KDF_INFO_LEN = sizeof(KDF_INFO);

static TEE_Result KdfGenKeySeed(const uint8_t *hardwareKey, uint32_t hardwareKeyLen,
                                uint8_t *outputKey, uint32_t *outputKeyLen);

static TEE_Result Hkdf256Extract(TEE_ObjectHandle salt, const uint8_t * const inputKey, size_t inputKeyLen,
                                 uint8_t *outputKey, uint32_t *outputKeyLen);

static TEE_Result Hkdf256Expand(const TEE_ObjectHandle prk, const uint8_t *info, uint32_t infoLen,
                                uint8_t *outputKey, uint32_t *outputKeyLen);

/* KdfAllocateKeySeed to alloc the key seed buffer */
TEE_Result KdfAllocateKeySeed(const uint8_t * const hardwareKey, uint32_t hardwareKeyLen, TEE_ObjectHandle *output)
{
    uint8_t keySeed[SHA256_LEN] = {0};
    uint32_t keySeedLen = SHA256_LEN;
    TEE_Attribute attrib;

    if ((hardwareKey == NULL) || (output == NULL)) {
        SLogError("Phase1 - null pointer");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, SHA256_MAX_OBJECT_LENGTH, output);
    if (ret != TEE_SUCCESS) {
        SLogError("Phase1 - Allocate failed");
        goto CLEANUP_1;
    }

    ret = KdfGenKeySeed(hardwareKey, hardwareKeyLen, keySeed, &keySeedLen);
    if (ret != TEE_SUCCESS) {
        SLogError("Failed to GenSeed");
        goto CLEANUP_2;
    }

    TEE_InitRefAttribute(&attrib, TEE_ATTR_SECRET_VALUE, (void *)keySeed, keySeedLen);

    ret = TEE_PopulateTransientObject(*output, &attrib, ATTRIBUTE_COUNT_ONE);
    if (ret != TEE_SUCCESS) {
        SLogError("Phase1 - Populate failed %d", ret);
        goto CLEANUP_2;
    }

    return ret;

CLEANUP_2:
    TEE_FreeTransientObject(*output);
CLEANUP_1:
    return ret;
}

/*
 * KdfGenKeySeed
 *
 * Description:
 *     Generating key seed.
 *
 * Params:
 *      hardwareKey- input - hardwareKey
 *      hardwareKeyLen - input - this represents the size of the hardwareKey
 *      outputKey - output - the output derived key
 *      outputKeyLen - input/output - on input this represents the size of the
 *      outputKey buffer, and the number of bytes of the desired key length.
 *
 * Returns:
 *    TEE_SUCCESS on success, and anything else on failure.
 */
static TEE_Result KdfGenKeySeed(const uint8_t * const hardwareKey, uint32_t hardwareKeyLen,
                                uint8_t *outputKey, uint32_t *outputKeyLen)
{
    TEE_ObjectHandle saltHandle = NULL;
    TEE_Attribute attrib = {0};
    uint8_t salt[SALT_LEN] = {0};
    if ((hardwareKey == NULL) || (hardwareKeyLen == 0) || (outputKey == NULL) || (outputKeyLen == NULL) ||
        (*outputKeyLen != AES256_KEY_LEN)) {
        SLogError("Phase 1 - Bad Args");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /*
     * Pack the puesdo randmon key returned by Extract into a TEE Key object
     */
    TEE_Result ret = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, SHA256_MAX_OBJECT_LENGTH, &saltHandle);
    if (ret != TEE_SUCCESS) {
        SLogTrace("Phase1 - Allocate failed %d", ret);
        goto CLEANUP_1;
    }
    TEE_InitRefAttribute(&attrib, TEE_ATTR_SECRET_VALUE, (void *)salt, SALT_LEN);
    ret = TEE_PopulateTransientObject(saltHandle, &attrib, ATTRIBUTE_COUNT_ONE);
    if (ret != TEE_SUCCESS) {
        SLogError("Phase1 - Populate failed %d", ret);
        goto CLEANUP_2;
    }
    /*
     * Call the KDF to generate the master seed for this user's cred
     */
    if (*outputKeyLen >= SHA256_MAX_OBJECT_LENGTH) {
        SLogTrace("HKDF - Bad args");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = Hkdf256(saltHandle, hardwareKey, hardwareKeyLen, outputKey, outputKeyLen);
CLEANUP_2:
    TEE_FreeTransientObject(saltHandle);
CLEANUP_1:
    return ret;
}

/*
 * HKDF has two primary and potentially independent uses:
 *
 * 1. To "extract" (condense/blend) entropy from a larger random source to provide a more uniformly
 * unbiased and higher entropy but smaller output (e.g. an encryption key). This is done by utilising
 * the diffusion properties of cryptographic MACs.
 *
 * 2. To "expand" the generated output of an already reasonably random input such as an existing
 * shared key into a larger cryptographically independent output, thereby producing multiple keys
 * deterministically from that initial shared key, so that the same process may produce those same
 * secret keys safely on multiple devices, as long as the same inputs are utilised.
 */
TEE_Result Hkdf256(const TEE_ObjectHandle salt, const uint8_t * const inputKeyMaterial,
                   uint32_t inputKeyMaterialLen, uint8_t *outputKey, uint32_t *outputKeyLen)
{
    TEE_Result ret;
    TEE_OperationHandle operation = NULL;
    TEE_ObjectHandle key = NULL;
    TEE_Attribute attrib = {0};
    uint8_t tempKey[SHA256_HASH_BYTES] = {0};
    uint32_t tempKeyLen = SHA256_HASH_BYTES;
    /*
     * Perform the HKDF Extract phase of RFC 5869
     */
    ret = Hkdf256Extract(salt, inputKeyMaterial, inputKeyMaterialLen, tempKey, &tempKeyLen);
    if (ret != TEE_SUCCESS) {
        SLogTrace("HKDF - Extract failed %d", ret);
        goto CLEANUP_1;
    }
    /*
     * Pack the puesdo randmon key returned by Extract into a TEE Key object
     */
    ret = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, SHA256_MAX_OBJECT_LENGTH, &key);
    if (ret != TEE_SUCCESS) {
        SLogTrace("HKDF - Allocate failed %d", ret);
        goto CLEANUP_1;
    }
    TEE_InitRefAttribute(&attrib, TEE_ATTR_SECRET_VALUE, (void *)(tempKey), sizeof(tempKey));
    ret = TEE_PopulateTransientObject(key, &attrib, ATTRIBUTE_COUNT_ONE);
    if (ret != TEE_SUCCESS) {
        SLogTrace("HKDF - Populate failed %d", ret);
        goto CLEANUP_2;
    }
    ret = TEE_AllocateOperation(&operation, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, SHA256_MAX_OBJECT_LENGTH);
    if (ret != TEE_SUCCESS) {
        SLogTrace("HKDF - AllocateOperation failed %d", ret);
        goto CLEANUP_2;
    }
    ret = TEE_SetOperationKey(operation, key);
    if (ret != TEE_SUCCESS) {
        SLogTrace("HKDF - SetKey failed %d", ret);
        goto CLEANUP_3;
    }
    /*
     * Call the HKDF Expand phase of RFC 5869
     */
    ret = Hkdf256Expand(key, KDF_INFO, KDF_INFO_LEN,
                        outputKey, outputKeyLen);
    if (ret != TEE_SUCCESS) {
        SLogTrace("HKDF - Expand failed %d", ret);
        goto CLEANUP_3;
    }
CLEANUP_3:
    TEE_FreeOperation(operation);
CLEANUP_2:
    TEE_FreeTransientObject(key);
CLEANUP_1:
    return ret;
}

/*
 * Implementation of RFC 5869 - HKDF.  This implementation only supports 32 byte (256 bit) keys
 *
 * From the RFC
 *
 *  2.2.  Step 1: Extract
 *
 *    HKDF-Extract(salt, IKM) -> PRK
 *
 *    Options:
 *       Hash     a hash function; HashLen denotes the length of the
 *                hash function output in octets
 *
 *    Inputs:
 *       salt     optional salt value (a non-secret random value);
 *                if not provided, it is set to a string of HashLen zeros.
 *       IKM      input keying material
 *
 *  Output:
 *       PRK      a pseudorandom key (of HashLen octets)
 *
 *  The output PRK is calculated as follows:
 *
 *  PRK = HMAC-Hash(salt, IKM)
 */
static TEE_Result Hkdf256Extract(const TEE_ObjectHandle salt, const uint8_t * const inputKeyMaterial,
                                 size_t inputKeyMaterialLen, uint8_t *outputKey, uint32_t *outputKeyLen)
{
    TEE_OperationHandle op = NULL;
    uint8_t *saltData = salt->Attribute->content.ref.buffer;
    uint32_t saltDataSize = salt->Attribute->content.ref.length;

    TEE_Result ret = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, SHA256_MAX_OBJECT_LENGTH);
    if (ret != TEE_SUCCESS) {
        SLogTrace("Extract - AllocateOperation failed %d", ret);
        return ret;
    }

    ret = TEE_SetOperationKey(op, salt);
    if (ret != TEE_SUCCESS) {
        SLogTrace("Extract - SetKey failed %d", ret);
        goto CLEANUP;
    }

    TEE_MACInit(op, saltData, saltDataSize);
    ret = TEE_MACComputeFinal(op, (void *)inputKeyMaterial, inputKeyMaterialLen, (void *)outputKey, outputKeyLen);
    if (ret != TEE_SUCCESS) {
        SLogTrace("Extract - MAC Final failed %d", ret);
        goto CLEANUP;
    }

CLEANUP:
    TEE_FreeOperation(op);
    return ret;
}

/* HkdfObject to alloc object buffer */
static TEE_Result HkdfObject(const TEE_ObjectHandle prk, TEE_OperationHandle *op)
{
    TEE_Result ret = TEE_AllocateOperation(op, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, SHA256_MAX_OBJECT_LENGTH);
    if (ret != TEE_SUCCESS) {
        SLogError("Expand - AllocateOperation failed %d", ret);
        return ret;
    }
    ret = TEE_SetOperationKey(*op, prk);
    if (ret != TEE_SUCCESS) {
        SLogError("Expand - SetKey failed %d", ret);
        return ret;
    }
    return TEE_SUCCESS;
}

/* HkdfMemcpy to alloc buffer */
static TEE_Result HkdfMemcpy(uint8_t **infoCnt, uint32_t infoLen, const uint8_t * const info)
{
    if ((info == NULL) || (infoCnt == NULL)) {
        SLogError("null pointer!");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t cntBuffer[1] = { 0x01 }; // the padding 0x01 for infoCnt buffer
    *infoCnt = TEE_Malloc((uint32_t)infoLen + sizeof(cntBuffer), 0);
    if (*infoCnt == NULL) {
        SLogError("malloc failed!");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (memcpy_s(*infoCnt, (uint32_t)infoLen, info, (uint32_t)infoLen) != EOK) {
        SLogError("memcpy failed!");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (memcpy_s(*infoCnt + (uint32_t)infoLen, sizeof(cntBuffer), cntBuffer, sizeof(cntBuffer)) != EOK) {
        SLogError("memcpy failed!");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

/* HkdfMemcpyBuf to copy buffer */
static TEE_Result HkdfMemcpyBuf(uint8_t *initBuffer, uint8_t *interBuffer, uint32_t bufferLen,
                                uint8_t index, uint8_t *outputKey)
{
    uint8_t initBufferLen = SHA256_HASH_BYTES * (sizeof(uint8_t));
    uint8_t interBufferLen = SHA256_HASH_BYTES * (sizeof(uint8_t));
    if (memcpy_s(initBuffer, initBufferLen, interBuffer, interBufferLen) != EOK) {
        SLogError("memcpy failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (memcpy_s(outputKey + (SHA256_HASH_BYTES * (index - 1)), bufferLen, interBuffer, bufferLen) != EOK) {
        SLogError("memcpy failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

/* HkdfCleanUp to clean buffer */
void HkdfCleanUp(uint8_t **infoCount, uint32_t infoCountLen, TEE_OperationHandle *op)
{
    if (*infoCount != NULL) {
        SecureFree(*infoCount, infoCountLen);
        *infoCount = NULL;
    }
    if (*op != NULL) {
        TEE_FreeOperation(*op);
    }
}

/*
 * Implementation of RFC 5869 - HKDF. This implementation only supports 32 byte (256 bit) keys
 *
 * From the RFC
 *
 *  2.2.  Step 1: Expand
 *
 *    HKDF-Expand(salt, IKM) -> PRK
 *
 *         The second stage "expands" the pseudorandom key to the desired
 *    length; the number and lengths of the output keys depend on the
 *    specific cryptographic algorithms for which the keys are needed.
 *
 *    Options:
 *
 *       Hash     a hash function; HashLen denotes the length of the
 *                hash function output in octets
 *
 *    Inputs:
 *
 *       prk     public key generated from Hkdf256Extract
 *
 *       info      information
 *
 *       infoLen the length of info
 *
 *  Output:
 *
 *       outputKey            the expand result
 *
 *       outputKeyLen      the length of outputKey
 *
 *  The output is calculated as follows:
 *
 *    outputKey = HKDF-Expand(PRK, info, L)
 */
static TEE_Result Hkdf256Expand(const TEE_ObjectHandle prk, const uint8_t * const info, uint32_t infoLen,
                                uint8_t *outputKey, uint32_t *outputKeyLen)
{
    TEE_OperationHandle op = NULL;
    uint8_t initBuffer[SHA256_HASH_BYTES] = {0};
    uint8_t interBuffer[SHA256_HASH_BYTES] = {0};
    uint32_t interBufferLen = SHA256_HASH_BYTES;
    uint8_t cntBuffer[1] = { 0x01 }; // padding 0x01 for cntInfo
    uint32_t macLen = 0;
    uint8_t *infoCnt = NULL;
    uint8_t *privKeyData = prk->Attribute->content.ref.buffer;
    uint32_t privKeyDataSize = prk->Attribute->content.ref.length;
    uint32_t infoCntLen = (uint32_t)infoLen + sizeof(cntBuffer);
    uint32_t iter = (*outputKeyLen / SHA256_HASH_BYTES) + ((*outputKeyLen % SHA256_HASH_BYTES) != 0);
    TEE_Result ret = HkdfObject(prk, &op);
    if (ret != TEE_SUCCESS) {
        goto CLEANUP;
    }
    uint32_t remainingLen = *outputKeyLen;
    ret = HkdfMemcpy(&infoCnt, infoLen, info);
    if (ret != TEE_SUCCESS) {
        goto CLEANUP;
    }
    for (uint8_t index = 1; index <= iter; index++) {
        TEE_MACInit(op, privKeyData, privKeyDataSize);
        if (macLen > 0) {
            TEE_MACUpdate(op, (uint8_t *)initBuffer, macLen);
        }
        TEE_MACUpdate(op, infoCnt, infoCntLen);
        ret = TEE_MACComputeFinal(op, NULL, 0, (void *)interBuffer, &interBufferLen);
        if (ret != TEE_SUCCESS) {
            SLogTrace("Expand - MACFinal failed %d", ret);
            goto CLEANUP;
        }
        if (index < iter) {
            cntBuffer[0]++;
            ret = HkdfMemcpyBuf(initBuffer, interBuffer, interBufferLen, index, outputKey);
            if (ret != TEE_SUCCESS) {
                goto CLEANUP;
            }
            remainingLen -= SHA256_HASH_BYTES;
        }
        macLen = SHA256_HASH_BYTES;
    }
    if (memcpy_s(outputKey + (SHA256_HASH_BYTES * (iter - 1)), remainingLen, interBuffer, remainingLen) != EOK) {
        SLogError("memcpy failed");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto CLEANUP;
    }
CLEANUP:
    HkdfCleanUp(&infoCnt, infoCntLen, &op);
    return ret;
}
