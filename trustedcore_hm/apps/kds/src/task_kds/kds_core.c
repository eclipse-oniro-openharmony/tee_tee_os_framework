/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: This file contains some core function related to key algorithm.
 * Create: 2020-06-28
 */

#include "kds_core.h"
#include "tee_crypto_kds_api.h"
#include "kds_defs.h"

static TEE_Result DoHmacSha256(const DataBlob *msgBlob, const DataBlob *hmacKey,
    DataBlob *hmacResult, TEE_OperationHandle *opModuleHandle, TEE_ObjectHandle *hmacKeyHandle)
{
    TEE_Result ret = TEE_AllocateOperation(opModuleHandle, TEE_ALG_HMAC_SHA256,
        TEE_MODE_MAC, hmacKey->len);
    if (ret != TEE_SUCCESS) {
        SLogError("TEE_AllocateOperation error:%x\n", ret);
        return ret;
    }
    ret = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, SHA256_OBJECT_MAX_LENGTH,
        hmacKeyHandle);
    if (ret != TEE_SUCCESS) {
        SLogError("TEE_AllocateTransientObject error:%x\n", ret);
        return ret;
    }

    TEE_Attribute attribute = {0};
    TEE_InitRefAttribute(&attribute, TEE_ATTR_SECRET_VALUE,
        (void *)(hmacKey->dataPtr), hmacKey->len);
    ret = TEE_PopulateTransientObject(*hmacKeyHandle, &attribute, ATTRIBUTE_NUM_ONE);
    if (ret != TEE_SUCCESS) {
        SLogError("TEE_PopulateTransientObject error, ret:%x\n", ret);
        return ret;
    }

    ret = TEE_SetOperationKey(*opModuleHandle, *hmacKeyHandle);
    if (ret != TEE_SUCCESS) {
        SLogError("TEE_SetOperationKey error, ret:%x\n", ret);
        return ret;
    }

    TEE_MACInit(*opModuleHandle, (void *)hmacKey->dataPtr, hmacKey->len);
    TEE_MACUpdate(*opModuleHandle, (void *)msgBlob->dataPtr, msgBlob->len);
    ret = TEE_MACComputeFinal(*opModuleHandle, NULL, 0, hmacResult->dataPtr,
        (size_t *)(&hmacResult->len));
    if (ret != TEE_SUCCESS) {
        SLogError("TEE_MACComputeFinal error, ret:%x\n", ret);
    }
    return ret;
}

TEE_Result HmacSha256(const DataBlob *msgBlob, const DataBlob *hmacKey, DataBlob *hmacResult)
{
    if ((msgBlob == NULL) || (msgBlob->dataPtr == NULL) ||
        (hmacKey == NULL) || (hmacKey->dataPtr == NULL) || (hmacKey->len == 0) ||
        (hmacResult->dataPtr == NULL)) {
        SLogError("Bad parameters! msgBlob->dataPtr=%x, hmacKey->dataPtr=%x, hmacResult->dataPtr=%x",
            msgBlob->dataPtr, hmacKey->dataPtr, hmacResult->dataPtr);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_OperationHandle opModuleHandle = NULL;
    TEE_ObjectHandle hmacKeyHandle = NULL;
    TEE_Result ret = DoHmacSha256(msgBlob, hmacKey, hmacResult, &opModuleHandle, &hmacKeyHandle);
    if (ret != TEE_SUCCESS) {
        SLogError("DoHmacSha256 failed ret = 0x%x", ret);
    }

    if (hmacKeyHandle != NULL) {
        TEE_CloseObject(hmacKeyHandle);
        hmacKeyHandle = NULL;
    }
    if (opModuleHandle) {
        TEE_FreeOperation(opModuleHandle);
        opModuleHandle = NULL;
    }
    return ret;
}

static TEE_Result CheckAesCbcEncParams(const DataBlob *keyData, const DataBlob *plantData,
    AesCbcEncryptParams *encryptParams)
{
    if ((keyData == NULL) || (plantData == NULL) || (encryptParams == NULL) ||
        (keyData->dataPtr == NULL) || (keyData->len == 0) ||
        (plantData->dataPtr == NULL) || (plantData->len == 0) ||
        (encryptParams->cipherData == NULL) ||
        (encryptParams->ivData == NULL) ||
        (encryptParams->cipherLen == 0) ||
        (encryptParams->ivLen == 0)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result GenKeyHandleForAes(const DataBlob *keyData, TEE_ObjectHandle *keyHandle,
    TEE_Attribute *attribute)
{
    TEE_Result ret = TEE_AllocateTransientObject(TEE_TYPE_AES, KDS_MAX_KEY_OBJECT_SIZE, keyHandle);
    if (ret != TEE_SUCCESS) {
        SLogError("GenKeyHandleForAes TEE_AllocateTransientObject error:0x%x", ret);
        return ret;
    }

    TEE_InitRefAttribute(attribute, TEE_ATTR_SECRET_VALUE,
        (void*)(keyData->dataPtr), keyData->len);
    ret = TEE_PopulateTransientObject(*keyHandle, attribute, ATTRIBUTE_NUM_ONE);
    if (ret != TEE_SUCCESS) {
        SLogError("GenKeyHandleForAes TEE_PopulateTransientObject error:0x%x", ret);
    }
    return ret;
}

static TEE_Result GenIvDataForAesCbc(uint8_t *ivData, size_t ivLen)
{
    TEE_GenerateRandom(ivData, ivLen);
    size_t j = 0;

    for (size_t i = 0; i < ivLen; ++i) {
        if (ivData[i] == 0) {
            j++;
        }
    }
    if (j == ivLen) {
        SLogError("generate random iv data failed\n");
        return TEE_FAIL;
    }
    return TEE_SUCCESS;
}

static TEE_Result DoAesCbcEncrypt(const TEE_ObjectHandle *keyHandle, const DataBlob *plantData,
    AesCbcEncryptParams *encryptParams)
{
    TEE_Result ret;
    TEE_OperationHandle aesModuleHandle = NULL;
    do {
        ret = TEE_AllocateOperation(&aesModuleHandle, TEE_ALG_AES_CBC_PKCS5, TEE_MODE_ENCRYPT,
            KDS_MAX_KEY_OBJECT_SIZE);
        if (ret != TEE_SUCCESS) {
            SLogError("DoAesCbcEncrypt TEE_AllocateOperation error:0x%x", ret);
            break;
        }

        ret = TEE_SetOperationKey(aesModuleHandle, *keyHandle);
        if (ret != TEE_SUCCESS) {
            SLogError("DoAesCbcEncrypt TEE_SetOperationKey error:0x%x", ret);
            break;
        }

        *(encryptParams->ivLen) = IV_SIZE;
        ret = GenIvDataForAesCbc(encryptParams->ivData, IV_SIZE);
        if (ret != TEE_SUCCESS) {
            SLogError("DoAesCbcEncrypt generate iv error:0x%x", ret);
            break;
        }

        TEE_CipherInit(aesModuleHandle, (void*)encryptParams->ivData, *encryptParams->ivLen);
        ret = TEE_CipherDoFinal(aesModuleHandle, (void *)plantData->dataPtr, plantData->len,
            (void *)encryptParams->cipherData, encryptParams->cipherLen);
        if (ret != TEE_SUCCESS) {
            SLogError("DoAesCbcEncrypt TEE_CipherDoFinal error:0x%x", ret);
            break;
        }
    } while (0);

    if (aesModuleHandle != NULL) {
        TEE_FreeOperation(aesModuleHandle);
        aesModuleHandle = NULL;
    }
    return ret;
}

TEE_Result TaAesCbcEncrypt(const DataBlob *keyData, const DataBlob *plantData,
    AesCbcEncryptParams *encryptParams)
{
    if (CheckAesCbcEncParams(keyData, plantData, encryptParams) != TEE_SUCCESS) {
        SLogError("Aes cbc encrypt param error");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = TEE_SUCCESS;
    TEE_ObjectHandle keyHandle = NULL;
    TEE_Attribute attribute = {0};
    do {
        if (GenKeyHandleForAes(keyData, &keyHandle, &attribute) != TEE_SUCCESS) {
            SLogError("Aes cbc encrypt GenKeyHandleForAes error");
            ret = TEE_FAIL;
            break;
        }

        if (DoAesCbcEncrypt(&keyHandle, plantData, encryptParams) != TEE_SUCCESS) {
            SLogError("Aes cbc encrypt DoAesCbcEncrypt error");
            ret = TEE_FAIL;
            break;
        }
    } while (0);
    if (keyHandle != NULL) {
        TEE_FreeTransientObject(keyHandle);
        keyHandle = NULL;
    }
    return ret;
}

static TEE_Result CheckAesCbcDecryptParams(const DataBlob *keyData, const DataBlob *ivData,
    const DataBlob *cipherData, uint8_t *plantData, size_t *plantDataSize)
{
    if ((keyData == NULL) || (ivData == NULL) || (cipherData == NULL) ||
        (keyData->dataPtr == NULL) || (ivData->dataPtr == NULL) || (cipherData->dataPtr == NULL) ||
        (keyData->len == 0) || (ivData->len == 0) || (cipherData->len == 0) ||
        (plantData == NULL) || (plantDataSize == 0)) {
        SLogError("CheckAesCbcDecryptParams error");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result DoAesCbcDecrypt(const TEE_ObjectHandle *keyHandle, const DataBlob *ivData,
    const DataBlob *cipherData, uint8_t *plantData, size_t *plantDataSize)
{
    TEE_Result ret;
    TEE_OperationHandle aesModuleHandle = NULL;
    do {
        ret = TEE_AllocateOperation(&aesModuleHandle, TEE_ALG_AES_CBC_PKCS5, TEE_MODE_DECRYPT,
            KDS_MAX_KEY_OBJECT_SIZE);
        if (ret != TEE_SUCCESS) {
            SLogError("TEE_AllocateOperation error:0x%x", ret);
            break;
        }

        ret = TEE_SetOperationKey(aesModuleHandle, *keyHandle);
        if (ret != TEE_SUCCESS) {
            SLogError("TEE_SetOperationKey error:0x%x", ret);
            break;
        }

        TEE_CipherInit(aesModuleHandle, (void*)ivData->dataPtr, ivData->len);
        ret = TEE_CipherDoFinal(aesModuleHandle, (void *)cipherData->dataPtr, cipherData->len,
            (void *)plantData, plantDataSize);
        if (ret != TEE_SUCCESS) {
            SLogError("TEE_CipherDoFinal error:0x%x", ret);
            break;
        }
    } while (0);
    if (aesModuleHandle != NULL) {
        TEE_FreeOperation(aesModuleHandle);
        aesModuleHandle = NULL;
    }
    return ret;
}

TEE_Result AesDecrypt(const DataBlob *keyData, const DataBlob *ivData,
    const DataBlob *cipherData, uint8_t *plantData, size_t *plantDataSize)
{
    if (CheckAesCbcDecryptParams(keyData, ivData, cipherData, plantData, plantDataSize) !=
        TEE_SUCCESS) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = TEE_SUCCESS;
    TEE_ObjectHandle keyHandle = NULL;
    TEE_Attribute attribute = {0};
    do {
        if (GenKeyHandleForAes(keyData, &keyHandle, &attribute) != TEE_SUCCESS) {
            SLogError("Aes cbc decrypt GenKeyHandleForAes error");
            ret = TEE_FAIL;
            break;
        }

        if (DoAesCbcDecrypt(&keyHandle, ivData, cipherData, plantData, plantDataSize) !=
            TEE_SUCCESS) {
            SLogError("Aes cbc decrypt DoAesCbcDecrypt error");
            ret = TEE_FAIL;
            break;
        }
    } while (0);
    if (keyHandle != NULL) {
        TEE_FreeTransientObject(keyHandle);
        keyHandle = NULL;
    }
    return ret;
}

static TEE_Result GenerateKeyHandle(TEE_ObjectHandle *keyHandle, const DataBlob *key,
    TEE_Attribute *attribute)
{
    TEE_Result ret = TEE_AllocateTransientObject(TEE_TYPE_AES, MAX_KEY_SIZE, keyHandle);
    if (ret != TEE_SUCCESS) {
        SLogError("GenerateKeyHandle: TEE_AllocateTransientObject, failed ret=0x%x", ret);
        return ret;
    }

    TEE_InitRefAttribute(attribute, TEE_ATTR_SECRET_VALUE, key->dataPtr, key->len);
    ret = TEE_PopulateTransientObject(*keyHandle, attribute, ATTRIBUTE_NUM_ONE);
    if (ret != TEE_SUCCESS) {
        SLogError("GenerateKeyHandle: TEE_PopulateTransientObject, failed ret=0x%x", ret);
        return ret;
    }
    return TEE_SUCCESS;
}

static TEE_Result DoAesCcmEncryptOrDecrypt(TEE_OperationHandle *aesModuleHandle,
    AesCcmParams *aesCcmParams, DataBlob *srcData, DataBlob *dest)
{
    TEE_Result ret;
    switch (aesCcmParams->mode) {
        case TEE_MODE_ENCRYPT:
            ret = TEE_AEEncryptFinal_KDS(*aesModuleHandle, srcData->dataPtr,
                srcData->len + aesCcmParams->tag.len,
                dest->dataPtr, &(dest->len), &(aesCcmParams->tag.len));
            if (ret != TEE_SUCCESS) {
                dest->len = 0;
                SLogError("encrypt mode,failed %x", ret);
                return ret;
            }
            return TEE_SUCCESS;
        case TEE_MODE_DECRYPT:
            ret = TEE_AEDecryptFinal_KDS(*aesModuleHandle, srcData->dataPtr,
                srcData->len + aesCcmParams->tag.len,
                dest->dataPtr, &(dest->len), aesCcmParams->tag.len);
            if (ret != TEE_SUCCESS) {
                dest->len = 0;
                SLogError("decrypt mode,failed %x", ret);
                return ret;
            }
            dest->len = srcData->len + aesCcmParams->tag.len;
            SLogTrace("decrypt mode, success");
            return TEE_SUCCESS;
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
}

static TEE_Result AesCcmEncryptOrDecrypt(const DataBlob *key, AesCcmParams *aesCcmParams,
    DataBlob *srcData, DataBlob *dest)
{
    TEE_Result ret;
    TEE_ObjectHandle keyHandle = NULL;
    TEE_OperationHandle aesModuleHandle = NULL;
    TEE_Attribute attribute = {0};
    do {
        ret = GenerateKeyHandle(&keyHandle, key, &attribute);
        if (ret != TEE_SUCCESS) {
            SLogError("generate key handle failed, ret=0x%x", ret);
            break;
        }

        ret = TEE_AllocateOperation(&aesModuleHandle, TEE_ALG_AES_CCM, aesCcmParams->mode,
            MAX_KEY_SIZE);
        if (ret != TEE_SUCCESS) {
            SLogError("TEE_AllocateOperation, failed ret=0x%x", ret);
            break;
        }
        ret = TEE_SetOperationKey(aesModuleHandle, keyHandle);
        if (ret != TEE_SUCCESS) {
            SLogError("TEE_SetOperationKey, failed ret=0x%x", ret);
            break;
        }

        ret = TEE_AEInit(aesModuleHandle, aesCcmParams->nonce.dataPtr, aesCcmParams->nonce.len,
            aesCcmParams->tag.len, aesCcmParams->aad.len, srcData->len);
        if (ret != TEE_SUCCESS) {
            SLogError("TEE_AEInit, failed ret=0x%x", ret);
            break;
        }
        TEE_AEUpdateAAD(aesModuleHandle, aesCcmParams->aad.dataPtr, aesCcmParams->aad.len);
        ret = DoAesCcmEncryptOrDecrypt(&aesModuleHandle, aesCcmParams, srcData, dest);
        if (ret != TEE_SUCCESS) {
            SLogError("aes ccm encrypt or decrypt failed, ret=0x%x", ret);
            break;
        }
    } while (0);

    if (aesModuleHandle != NULL) {
        TEE_FreeOperation(aesModuleHandle);
        aesModuleHandle = NULL;
    }
    if (keyHandle != NULL) {
        TEE_FreeTransientObject(keyHandle);
        keyHandle = NULL;
    }
    return ret;
}

static TEE_Result DoKdsHmac(const DataBlob *srcData, const DataBlob *key,
    TEE_OperationHandle *hmacModuleHandle, TEE_ObjectHandle *keyHandle, DataBlob *dest)
{
    TEE_Attribute attribute = {0};
    TEE_Result ret = GenerateKeyHandle(keyHandle, key, &attribute);
    if (ret != TEE_SUCCESS) {
        SLogError("GenerateKeyHandle, failed ret=0x%x", ret);
        return ret;
    }

    ret = TEE_AllocateOperation(hmacModuleHandle, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, MAX_KEY_SIZE);
    if (ret != TEE_SUCCESS) {
        SLogError("TEE_AllocateOperation, failed ret=0x%x", ret);
        return ret;
    }

    ret = TEE_SetOperationKey(*hmacModuleHandle, *keyHandle);
    if (ret != TEE_SUCCESS) {
        SLogError("TEE_SetOperationKey fail,%x", ret);
        return ret;
    }

    TEE_MACInit(*hmacModuleHandle, (void *)key->dataPtr, key->len);

    uint32_t loop = srcData->len / BLOCK_SIZE_MAX;
    for (uint32_t i = 0; i < loop; i++) {
        TEE_MACUpdate(*hmacModuleHandle, srcData->dataPtr + (i * BLOCK_SIZE_MAX), BLOCK_SIZE_MAX);
    }
    uint32_t last = srcData->len % BLOCK_SIZE_MAX;
    TEE_MACUpdate(*hmacModuleHandle, srcData->dataPtr + loop * BLOCK_SIZE_MAX, last);

    ret = TEE_MACComputeFinal(*hmacModuleHandle, NULL, 0, dest->dataPtr, &dest->len);
    if (ret != TEE_SUCCESS) {
        SLogError("TEE_MACComputeFinal, fail ret=%x, srcDatalen=%x, destlen=%x\n",
            ret, srcData->len, dest->len);
        return ret;
    }
    return TEE_SUCCESS;
}

TEE_Result KdsHmac(const DataBlob *srcData, const DataBlob *key, DataBlob *dest)
{
    TEE_OperationHandle hmacModuleHandle = NULL;
    TEE_ObjectHandle keyHandle = NULL;
    TEE_Result ret = DoKdsHmac(srcData, key, &hmacModuleHandle, &keyHandle, dest);
    if (ret != TEE_SUCCESS) {
        SLogError("DoKdsHmac, fail ret = 0x%x", ret);
    }

    if (hmacModuleHandle != NULL) {
        TEE_FreeOperation(hmacModuleHandle);
        hmacModuleHandle = NULL;
    }

    if (keyHandle != NULL) {
        TEE_FreeTransientObject(keyHandle);
        keyHandle = NULL;
    }
    return ret;
}

static TEE_Result DerivePlatformKey(TEE_ObjectHandle *nativeKeyHandle, uint32_t curveInfo,
    const DataBlob *extInfo)
{
    TEE_Result ret = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, MAX_KEY_OBJECT_SIZE,
        nativeKeyHandle);
    if (ret != TEE_SUCCESS) {
        SLogError("key native failed\n");
        return ret;
    }

    ret = TEE_EXT_DeriveTAPlatfromKeys(*nativeKeyHandle, curveInfo, NULL, 0,
        extInfo->dataPtr, extInfo->len);
    if (ret != TEE_SUCCESS) {
        SLogError("TEE_EXT_DeriveTAPlatfromKeys return 0x%x.\n", ret);
        return ret;
    }
    SLogTrace("TEE_EXT_DeriveTAPlatfromKeys success.\n");

    DataBlob platPubKeyX = { NULL, KDS_PK_MAX };
    DataBlob platPubKeyY = { NULL, KDS_PK_MAX };
    platPubKeyX.dataPtr = (uint8_t *)TEE_Malloc(KDS_PK_MAX, 0);
    if (platPubKeyX.dataPtr == NULL) {
        SLogError("alloc pkx failed");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto EXIT;
    }
    platPubKeyY.dataPtr = (uint8_t *)TEE_Malloc(KDS_PK_MAX, 0);
    if (platPubKeyY.dataPtr == NULL) {
        SLogError("alloc pky failed");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto EXIT;
    }

    ret = TEE_GetObjectBufferAttribute(*nativeKeyHandle, TEE_ATTR_ECC_PUBLIC_VALUE_X,
        platPubKeyX.dataPtr, &platPubKeyX.len);
    if (ret != TEE_SUCCESS) {
        SLogError("TEE_GetObjectBufferAttribute failed, ret 0x%x\n", ret);
        goto EXIT;
    }

    ret = TEE_GetObjectBufferAttribute(*nativeKeyHandle, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
        platPubKeyY.dataPtr, &platPubKeyY.len);
    if (ret != TEE_SUCCESS) {
        SLogError("TEE_GetObjectBufferAttribute failed, ret 0x%x\n", ret);
        goto EXIT;
    }

EXIT:
    FREE_DATA_BLOB(&platPubKeyX);
    FREE_DATA_BLOB(&platPubKeyY);
    return ret;
}

static TEE_Result DoGenEcdhSharedKey(const TEE_ObjectHandle *nativeKeyHandle,
    const DataBlob *machinePk, DataBlob *sharedKey)
{
    TEE_OperationHandle algorithmModuleHandle = NULL;
    TEE_Attribute deriveParams[ATTRIBUTE_NUM_THREE] = { { 0 }, { 0 }, { 0 } };
    TEE_ObjectHandle sharedKeyHandle = NULL;
    TEE_Result ret;
    do {
        ret = TEE_AllocateOperation(&algorithmModuleHandle, TEE_ALG_ECDH_DERIVE_SHARED_SECRET,
            TEE_MODE_DERIVE, ECC256_OBJECT_MAX_LENGTH);
        if (ret != TEE_SUCCESS) {
            SLogError("TEE_AllocateOperation failed, ret %x\n", ret);
            break;
        }
        ret = TEE_SetOperationKey(algorithmModuleHandle, *nativeKeyHandle);
        if (ret != TEE_SUCCESS) {
            SLogError("TEE_SetOperationKey failed, ret %x\n", ret);
            break;
        }
        TEE_InitRefAttribute(&deriveParams[INDEX_ZERO], TEE_ATTR_ECC_PUBLIC_VALUE_X,
            machinePk->dataPtr, machinePk->len / DIVISION_NUM_TWO);
        TEE_InitRefAttribute(&deriveParams[INDEX_ONE], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
            machinePk->dataPtr + (machinePk->len / DIVISION_NUM_TWO),
            machinePk->len / DIVISION_NUM_TWO);
        TEE_InitValueAttribute(&deriveParams[INDEX_TWO], TEE_ATTR_ECC_CURVE,
            TEE_ECC_CURVE_NIST_P256, 0);

        ret = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, ECC256_OBJECT_MAX_LENGTH,
            &sharedKeyHandle);
        if (ret != TEE_SUCCESS) {
            SLogError("TEE_AllocateTransientObject failed, ret %x\n", ret);
            break;
        }
        TEE_DeriveKey(algorithmModuleHandle, deriveParams, ATTRIBUTE_NUM_THREE, sharedKeyHandle);
        ret = TEE_GetObjectBufferAttribute(sharedKeyHandle, TEE_ATTR_SECRET_VALUE,
            sharedKey->dataPtr, &sharedKey->len);
        if (ret != TEE_SUCCESS) {
            SLogError("TEE_GetObjectBufferAttribute failed, ret %x\n", ret);
            break;
        }
    } while (0);

    if (sharedKeyHandle != NULL) {
        TEE_FreeTransientObject(sharedKeyHandle);
        sharedKeyHandle = NULL;
    }
    if (algorithmModuleHandle != NULL) {
        TEE_FreeOperation(algorithmModuleHandle);
        algorithmModuleHandle = NULL;
    }
    return ret;
}

static TEE_Result GenEcdhSharedKey(const DataBlob *machinePk, const DataBlob *extInfo,
    uint32_t curveInfo, DataBlob *out)
{
    TEE_ObjectHandle nativeKeyHandle = NULL;
    SLogTrace("curveInfo = 0x%x \n", curveInfo);
    TEE_Result ret;
    do {
        ret = DerivePlatformKey(&nativeKeyHandle, curveInfo, extInfo);
        if (ret != TEE_SUCCESS) {
            SLogError("DerivePlatformKey, failed 0x%x\n", ret);
            break;
        }

        ret = DoGenEcdhSharedKey(&nativeKeyHandle, machinePk, out);
        if (ret != TEE_SUCCESS) {
            SLogError("DoGenEcdhSharedKey, failed 0x%x\n", ret);
            break;
        }
    } while (0);

    if (nativeKeyHandle != NULL) {
        TEE_FreeTransientObject(nativeKeyHandle);
        nativeKeyHandle = NULL;
    }
    return ret;
}

static TEE_Result DeriveWrapperKey(const DataBlob *taCustomData, const DataBlob *shareKey,
    DataBlob *out)
{
    TEE_Result ret = KdsHmac(taCustomData, shareKey, out);
    if (ret != TEE_SUCCESS) {
        SLogError("DeriveWrapperKey, failed 0x%x\n", ret);
    }
    return ret;
}

static void AssignAesCcmParams(const KdsDecryptParams *decryptParams, AesCcmParams *aesCcmParams)
{
    aesCcmParams->aad.dataPtr = decryptParams->aadData.dataPtr;
    aesCcmParams->aad.len = decryptParams->aadData.len;

    aesCcmParams->nonce.dataPtr = decryptParams->nonceData.dataPtr;
    aesCcmParams->nonce.len = decryptParams->nonceData.len;

    aesCcmParams->tag.dataPtr = decryptParams->tagData.dataPtr;
    aesCcmParams->tag.len = decryptParams->tagData.len;
}

static TEE_Result DoKdsDecrypt(const KdsDecryptParams *decryptParams, const DataBlob *wrapKey,
    DataBlob *out)
{
    DataBlob plantData;
    DataBlob realCipher;
    AesCcmParams aesCcmParams;
    memset_s(&aesCcmParams, sizeof(AesCcmParams), 0, sizeof(AesCcmParams));
    AssignAesCcmParams(decryptParams, &aesCcmParams);
    aesCcmParams.mode = TEE_MODE_DECRYPT;

    plantData.len = out->len + decryptParams->tagData.len;
    plantData.dataPtr = (uint8_t *)TEE_Malloc(plantData.len, 0);
    if (plantData.dataPtr == NULL) {
        SLogError("alloc plant failed");
        return TEE_FAIL;
    }

    realCipher.dataPtr = decryptParams->cipherData.dataPtr;
    realCipher.len = decryptParams->cipherData.len - decryptParams->tagData.len;

    TEE_Result teeRet = AesCcmEncryptOrDecrypt(wrapKey, &aesCcmParams, &realCipher, &plantData);
    if (teeRet != TEE_SUCCESS) {
        SLogError("aesCcm decrypt failed, 0x%x\n", teeRet);
        FREE_DATA_BLOB(&plantData);
        return teeRet;
    }

    int ret = memcpy_s(out->dataPtr, out->len, plantData.dataPtr,
        plantData.len - decryptParams->tagData.len);
    memset_s(plantData.dataPtr, plantData.len, 0, plantData.len);
    FREE_DATA_BLOB(&plantData);
    if (ret != EOK) {
        SLogError("copy failed, ret = 0x%x\n", ret);
        return TEE_FAIL;
    }
    return TEE_SUCCESS;
}

static TEE_Result InitShareAndWrapBlob(DataBlob *shareKey, DataBlob *wrapKey)
{
    shareKey->dataPtr = (uint8_t *)TEE_Malloc(KEY_MAX, 0);
    if (shareKey->dataPtr == NULL) {
        SLogError("alloc share key, failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    shareKey->len = KEY_MAX;

    wrapKey->dataPtr = (uint8_t *)TEE_Malloc(KEY_MAX, 0);
    if (wrapKey->dataPtr == NULL) {
        SLogError("alloc wrap key, failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    wrapKey->len = KEY_MAX;
    return TEE_SUCCESS;
}

TEE_Result KdsDecryptService(const KdsDecryptParams *decryptParams, DataBlob *out)
{
    TEE_Result ret;
    DataBlob shareKey; // Come from plat and enc machine ecdh, use for calculate wrapKey.
    DataBlob wrapKey; // Derived by share key, use for aes ccm decrypt.
    do {
        ret = InitShareAndWrapBlob(&shareKey, &wrapKey);
        if (ret != TEE_SUCCESS) {
            SLogError("InitShareAndWrapBlob, failed %x\n", ret);
            break;
        }

        ret = GenEcdhSharedKey(&decryptParams->pubKey, &decryptParams->extInfo,
            CONST_CURVE_INFO, &shareKey);
        if (ret != TEE_SUCCESS) {
            SLogError("get sharekey, failed %x\n", ret);
            break;
        }

        // Calculate wrapkey.
        ret = DeriveWrapperKey(&decryptParams->customData, &shareKey, &wrapKey);
        if (ret != TEE_SUCCESS) {
            SLogError("derive wrapKey failed, %x\n", ret);
            break;
        }

        ret = DoKdsDecrypt(decryptParams, &wrapKey, out);
        if (ret != TEE_SUCCESS) {
            SLogError("DoKdsDecrypt failed, %x\n", ret);
            break;
        }
    } while (0);

    FREE_DATA_BLOB(&shareKey);
    FREE_DATA_BLOB(&wrapKey);
    return ret;
}