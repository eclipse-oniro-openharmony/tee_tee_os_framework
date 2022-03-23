/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: cc driver implementation
 * Author: Dizhe Mao maodizhe1@huawei.com
 * Create: 2018-05-18
 */

/*
 * This file is used as a intermedia layer of Userspace and Dx driver.
 * In Userspace all functions/variables/macros are using Austin DX Head files.
 * In Driver they are all using the real driver's Head files.
 * and we have 3 different DX drivers : Austin/Atlanta/MTK6765
 *
 * DX version:
 * Austin:  CryptoCell_6.3
 * Atlanta: CryptoCell_7.1.2
 * MTK:     CryptoCell_7.1.0
 *
 * For adapt purpose, we make several modifies to MTK DX driver:
 * 1. to avoid name define conflicts, we replaces all
 *    CRYS/SaSi, crys/sasi, crys/sasi in whole driver dirs.
 * 2. there are several bugfixs in Atlanta, we also ported them into MTK DX driver.
 *
 */
#include "mtk_adapt.h"
#include <legacy_mem_ext.h> /* SRE_MemAlloc */
#include <securec.h>
#include <openssl/rand.h>
#include "mem_ops.h"
#include "sre_log.h"

#define AES_Key128BitSize 0
#define AES_Key192BitSize 1
#define AES_Key256BitSize 2
#define AES_Key512BitSize 3

#define AES_Key16Bytes    16
#define AES_Key24Bytes    24
#define AES_Key32Bytes    32
#define AES_Key64Bytes    64

#define STORE_IN_PAIR     2
#define BUFFER_4K_SIZE 4096
#define BUFFER_16_SIZE 16
#define BUFFER_16_COUNT 256

SaSi_RND_Context_t g_rnd_context_ptr;
SaSi_RND_WorkBuff_t g_rnd_workbuff_ptr = {0};
static uint8_t g_vectors[BUFFER_4K_SIZE] = {0};
static unsigned int g_get_vector_count = BUFFER_16_COUNT;
SaSi_RND_Context_t *get_rnd_context_ptr(void)
{
    return &g_rnd_context_ptr;
}

SaSi_RND_WorkBuff_t *get_rnd_workbuff_ptr(void)
{
    return &g_rnd_workbuff_ptr;
}

SaSiError_t crys_aes_is_mac_mode(SaSi_DESUserContext_t *context, SaSiBool_t *mac_mode)
{
    if (context == NULL || mac_mode == NULL)
        return -1;

    return sasi_aes_mac_mode((SaSiAesUserContext_t*)context, mac_mode);
}

static SaSiError_t crys_rnd_generatevector_tmp(
    /* !< [in] The size in bytes of the random vector required. The maximal size is 2^16 -1 bytes. */
    size_t    outSizeBytes,
    /* !< [out] The pointer to output buffer. */
    uint8_t   *out_ptr)
{
    DX_Clock_Init();
    SaSiError_t ret;
    ret = SaSi_RND_GenerateVector_MTK(
        &g_rnd_context_ptr.rndState,
        outSizeBytes,
        out_ptr);
    if (ret != SaSi_OK)
        printf("create rnd failed\n");
    DX_Clock_Uninit();
    return ret;
}

static SaSiError_t get_4k_vector(void)
{
    SaSiError_t ret;
    ret = crys_rnd_generatevector_tmp(sizeof(g_vectors), g_vectors);
    if (ret != 0) {
        tloge("CRYS_RND failed\n");
        return ret;
    }

    g_get_vector_count = 0;
    return 0;
}

SaSiError_t CRYS_RND_GenerateVector(uint16_t outSizeBytes, uint8_t *out_ptr)
{
    SaSiError_t ret;
    int res;
    unsigned int write_count;
    unsigned int left_size = (unsigned int)outSizeBytes;
    if (out_ptr == NULL) {
        tloge("out_ptr error\n");
        return -1;
    }
    if (outSizeBytes >= BUFFER_4K_SIZE) {
        ret = crys_rnd_generatevector_tmp(outSizeBytes, out_ptr);
        if (ret != 0) {
            tloge("CRYS_RND failed\n");
            return ret;
        }
        return 0;
    }
    if (g_get_vector_count > BUFFER_16_COUNT) {
        tloge("g_get_vector_count is error\n");
        return -1;
    }
    if (g_get_vector_count == BUFFER_16_COUNT ||
        left_size > (BUFFER_16_COUNT - g_get_vector_count) * BUFFER_16_SIZE) {
        ret = get_4k_vector();
        if (ret != 0) {
            tloge("get_4k_vector failed\n");
            return -1;
        }
    }
    if (left_size % BUFFER_16_SIZE == 0) {
        write_count = left_size / BUFFER_16_SIZE;
    } else {
        write_count = left_size / BUFFER_16_SIZE + 1;
    }
    res = memcpy_s(out_ptr, outSizeBytes, g_vectors + g_get_vector_count * BUFFER_16_SIZE, left_size);
    if (res != EOK) {
        tloge("memcpy to out_ptr failed\n");
        return -1;
    }
    res = memset_s(g_vectors + g_get_vector_count * BUFFER_16_SIZE,
                   BUFFER_4K_SIZE - g_get_vector_count * BUFFER_16_SIZE, 0, left_size);
    if (res != EOK) {
        tloge("memset g_vectors failed\n");
        return -1;
    }
    g_get_vector_count += write_count;
    return 0;
}

SaSiError_t _DX_RSA_Sign(
        SaSi_RSAPrivUserContext_t *UserContext_ptr,
        SaSi_RSAUserPrivKey_t *UserPrivKey_ptr,
        SaSi_RSA_HASH_OpMode_t rsaHashMode,
        SaSi_PKCS1_MGF_t MGF,
        uint16_t       SaltLen,
        uint8_t     *DataIn_ptr,
        uint32_t       DataInSize,
        uint8_t     *Output_ptr,
        uint16_t    *OutputSize_ptr,
        SaSi_PKCS1_version PKCS1_ver)

{
    SaSiError_t ret;

    DX_Clock_Init();
    ret = SaSi_RsaSign(
        &g_rnd_context_ptr,
        UserContext_ptr,
        UserPrivKey_ptr,
        rsaHashMode,
        MGF,
        SaltLen,
        DataIn_ptr,
        DataInSize,
        Output_ptr,
        OutputSize_ptr,
        PKCS1_ver);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t _DX_RSA_SCHEMES_Decrypt(
        SaSi_RSAUserPrivKey_t  *UserPrivKey_ptr,
        SaSi_RSAPrimeData_t    *PrimeData_ptr,
        SaSi_RSA_HASH_OpMode_t  hashFunc,
        uint8_t              *L,
        uint16_t                Llen,
        SaSi_PKCS1_MGF_t      MGF,
        uint8_t              *DataIn_ptr,
        uint16_t                DataInSize,
        uint8_t              *Output_ptr,
        uint16_t             *OutputSize_ptr,
        SaSi_PKCS1_version    PKCS1_ver)

{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_RsaSchemesDecrypt(
        UserPrivKey_ptr,
        PrimeData_ptr,
        hashFunc,
        L,
        Llen,
        MGF,
        DataIn_ptr,
        DataInSize,
        Output_ptr,
        OutputSize_ptr,
        PKCS1_ver);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_RSA_Get_PubKey(
        SaSi_RSAUserPubKey_t *UserPubKey_ptr,
        uint8_t  *Exponent_ptr,
        uint16_t   *ExponentSize_ptr,
        uint8_t  *Modulus_ptr,
        uint16_t   *ModulusSize_ptr)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_RSA_Get_PubKey_MTK(
        UserPubKey_ptr,
        Exponent_ptr,
        ExponentSize_ptr,
        Modulus_ptr,
        ModulusSize_ptr);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_HASH_Init(
    /* !< [in]  Pointer to the HASH context buffer allocated by the user that is used for the HASH machine operation. */
    SaSi_HASHUserContext_t     *ContextID_ptr,
    /* !< [in]  One of the supported HASH modes, as defined in SaSi_HASH_OperationMode_t. */
    SaSi_HASH_OperationMode_t  OperationMode)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_HASH_Init_MTK(ContextID_ptr, OperationMode);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_DES_Free(SaSi_DESUserContext_t *ContextID_ptr)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_DES_Free_MTK(ContextID_ptr);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_HMAC_Free(SaSi_HMACUserContext_t *ContextID_ptr)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_HMAC_Free_MTK(ContextID_ptr);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_HASH_Update(
        SaSi_HASHUserContext_t   *ContextID_ptr,
        uint8_t                  *DataIn_ptr,
        size_t                   DataInSize)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_HASH_Update_MTK(ContextID_ptr,
                               DataIn_ptr,
                               DataInSize);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_HMAC_Init(
        SaSi_HMACUserContext_t *ContextID_ptr,
        SaSi_HASH_OperationMode_t OperationMode,
        uint8_t *key_ptr,
        uint16_t keySize)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_HMAC_Init_MTK(
        ContextID_ptr,
        OperationMode,
        key_ptr,
        keySize);
    DX_Clock_Uninit();
    return ret;
}


SaSiError_t CRYS_HMAC_Finish(SaSi_HMACUserContext_t  *ContextID_ptr,
                             SaSi_HASH_Result_t      HmacResultBuff)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_HMAC_Finish_MTK(ContextID_ptr, HmacResultBuff);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_HASH_Finish(SaSi_HASHUserContext_t  *ContextID_ptr,
                             SaSi_HASH_Result_t      HashResultBuff)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_HASH_Finish_MTK(ContextID_ptr, HashResultBuff);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_HMAC_Update(
        SaSi_HMACUserContext_t  *ContextID_ptr,
        uint8_t                 *DataIn_ptr,
        uint32_t                  DataInSize)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_HMAC_Update_MTK(ContextID_ptr,
                               DataIn_ptr,
                               DataInSize);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_HMAC(
        SaSi_HASH_OperationMode_t   OperationMode,
        uint8_t                  *key_ptr,
        uint16_t                   keySize,
        uint8_t                  *DataIn_ptr,
        uint32_t                   DataSize,
        SaSi_HASH_Result_t          HmacResultBuff)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_HMAC_MTK(OperationMode,
                        key_ptr,
                        keySize,
                        DataIn_ptr,
                        DataSize,
                        HmacResultBuff);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_AES_Finish(
    SaSiAesUserContext_t   *pContext,
    uint8_t                *pDataIn,
    size_t                 dataSize,
    uint8_t                *pDataOut)
{
    SaSiError_t ret;
    size_t data_out_size;
    DX_Clock_Init();
    if (dataSize < SASI_AES_BLOCK_SIZE_IN_BYTES)
        data_out_size = SASI_AES_BLOCK_SIZE_IN_BYTES;
    else
        data_out_size = dataSize;

    ret = SaSi_AesFinish(pContext,
                         dataSize,
                         pDataIn,
                         dataSize,
                         pDataOut,
                         &data_out_size);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t  CRYS_AES_Init(
        SaSiAesUserContext_t *pContext,
        SaSiAesIv_t pIv,
        uint8_t     *pKey,
        uint32_t keySize,
        SaSiAesEncryptMode_t   encryptDecryptFlag,
        SaSiAesOperationMode_t operationMode)
{
    SaSiError_t error;
    SaSiAesUserKeyData_t keyData = {0};
    uint32_t keySizeBytes = 0;

    DX_Clock_Init();
    /* Encrypt (K,IV) by AES-CBC using output buff */
    error = SaSi_AesInit(pContext, encryptDecryptFlag, operationMode, SASI_AES_PADDING_NONE);
    if (error != SaSi_OK) {
        DX_Clock_Uninit();
        return error;
    }
    switch (keySize) {
    case AES_Key128BitSize:
        keySizeBytes = AES_Key16Bytes;
        break;
    case AES_Key192BitSize:
        keySizeBytes = AES_Key24Bytes;
        break;
    case AES_Key256BitSize:
        keySizeBytes = AES_Key32Bytes;
        break;
    case AES_Key512BitSize:
        keySizeBytes = AES_Key64Bytes;
        break;
    default:
        DX_Clock_Uninit();
        return 0xF00003; /* for preventing compiler warnings */
    }
    keyData.pKey = pKey;
    keyData.keySize = keySizeBytes;
    error = SaSi_AesSetKey(pContext, SASI_AES_USER_KEY, (void*)&keyData, sizeof(keyData));
    if (error != SaSi_OK) {
        DX_Clock_Uninit();
        return error;
    }

    if (operationMode != SASI_AES_MODE_ECB && operationMode != SASI_AES_MODE_CMAC) {
        error = SaSi_AesSetIv(pContext, pIv);
        if (error != SaSi_OK) {
            DX_Clock_Uninit();
            return error;
        }
    }
    DX_Clock_Uninit();
    return error;
}


SaSiError_t CRYS_AES_Block(
        SaSiAesUserContext_t  *pContext,
        uint8_t               *pDataIn,
        size_t                dataInSize,
        uint8_t               *pDataOut)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_AesBlock(pContext,
                        pDataIn,
                        dataInSize,
                        pDataOut);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t  CRYS_AES(
        SaSiAesIv_t pIv,
        uint8_t *pKey,
        uint32_t keySize,
        SaSiAesEncryptMode_t encMode,
        SaSiAesOperationMode_t oprMode,
        uint8_t *dataIn,
        size_t dataInSize,
        uint8_t *dataOut)
{
    SaSiError_t error;
    SaSiAesUserContext_t aesContext = {0};
    SaSiAesUserKeyData_t keyData = {0};
    size_t dataOutSize = dataInSize;
    uint32_t keySizeBytes = 0;

    DX_Clock_Init();
    /* Encrypt (K,IV) by AES-CBC using output buff */
    error = SaSi_AesInit(&aesContext, encMode, oprMode, SASI_AES_PADDING_NONE);
    if (error != SaSi_OK) {
        DX_Clock_Uninit();
        return error;
    }
    switch (keySize) {
    case AES_Key128BitSize:
        keySizeBytes = AES_Key16Bytes;
        break;
    case AES_Key192BitSize:
        keySizeBytes = AES_Key24Bytes;
        break;
    case AES_Key256BitSize:
        keySizeBytes = AES_Key32Bytes;
        break;
    case AES_Key512BitSize:
        keySizeBytes = AES_Key64Bytes;
        break;
    default:
        /* for preventing compiler warnings */
        DX_Clock_Uninit();
        return SASI_AES_ILLEGAL_KEY_SIZE_ERROR;
    }
    keyData.pKey = pKey;
    keyData.keySize = keySizeBytes;
    error = SaSi_AesSetKey(&aesContext, SASI_AES_USER_KEY, (void*)&keyData, sizeof(keyData));
    if (error != SaSi_OK) {
        DX_Clock_Uninit();
        return error;
    }

    if (oprMode != SASI_AES_MODE_ECB && oprMode != SASI_AES_MODE_CMAC) {
        error = SaSi_AesSetIv(&aesContext, pIv);
        if (error != SaSi_OK) {
            DX_Clock_Uninit();
            return error;
        }
    }
    error = SaSi_AesFinish(&aesContext,
                           dataInSize,
                           dataIn, /* in */
                           dataInSize,
                           dataOut, /* out */
                           (size_t *)&dataOutSize);
    DX_Clock_Uninit();
    return error;
}

SaSiError_t  CRYS_DES_Init(SaSi_DESUserContext_t    *ContextID_ptr,
                           SaSi_DES_Iv_t            IV_ptr,
                           SaSi_DES_Key_t           *Key_ptr,
                           SaSi_DES_NumOfKeys_t     NumOfKeys,
                           SaSi_DES_EncryptMode_t   EncryptDecryptFlag,
                           SaSi_DES_OperationMode_t OperationMode)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_DES_Init_MTK(ContextID_ptr,
                            IV_ptr,
                            Key_ptr,
                            NumOfKeys,
                            EncryptDecryptFlag,
                            OperationMode);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_DES_Block(
        SaSi_DESUserContext_t *ContextID_ptr,
        uint8_t        *DataIn_ptr,
        uint32_t    DataInSize,
        uint8_t        *DataOut_ptr)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_DES_Block_MTK(ContextID_ptr,
                             DataIn_ptr,
                             DataInSize,
                             DataOut_ptr);
    DX_Clock_Uninit();
    return ret;
}

SaSiUtilError_t DX_UTIL_CmacDeriveKey(SaSiUtilKeyType_t keyType,
                                      uint8_t           *pDataIn,
                                      size_t            dataInSize,
                                      SaSiUtilAesCmacResult_t   pCmacResult)
{
    SaSiUtilError_t ret;

    if (keyType == SASI_UTIL_USER_KEY) {
        tloge("not support this keyType: UTIL_USER_KEY\n");
        return SASI_UTIL_INVALID_KEY_TYPE;
    }

    DX_Clock_Init();
    ret = SaSi_UtilCmacDeriveKey(keyType, NULL, pDataIn, dataInSize, pCmacResult);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t _DX_ECPKI_BuildPublKey(
        SaSi_ECPKI_DomainID_t  DomainID,        /* in */
        uint8_t *pPubKeyIn,                     /* in */
        uint32_t publKeySizeInBytes,            /* in */
        EC_PublKeyCheckMode_t checkMode,        /* in */
        SaSi_ECPKI_UserPublKey_t *pUserPublKey, /* out */
        SaSi_ECPKI_BUILD_TempData_t *tempBuff)  /* in */
{
    (void)tempBuff;
    SaSiError_t ret;
    SaSi_ECPKI_UserPublKey_t UserPublKey = {0};
    SaSi_ECPKI_BUILD_TempData_t ptempBuff;
    struct SaSi_ECPKI_PublKey_t *rPublKey = NULL;
    SaSi_ECPKI_PublKey_trans_t *pPublKey = NULL;

    if (pUserPublKey == NULL) {
        tloge("invalid pUserPublKey\n");
        return -1;
    }

    pPublKey = (SaSi_ECPKI_PublKey_trans_t *)&pUserPublKey->PublKeyDbBuff;
    rPublKey = (struct SaSi_ECPKI_PublKey_t *)&UserPublKey.PublKeyDbBuff;

    DX_Clock_Init();
    ret = _DX_ECPKI_BuildPublKey_MTK(SaSi_ECPKI_GetEcDomain(DomainID),
                                     pPubKeyIn,
                                     publKeySizeInBytes,
                                     checkMode,
                                     &UserPublKey,
                                     &ptempBuff);
    DX_Clock_Uninit();
    if (EOK != memcpy_s(pPublKey,
                        SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t),
                        rPublKey,
                        SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t))) {
        tloge("memcpy_s failed\n");
        ret = -1;
    }
    pPublKey->DomainID = rPublKey->domain.DomainID;

    return ret;
}

SaSiError_t CRYS_ECPKI_GenKeyPair(SaSi_ECPKI_DomainID_t DomainID, /* in */
                                  SaSi_ECPKI_UserPrivKey_trans_t *pUserPrivKey, /* out */
                                  SaSi_ECPKI_UserPublKey_trans_t *pUserPublKey, /* out */
                                  SaSi_ECPKI_KG_TempData_t *pTempBuff)          /* in */
{
    (void)pTempBuff;
    SaSi_ECPKI_UserPrivKey_t UserPrivKey = {0};
    SaSi_ECPKI_UserPublKey_t UserPublKey = {0};

    if ((pUserPrivKey == NULL) || (pUserPublKey == NULL)) {
        tloge("invalid params\n");
        return -1;
    }

    SaSi_ECPKI_KG_TempData_t *TempBuff = (SaSi_ECPKI_KG_TempData_t *)SRE_MemAlloc(0, 0,
                                                                                  sizeof(SaSi_ECPKI_KG_TempData_t));
    if (TempBuff == NULL) {
        tloge("malloc TempBuff failed\n");
        return -1;
    }

    DX_Clock_Init();
    SaSiError_t ret = SaSi_ECPKI_GenKeyPair_MTK(&g_rnd_context_ptr, SaSi_ECPKI_GetEcDomain(DomainID),
                                                &UserPrivKey, &UserPublKey, TempBuff, NULL);
    DX_Clock_Uninit();
    /* copy data to user */
    SaSi_ECPKI_PrivKey_t *rPrivKey = (SaSi_ECPKI_PrivKey_t *)&UserPrivKey.PrivKeyDbBuff;
    SaSi_ECPKI_PrivKey_trans_t *pPrivKey = (SaSi_ECPKI_PrivKey_trans_t *)&pUserPrivKey->PrivKeyDbBuff;
    if (EOK != memcpy_s(pPrivKey->PrivKey,
                        (SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1) * sizeof(uint32_t),
                        rPrivKey->PrivKey,
                        (SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1) * sizeof(uint32_t))) {
        tloge("memcpy_s failed\n");
        (void)SRE_MemFree(0, TempBuff);
        return -1;
    }
    pPrivKey->DomainID = rPrivKey->domain.DomainID;

    struct SaSi_ECPKI_PublKey_t *rPublKey = (struct SaSi_ECPKI_PublKey_t *)&UserPublKey.PublKeyDbBuff;
    SaSi_ECPKI_PublKey_trans_t *pPublKey = (SaSi_ECPKI_PublKey_trans_t *)pUserPublKey->PublKeyDbBuff;
    if (EOK != memcpy_s(pPublKey,
                        SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t),
                        rPublKey,
                        SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t))) {
        tloge("memcpy_s failed\n");
        (void)SRE_MemFree(0, TempBuff);
        return -1;
    }
    pPublKey->DomainID = rPublKey->domain.DomainID;
    (void)SRE_MemFree(0, TempBuff);
    return ret;
}

SaSiError_t CRYS_ECPKI_ExportPublKey(
                        SaSi_ECPKI_UserPublKey_trans_t *pUserPublKey, /* in */
                        SaSi_ECPKI_PointCompression_t compression,    /* in */
                        uint8_t *pExportPublKey,     /* in */
                        uint32_t *pPublKeySizeBytes) /* in/out */
{
    SaSiError_t ret;

    SaSi_ECPKI_UserPublKey_t UserPublKey = {0};
    struct SaSi_ECPKI_PublKey_t *rPublKey = NULL;
    SaSi_ECPKI_PublKey_trans_t *pPublKey = NULL;

    if (pUserPublKey == NULL) {
        tloge("invalid params\n");
        return -1;
    }
    pPublKey = (SaSi_ECPKI_PublKey_trans_t *)&pUserPublKey->PublKeyDbBuff;
    rPublKey = (struct SaSi_ECPKI_PublKey_t *)&UserPublKey.PublKeyDbBuff;
    if (EOK != memcpy_s(rPublKey,
                        SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t),
                        pPublKey,
                        SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t))) {
        tloge("memcpy_s failed\n");
        return -1;
    }
    if (EOK != memcpy_s(&rPublKey->domain,
                        sizeof(SaSi_ECPKI_Domain_t),
                        SaSi_ECPKI_GetEcDomain(pPublKey->DomainID),
                        sizeof(SaSi_ECPKI_Domain_t))) {
        tloge("memcpy_s failed\n");
        return -1;
    }
    UserPublKey.valid_tag = SaSi_ECPKI_PUBL_KEY_VALIDATION_TAG;

    DX_Clock_Init();
    ret = SaSi_ECPKI_ExportPublKey_MTK(&UserPublKey,
                                       compression,
                                       pExportPublKey,
                                       pPublKeySizeBytes);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_ECPKI_BuildPrivKey(
        SaSi_ECPKI_DomainID_t DomainID, /* in */
        const uint8_t *pPrivKeyIn,      /* in */
        size_t privKeySizeInBytes,      /* in */
        SaSi_ECPKI_UserPrivKey_trans_t *pUserPrivKey) /* out */
{
    SaSiError_t ret;
    SaSi_ECPKI_UserPrivKey_t UserPrivKey = {0};
    SaSi_ECPKI_PrivKey_trans_t *pPrivKey = NULL;
    SaSi_ECPKI_PrivKey_t *rPrivKey = NULL;

    if (pUserPrivKey == NULL) {
        tloge("invalid params\n");
        return -1;
    }
    DX_Clock_Init();
    ret = SaSi_ECPKI_BuildPrivKey_MTK(SaSi_ECPKI_GetEcDomain(DomainID),
                                      pPrivKeyIn,
                                      privKeySizeInBytes,
                                      &UserPrivKey);
    DX_Clock_Uninit();
    pPrivKey = (SaSi_ECPKI_PrivKey_trans_t *)&pUserPrivKey->PrivKeyDbBuff;
    rPrivKey = (SaSi_ECPKI_PrivKey_t *)&UserPrivKey.PrivKeyDbBuff;
    if (EOK != memcpy_s(pPrivKey->PrivKey,
                        (SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1) * sizeof(uint32_t),
                        rPrivKey->PrivKey,
                        (SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1) * sizeof(uint32_t))) {
        tloge("memcpy_s failed\n");
        return -1;
    }
    pPrivKey->DomainID = rPrivKey->domain.DomainID;

    return ret;
}

SaSiError_t CRYS_ECDSA_Sign(SaSi_ECDSA_SignUserContext_t *pSignUserContext, /* in/out */
                            SaSi_ECPKI_UserPrivKey_trans_t *pUserPrivKey,   /* in */
                            SaSi_ECPKI_HASH_OpMode_t hashMode,              /* in */
                            uint8_t *pMessageDataIn,     /* in */
                            uint32_t messageSizeInBytes, /* in */
                            uint8_t *pSignOut,           /* out */
                            uint32_t *pSignOutSize)      /* in */
{
    (void)pSignUserContext;
    SaSi_ECDSA_SignUserContext_t *SignUserContext = NULL;
    SaSi_ECPKI_UserPrivKey_t UserPrivKey = {0};

    if (pUserPrivKey == NULL) {
        tloge("invalid params\n");
        return -1;
    }

    SignUserContext = (SaSi_ECDSA_SignUserContext_t *)SRE_MemAlloc(0, 0, sizeof(SaSi_ECDSA_SignUserContext_t));
    if (SignUserContext == NULL) {
        tloge("malloc SignUserContext failed\n");
        return -1;
    }
    UserPrivKey.valid_tag = SaSi_ECPKI_PRIV_KEY_VALIDATION_TAG;
    SaSi_ECPKI_PrivKey_t *rPrivKey = (SaSi_ECPKI_PrivKey_t *)&UserPrivKey.PrivKeyDbBuff;
    SaSi_ECPKI_PrivKey_trans_t *pPrivKey = (SaSi_ECPKI_PrivKey_trans_t *)&pUserPrivKey->PrivKeyDbBuff;

    if (EOK != memcpy_s(rPrivKey->PrivKey, (SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1) * sizeof(uint32_t),
                        pPrivKey->PrivKey, (SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1) * sizeof(uint32_t))) {
        tloge("memcpy_s failed\n");
        (void)SRE_MemFree(0, SignUserContext);
        return -1;
    }

    if (EOK != memcpy_s(&rPrivKey->domain, sizeof(SaSi_ECPKI_Domain_t),
                        SaSi_ECPKI_GetEcDomain(pPrivKey->DomainID), sizeof(SaSi_ECPKI_Domain_t))) {
        tloge("memcpy_s failed\n");
        (void)SRE_MemFree(0, SignUserContext);
        return -1;
    }

    DX_Clock_Init();
    SaSiError_t ret = SaSi_ECDSA_Sign_MTK(&g_rnd_context_ptr, SignUserContext, /* in/out */
                                          &UserPrivKey, hashMode, pMessageDataIn, messageSizeInBytes, /* in */
                                          pSignOut,      /* out */
                                          pSignOutSize); /* in */
    DX_Clock_Uninit();

    ECDSA_SignContext_t *temp_buf1 = (ECDSA_SignContext_t *)&SignUserContext->context_buff;
    SaSi_ECPKI_UserPrivKey_t *temp_buf2 = (SaSi_ECPKI_UserPrivKey_t *)&temp_buf1->ECDSA_SignerPrivKey;
    rPrivKey  = (SaSi_ECPKI_PrivKey_t *)&temp_buf2->PrivKeyDbBuff;
    (void)SRE_MemFree(0, SignUserContext);
    return ret;
}

SaSiError_t CRYS_ECDSA_Verify (SaSi_ECDSA_VerifyUserContext_t *pVerifyUserContext, /* in/out */
                               SaSi_ECPKI_UserPublKey_trans_t *pUserPublKey,       /* in */
                               SaSi_ECPKI_HASH_OpMode_t hashMode, /* in */
                               uint8_t *pSignatureIn,             /* in */
                               uint32_t SignatureSizeBytes,       /* in */
                               uint8_t *pMessageDataIn,           /* in */
                               uint32_t messageSizeInBytes)       /* in */
{
    (void)pVerifyUserContext;
    SaSiError_t ret;
    SaSi_ECDSA_VerifyUserContext_t VerifyUserContext;
    SaSi_ECPKI_UserPublKey_t UserPublKey = {0};
    SaSi_ECPKI_PublKey_trans_t *pPublKey = NULL;
    struct SaSi_ECPKI_PublKey_t *rPublKey = NULL;

    if (pUserPublKey == NULL) {
        tloge("invalid params\n");
        return -1;
    }

    UserPublKey.valid_tag = SaSi_ECPKI_PUBL_KEY_VALIDATION_TAG;
    rPublKey = (struct SaSi_ECPKI_PublKey_t *)&UserPublKey.PublKeyDbBuff;
    pPublKey = (SaSi_ECPKI_PublKey_trans_t *)&pUserPublKey->PublKeyDbBuff;

    if (EOK != memcpy_s(rPublKey,
                        SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t),
                        pPublKey,
                        SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t))) {
        tloge("memcpy_s failed\n");
        return -1;
    }
    if (EOK != memcpy_s(&rPublKey->domain, sizeof(SaSi_ECPKI_Domain_t),
                        SaSi_ECPKI_GetEcDomain(pPublKey->DomainID),
                        sizeof(SaSi_ECPKI_Domain_t))) {
        tloge("memcpy_s failed\n");
        return -1;
    }

    DX_Clock_Init();
    ret = SaSi_ECDSA_Verify_MTK(&VerifyUserContext,
                                &UserPublKey,
                                hashMode,
                                pSignatureIn,
                                SignatureSizeBytes,
                                pMessageDataIn,
                                messageSizeInBytes);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_RSA_Build_PubKey(SaSi_RSAUserPubKey_t *UserPubKey_ptr,
                                  uint8_t *Exponent_ptr,
                                  uint16_t ExponentSize,
                                  uint8_t *Modulus_ptr,
                                  uint16_t ModulusSize)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_RSA_Build_PubKey_MTK(UserPubKey_ptr,
                                    Exponent_ptr,
                                    ExponentSize,
                                    Modulus_ptr,
                                    ModulusSize);
    DX_Clock_Uninit();
    return ret;
}


SaSiError_t _DX_RSA_Verify(SaSi_RSAPubUserContext_t *UserContext_ptr,
                           SaSi_RSAUserPubKey_t *UserPubKey_ptr,
                           SaSi_RSA_HASH_OpMode_t hashFunc,
                           SaSi_PKCS1_MGF_t MGF,
                           uint16_t SaltLen,
                           uint8_t     *DataIn_ptr,
                           uint32_t     DataInSize,
                           uint8_t     *Sig_ptr,
                           SaSi_PKCS1_version PKCS1_ver)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_RsaVerify(UserContext_ptr,
                         UserPubKey_ptr,
                         hashFunc,
                         MGF,
                         SaltLen,
                         DataIn_ptr,
                         DataInSize,
                         Sig_ptr,
                         PKCS1_ver);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_KDF_KeyDerivFunc(uint8_t                *ZZSecret_ptr,
                                  uint32_t                ZZSecretSize,
                                  SaSi_KDF_OtherInfo_t     *OtherInfo_ptr,
                                  SaSi_KDF_HASH_OpMode_t    KDFhashMode,
                                  SaSi_KDF_DerivFuncMode_t  derivation_mode,
                                  uint8_t                *KeyingData_ptr,
                                  uint32_t                KeyingDataSizeBytes)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_KDF_KeyDerivFunc_MTK(ZZSecret_ptr,
                                    ZZSecretSize,
                                    OtherInfo_ptr,
                                    KDFhashMode,
                                    derivation_mode,
                                    KeyingData_ptr,
                                    KeyingDataSizeBytes);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t _DX_RSA_SCHEMES_Encrypt(
                        SaSi_RSAUserPubKey_t  *UserPubKey_ptr,
                        SaSi_RSAPrimeData_t   *PrimeData_ptr,
                        SaSi_RSA_HASH_OpMode_t hashFunc,
                        uint8_t  *L,
                        uint16_t  Llen,
                        SaSi_PKCS1_MGF_t MGF,
                        uint8_t   *DataIn_ptr,
                        uint16_t   DataInSize,
                        uint8_t   *Output_ptr,
                        SaSi_PKCS1_version  PKCS1_ver)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_RsaSchemesEncrypt(&g_rnd_context_ptr,
                                 UserPubKey_ptr,
                                 PrimeData_ptr,
                                 hashFunc,
                                 L,
                                 Llen,
                                 MGF,
                                 DataIn_ptr,
                                 DataInSize,
                                 Output_ptr,
                                 PKCS1_ver);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_RSA_PRIM_Decrypt(SaSi_RSAUserPrivKey_t *UserPrivKey_ptr,
                                  SaSi_RSAPrimeData_t   *PrimeData_ptr,
                                  uint8_t     *Data_ptr,
                                  uint16_t     DataSize,
                                  uint8_t     *Output_ptr)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_RSA_PRIM_Decrypt_MTK(UserPrivKey_ptr,
                                    PrimeData_ptr,
                                    Data_ptr,
                                    DataSize,
                                    Output_ptr);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_ECDH_SVDP_DH(
        SaSi_ECPKI_UserPublKey_trans_t *PartnerPublKey_ptr, /* in */
        SaSi_ECPKI_UserPrivKey_trans_t *UserPrivKey_ptr,    /* in */
        uint8_t *SharedSecretValue_ptr,     /* out */
        uint32_t *SharedSecrValSize_ptr,    /* in/out */
        SaSi_ECDH_TempData_t *TempBuff_ptr) /* in */
{
    (void)TempBuff_ptr;
    SaSi_ECPKI_UserPublKey_t PartnerPublKey = {0};
    SaSi_ECPKI_UserPrivKey_t UserPrivKey = {0};
    SaSi_ECDH_TempData_t TempBuff = {0};

    if ((PartnerPublKey_ptr == NULL) || (UserPrivKey_ptr == NULL)) {
        tloge("invalid params\n");
        return -1;
    }

    struct SaSi_ECPKI_PublKey_t *rPublKey = (struct SaSi_ECPKI_PublKey_t *)&PartnerPublKey.PublKeyDbBuff;
    SaSi_ECPKI_PublKey_trans_t *pPublKey = (SaSi_ECPKI_PublKey_trans_t *)&PartnerPublKey_ptr->PublKeyDbBuff;

    PartnerPublKey.valid_tag = SaSi_ECPKI_PUBL_KEY_VALIDATION_TAG;
    if (memcpy_s(rPublKey, SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t),
                 pPublKey, SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t)) != EOK) {
        tloge("memcpy failed\n");
        return -1;
    }
    if (memcpy_s(&rPublKey->domain, sizeof(SaSi_ECPKI_Domain_t),
                 SaSi_ECPKI_GetEcDomain(pPublKey->DomainID), sizeof(SaSi_ECPKI_Domain_t)) != EOK) {
        tloge("memcpy failed\n");
        return -1;
    }

    SaSi_ECPKI_PrivKey_t *rPrivKey = (SaSi_ECPKI_PrivKey_t *)&UserPrivKey.PrivKeyDbBuff;
    SaSi_ECPKI_PrivKey_trans_t *pPrivKey = (SaSi_ECPKI_PrivKey_trans_t *)&UserPrivKey_ptr->PrivKeyDbBuff;

    UserPrivKey.valid_tag = SaSi_ECPKI_PRIV_KEY_VALIDATION_TAG;
    if (EOK != memcpy_s(rPrivKey, (SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1) * sizeof(uint32_t),
                        pPrivKey, (SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1) * sizeof(uint32_t))) {
        tloge("memcpy_s failed\n");
        return -1;
    }

    if (EOK != memcpy_s(&rPrivKey->domain, sizeof(SaSi_ECPKI_Domain_t),
                        SaSi_ECPKI_GetEcDomain(pPrivKey->DomainID), sizeof(SaSi_ECPKI_Domain_t))) {
        tloge("memcpy_s failed\n");
        return -1;
    }

    DX_Clock_Init();
    SaSiError_t ret = SaSi_ECDH_SVDP_DH_MTK(&PartnerPublKey, &UserPrivKey,
                                            SharedSecretValue_ptr, SharedSecrValSize_ptr, &TempBuff);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_RSA_PRIM_Encrypt(SaSi_RSAUserPubKey_t *UserPubKey_ptr,
                                  SaSi_RSAPrimeData_t  *PrimeData_ptr,
                                  uint8_t              *Data_ptr,
                                  uint16_t              DataSize,
                                  uint8_t              *Output_ptr)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_RSA_PRIM_Encrypt_MTK(UserPubKey_ptr,
                                    PrimeData_ptr,
                                    Data_ptr,
                                    DataSize,
                                    Output_ptr);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_RSA_KG_GenerateKeyPair(uint8_t             *pubExp_ptr,
                                        uint16_t             pubExpSizeInBytes,
                                        uint32_t             keySize,
                                        SaSi_RSAUserPrivKey_t *userPrivKey_ptr,
                                        SaSi_RSAUserPubKey_t  *userPubKey_ptr,
                                        SaSi_RSAKGData_t      *keyGenData_ptr)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_RSA_KG_GenerateKeyPair_MTK(&g_rnd_context_ptr,
                                          pubExp_ptr,
                                          pubExpSizeInBytes,
                                          keySize,
                                          userPrivKey_ptr,
                                          userPubKey_ptr,
                                          keyGenData_ptr,
                                          NULL);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_RSA_Build_PrivKey(SaSi_RSAUserPrivKey_t   *UserPrivKey_ptr,
                                   uint8_t               *PrivExponent_ptr,
                                   uint16_t               PrivExponentSize,
                                   uint8_t               *PubExponent_ptr,
                                   uint16_t               PubExponentSize,
                                   uint8_t               *Modulus_ptr,
                                   uint16_t               ModulusSize)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_RSA_Build_PrivKey_MTK(
        UserPrivKey_ptr,
        PrivExponent_ptr,
        PrivExponentSize,
        PubExponent_ptr,
        PubExponentSize,
        Modulus_ptr,
        ModulusSize);
    DX_Clock_Uninit();
    return ret;
}

SaSiError_t CRYS_RSA_Build_PrivKeyCRT(SaSi_RSAUserPrivKey_t *UserPrivKey_ptr,
                                      uint8_t *P_ptr,
                                      uint16_t PSize,
                                      uint8_t *Q_ptr,
                                      uint16_t QSize,
                                      uint8_t *dP_ptr,
                                      uint16_t dPSize,
                                      uint8_t *dQ_ptr,
                                      uint16_t dQSize,
                                      uint8_t *qInv_ptr,
                                      uint16_t qInvSize)
{
    SaSiError_t ret;
    DX_Clock_Init();
    ret = SaSi_RSA_Build_PrivKeyCRT_MTK(UserPrivKey_ptr,
                                        P_ptr,
                                        PSize,
                                        Q_ptr,
                                        QSize,
                                        dP_ptr,
                                        dPSize,
                                        dQ_ptr,
                                        dQSize,
                                        qInv_ptr,
                                        qInvSize);
    DX_Clock_Uninit();
    return ret;
}
