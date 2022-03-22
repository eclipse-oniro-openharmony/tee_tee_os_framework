/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: cc driver implementation
 * Author: Dizhe Mao maodizhe1@huawei.com
 * Create: 2018-05-18
 */
#include "cc_adapt.h"
#include <legacy_mem_ext.h> // SRE_MemAlloc
#include <mem_ops.h>
#include "securec.h"
#include "sre_log.h"
#include "cc_lib.h"
#include "cc_ecpki_build.h"
#include "cc_ecpki_domain.h"
#include "cc_ecpki_kg.h"
#include <cc_ecpki_ecdsa.h>
#include <ec_wrst/cc_ecpki_local.h>
#include "cc_ecpki_dh.h"

#define BUFFER_4k_SIZE 4096
#define BUFFER_16_SIZE 16
#define BUFFER_16_COUNT 256
#define STORE_IN_PAIR     2

CCRndContext_t g_rnd_context_ptr;
CCRndWorkBuff_t g_rnd_workbuff_ptr = {0};
static uint8_t g_vectors[BUFFER_4k_SIZE] = {0};
static unsigned int g_get_vector_count = BUFFER_16_COUNT;

CCRndContext_t *get_rnd_context_ptr(void)
{
    return &g_rnd_context_ptr;
}
CCRndWorkBuff_t *get_rnd_workbuff_ptr(void)
{
    return &g_rnd_workbuff_ptr;
}

static CCError_t CRYS_RND_GenerateVector_tmp(
    /* !< [in] The size in bytes of the random vector required. The maximal size is 2^16 -1 bytes. */
    size_t    outSizeBytes,
    /* !< [out] The pointer to output buffer. */
    uint8_t   *out_ptr)
{
    CCError_t ret;

    if (out_ptr == NULL) {
        tloge("out_ptr error\n");
        return -1;
    }

    ret = CC_RndGenerateVector(
        &g_rnd_context_ptr.rndState,
        outSizeBytes,
        out_ptr);

    return ret;
}

static CCError_t get_4k_vector(void)
{
    CCError_t ret;
    ret = CRYS_RND_GenerateVector_tmp(sizeof(g_vectors), g_vectors);
    if (ret != 0) {
        tloge("CRYS_RND failed\n");
        return ret;
    }

    g_get_vector_count = 0;
    return 0;
}

CCError_t CRYS_RND_GenerateVector(
    /* !< [in] The size in bytes of the random vector required. The maximal size is 2^16 -1 bytes. */
    size_t    outSizeBytes,
    /* !< [out]out_ptr: The pointer to output buffer. */
    uint8_t   *out_ptr)
{
    int res;
    CCError_t ret;
    unsigned int write_count;
    unsigned int left_size = (unsigned int)outSizeBytes;
    if (out_ptr == NULL) {
        tloge("out_ptr error\n");
        return -1;
    }
    if (outSizeBytes >= BUFFER_4k_SIZE) {
        ret = CRYS_RND_GenerateVector_tmp(outSizeBytes, out_ptr);
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
                   BUFFER_4k_SIZE - g_get_vector_count * BUFFER_16_SIZE, 0, left_size);
    if (res != EOK) {
        tloge("memset g_vectors failed\n");
        return -1;
    }
    g_get_vector_count += write_count;
    return 0;
}

CCError_t CRYS_HASH_Init(
    /* !< [in]  Pointer to the HASH context buffer allocated by the user that is used for the HASH machine operation. */
    CCHashUserContext_t     *ContextID_ptr,
    /* !< [in]  One of the supported HASH modes, as defined in CCHashOperationMode_t. */
    CCHashOperationMode_t  OperationMode)
{
    CCError_t ret;
    ret = CC_HashInit(ContextID_ptr, OperationMode);
    return ret;
}

CCError_t CRYS_HASH_Free(CCHashUserContext_t *ContextID_ptr)
{
    CCError_t ret;
    ret = CC_HashFree(ContextID_ptr);
    return ret;
}

CCError_t CRYS_HASH_Update(
    CCHashUserContext_t      *ContextID_ptr,
    uint8_t                  *DataIn_ptr,
    size_t                   DataInSize)
{
    CCError_t ret;

    ret = CC_HashUpdate(ContextID_ptr,
                        DataIn_ptr,
                        DataInSize);
    return ret;
}

CCError_t CRYS_HASH_Finish(CCHashUserContext_t *ContextID_ptr,
    CCHashResultBuf_t   HashResultBuff)
{
    CCError_t ret;

    ret = CC_HashFinish(ContextID_ptr, HashResultBuff);

    return ret;
}

CCUtilError_t DX_UTIL_CmacDeriveKey(UtilKeyType_t           keyType,
                                    uint8_t                 *pDataIn,
                                    size_t                  dataInSize,
                                    CCUtilAesCmacResult_t   pCmacResult)
{
    CCUtilError_t ret;

    ret = UtilCmacDeriveKey(keyType, NULL, pDataIn, dataInSize, pCmacResult);

    return ret;
}

CCUtilError_t DX_UTIL_UserDeriveKey(UtilKeyType_t           keyType,
                                    CCAesUserKeyData_t      *pUserKey,
                                    uint8_t                 *pDataIn,
                                    size_t                  dataInSize,
                                    CCUtilAesCmacResult_t   pCmacResult)
{
    CCUtilError_t ret;

    ret = UtilCmacDeriveKey(keyType, pUserKey, pDataIn, dataInSize, pCmacResult);

    return ret;
}

CCError_t _DX_ECPKI_BuildPublKey(
    CCEcpkiDomainID_t  DomainID,            /* in */
    uint8_t                     *pPubKeyIn,         /* in */
    size_t                      publKeySizeInBytes, /* in */
    ECPublKeyCheckMode_t        checkMode,          /* in */
    CCEcpkiUserPublKey_t    *pUserPublKey,       /* out */
    CCEcpkiBuildTempData_t *tempBuff           /* in */)
{
    CCError_t ret;
    CCEcpkiUserPublKey_t UserPublKey = {0};
    CCEcpkiBuildTempData_t ptempBuff;
    CCEcpkiPublKey_t *rPublKey = NULL;
    CCEcpkiPublKey_trans_t *pPublKey = NULL;
    (void)tempBuff;

    if (pUserPublKey == NULL) {
        tloge("invalid pUserPublKey\n");
        return -1;
    }

    pPublKey = (CCEcpkiPublKey_trans_t *)&pUserPublKey->PublKeyDbBuff;
    rPublKey = (CCEcpkiPublKey_t *)&UserPublKey.PublKeyDbBuff;

    if (CC_EcpkiGetEcDomain(DomainID) == NULL) {
        tloge("invalid params\n");
        return -1;
    }

    ret = CC_EcpkiPublKeyBuildAndCheck(CC_EcpkiGetEcDomain(DomainID),
                                       pPubKeyIn,
                                       publKeySizeInBytes,
                                       checkMode,
                                       &UserPublKey,
                                       &ptempBuff);
    if (EOK != memcpy_s(pPublKey,
                        CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t),
                        rPublKey,
                        CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t))) {
        tloge("memcpy_s failed\n");
        ret = -1;
    }
    pPublKey->DomainID = rPublKey->domain.DomainID;
    (void)memset_s(&UserPublKey, sizeof(CCEcpkiUserPublKey_t), 0, sizeof(CCEcpkiUserPublKey_t));

    (void)memset_s(&UserPublKey, sizeof(CCEcpkiUserPublKey_t), 0, sizeof(CCEcpkiUserPublKey_t));

    (void)memset_s(&ptempBuff, sizeof(CCEcpkiBuildTempData_t), 0, sizeof(CCEcpkiBuildTempData_t));

    rPublKey = NULL;
    pPublKey = NULL;
    return ret;
}

CCError_t CRYS_ECPKI_GenKeyPair(
    CCEcpkiDomainID_t       DomainID,           /* in */
    CCEcpkiUserPrivKey_trans_t   *pUserPrivKey, /* out */
    CCEcpkiUserPublKey_trans_t   *pUserPublKey, /* out */
    CCEcpkiKgTempData_t   *pTempBuff    /* in */)
{
    CCError_t ret;
    CCEcpkiUserPrivKey_t UserPrivKey = {0};
    CCEcpkiUserPublKey_t UserPublKey = {0};
    CCEcpkiPrivKey_t *rPrivKey = NULL;
    CCEcpkiPublKey_t *rPublKey = NULL;
    CCEcpkiPrivKey_trans_t *pPrivKey = NULL;
    CCEcpkiPublKey_trans_t *pPublKey = NULL;
    (void)pTempBuff;

    if ((pUserPrivKey == NULL) || (pUserPublKey == NULL)) {
        tloge("invalid params\n");
        return -1;
    }

    CCEcpkiKgTempData_t *TempBuff = (CCEcpkiKgTempData_t *)SRE_MemAlloc(0, 0, sizeof(CCEcpkiKgTempData_t));
    if (!TempBuff) {
        tloge("malloc TempBuff failed\n");
        return -1;
    }

    if (CC_EcpkiGetEcDomain(DomainID) == NULL) {
        (void)SRE_MemFree(0, TempBuff);
        tloge("invalid params\n");
        return -1;
    }

    ret = CC_EcpkiKeyPairGenerate(&g_rnd_context_ptr,
                                  CC_EcpkiGetEcDomain(DomainID),
                                  &UserPrivKey,
                                  &UserPublKey,
                                  TempBuff,
                                  NULL);
    /* copy data to user */
    rPrivKey = (CCEcpkiPrivKey_t *)&UserPrivKey.PrivKeyDbBuff;
    pPrivKey = (CCEcpkiPrivKey_trans_t *)&pUserPrivKey->PrivKeyDbBuff;
    if (EOK != memcpy_s(pPrivKey->PrivKey,
                        (CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1) * sizeof(uint32_t),
                        rPrivKey->PrivKey,
                        (CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1) * sizeof(uint32_t))) {
        tloge("memcpy_s failed\n");
        (void)SRE_MemFree(0, TempBuff);
        return -1;
    }
    pPrivKey->DomainID = rPrivKey->domain.DomainID;

    rPublKey = (CCEcpkiPublKey_t *)&UserPublKey.PublKeyDbBuff;
    pPublKey = (CCEcpkiPublKey_trans_t *)pUserPublKey->PublKeyDbBuff;
    if (EOK != memcpy_s(pPublKey,
                        CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t),
                        rPublKey,
                        CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t))) {
        tloge("memcpy_s failed\n");
        (void)SRE_MemFree(0, TempBuff);
        return -1;
    }
    pPublKey->DomainID = rPublKey->domain.DomainID;
    rPrivKey = NULL;
    rPublKey = NULL;
    pPrivKey = NULL;
    pPublKey = NULL;
    (void)memset_s(TempBuff, sizeof(CCEcpkiKgTempData_t), 0, sizeof(CCEcpkiKgTempData_t));
    (void)SRE_MemFree(0, TempBuff);
    return ret;
}

CCError_t CRYS_ECPKI_ExportPublKey(
    CCEcpkiUserPublKey_trans_t      *pUserPublKey,       /* in */
    CCEcpkiPointCompression_t  compression,        /* in */
    uint8_t                       *pExportPublKey,     /* in */
    size_t                        *pPublKeySizeBytes   /* in/out */)
{
    CCError_t ret;

    CCEcpkiUserPublKey_t UserPublKey = {0};
    CCEcpkiPublKey_t *rPublKey = NULL;
    CCEcpkiPublKey_trans_t *pPublKey = NULL;

    if (pUserPublKey == NULL) {
        tloge("invalid params\n");
        return -1;
    }
    pPublKey = (CCEcpkiPublKey_trans_t *)&pUserPublKey->PublKeyDbBuff;
    rPublKey = (CCEcpkiPublKey_t *)&UserPublKey.PublKeyDbBuff;
    if (EOK != memcpy_s(rPublKey,
                        CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t),
                        pPublKey,
                        CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t))) {
        tloge("memcpy_s failed\n");
        return -1;
    }

    if (CC_EcpkiGetEcDomain(pPublKey->DomainID) == NULL) {
        tloge("invalid params\n");
        return -1;
    }

    if (EOK != memcpy_s(&rPublKey->domain,
                        sizeof(CCEcpkiDomain_t),
                        CC_EcpkiGetEcDomain(pPublKey->DomainID),
                        sizeof(CCEcpkiDomain_t))) {
        tloge("memcpy_s failed\n");
        return -1;
    }
    UserPublKey.valid_tag = CC_ECPKI_PUBL_KEY_VALIDATION_TAG;

    ret = CC_EcpkiPubKeyExport(&UserPublKey,
                               compression,
                               pExportPublKey,
                               pPublKeySizeBytes);
    rPublKey = NULL;
    pPublKey = NULL;
    (void)memset_s(&UserPublKey, sizeof(CCEcpkiUserPublKey_t), 0, sizeof(CCEcpkiUserPublKey_t));

    return ret;
}

CCError_t CRYS_ECPKI_BuildPrivKey(
    CCEcpkiDomainID_t      DomainID,          /* in */
    const uint8_t             *pPrivKeyIn,     /* in */
    size_t                    privKeySizeInBytes, /* in */
    CCEcpkiUserPrivKey_trans_t  *pUserPrivKey    /* out */)
{
    CCError_t ret;
    CCEcpkiUserPrivKey_t UserPrivKey = {0};
    CCEcpkiPrivKey_trans_t *pPrivKey = NULL;
    CCEcpkiPrivKey_t *rPrivKey = NULL;

    if (pUserPrivKey == NULL) {
        tloge("invalid params\n");
        return -1;
    }
    if (CC_EcpkiGetEcDomain(DomainID) == NULL) {
        tloge("invalid params\n");
        return -1;
    }

    ret = CC_EcpkiPrivKeyBuild(CC_EcpkiGetEcDomain(DomainID),
                               pPrivKeyIn,
                               privKeySizeInBytes,
                               &UserPrivKey);
    pPrivKey = (CCEcpkiPrivKey_trans_t *)&pUserPrivKey->PrivKeyDbBuff;
    rPrivKey = (CCEcpkiPrivKey_t *)&UserPrivKey.PrivKeyDbBuff;
    if (EOK != memcpy_s(pPrivKey->PrivKey,
                        (CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1) * sizeof(uint32_t),
                        rPrivKey->PrivKey,
                        (CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1) * sizeof(uint32_t))) {
        tloge("memcpy_s failed\n");
        return -1;
    }
    pPrivKey->DomainID = rPrivKey->domain.DomainID;
    pPrivKey = NULL;
    rPrivKey = NULL;
    (void)memset_s(&UserPrivKey, sizeof(CCEcpkiUserPrivKey_t), 0, sizeof(CCEcpkiUserPrivKey_t));

    return ret;
}

CCError_t CRYS_ECDH_SVDP_DH(
    CCEcpkiUserPublKey_trans_t *PartnerPublKey_ptr,        /* in */
    CCEcpkiUserPrivKey_trans_t *UserPrivKey_ptr,           /* in */
    uint8_t                  *SharedSecretValue_ptr,     /* out */
    size_t                   *SharedSecrValSize_ptr,     /* in/out */
    CCEcdhTempData_t     *TempBuff_ptr               /* in */)
{
    CCError_t ret;
    CCEcpkiUserPublKey_t PartnerPublKey = {0};
    CCEcpkiUserPrivKey_t UserPrivKey = {0};
    CCEcdhTempData_t TempBuff = {0};
    (void)TempBuff_ptr;

    CCEcpkiPublKey_t *rPublKey = NULL;
    CCEcpkiPublKey_trans_t *pPublKey = NULL;

    CCEcpkiPrivKey_t *rPrivKey = NULL;
    CCEcpkiPrivKey_trans_t *pPrivKey = NULL;

    if ((PartnerPublKey_ptr == NULL) || (UserPrivKey_ptr == NULL)) {
        tloge("invalid params\n");
        return -1;
    }

    rPublKey = (CCEcpkiPublKey_t *)&PartnerPublKey.PublKeyDbBuff;
    pPublKey = (CCEcpkiPublKey_trans_t *)&PartnerPublKey_ptr->PublKeyDbBuff;

    PartnerPublKey.valid_tag = CC_ECPKI_PUBL_KEY_VALIDATION_TAG;
    if (EOK != memcpy_s(rPublKey,
                        CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t),
                        pPublKey,
                        CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * STORE_IN_PAIR * sizeof(uint32_t))) {
        tloge("memcpy_s failed\n");
        return -1;
    }

    if (CC_EcpkiGetEcDomain(pPublKey->DomainID) == NULL) {
        tloge("invalid params\n");
        return -1;
    }

    if (EOK != memcpy_s(&rPublKey->domain,
                        sizeof(CCEcpkiDomain_t),
                        CC_EcpkiGetEcDomain(pPublKey->DomainID),
                        sizeof(CCEcpkiDomain_t))) {
        tloge("memcpy_s failed\n");
        return -1;
    }

    rPrivKey = (CCEcpkiPrivKey_t *)&UserPrivKey.PrivKeyDbBuff;
    pPrivKey = (CCEcpkiPrivKey_trans_t *)&UserPrivKey_ptr->PrivKeyDbBuff;

    UserPrivKey.valid_tag = CC_ECPKI_PRIV_KEY_VALIDATION_TAG;
    if (EOK != memcpy_s(rPrivKey,
                        (CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1) * sizeof(uint32_t),
                        pPrivKey,
                        (CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1) * sizeof(uint32_t))) {
        tloge("memcpy_s failed\n");
        return -1;
    }

    if (CC_EcpkiGetEcDomain(pPrivKey->DomainID) == NULL) {
        tloge("invalid params\n");
        return -1;
    }

    if (EOK != memcpy_s(&rPrivKey->domain,
                        sizeof(CCEcpkiDomain_t),
                        CC_EcpkiGetEcDomain(pPrivKey->DomainID),
                        sizeof(CCEcpkiDomain_t))) {
        tloge("memcpy_s failed\n");
        return -1;
    }

    ret = CC_EcdhSvdpDh(&PartnerPublKey,
                        &UserPrivKey,
                        SharedSecretValue_ptr,
                        SharedSecrValSize_ptr,
                        &TempBuff);

    rPublKey = NULL;
    pPublKey = NULL;
    rPrivKey = NULL;
    pPrivKey = NULL;
    (void)memset_s(&PartnerPublKey, sizeof(CCEcpkiUserPublKey_t), 0, sizeof(CCEcpkiUserPublKey_t));
    (void)memset_s(&UserPrivKey, sizeof(CCEcpkiUserPrivKey_t), 0, sizeof(CCEcpkiUserPrivKey_t));
    (void)memset_s(&TempBuff, sizeof(CCEcdhTempData_t), 0, sizeof(CCEcdhTempData_t));

    return ret;
}
