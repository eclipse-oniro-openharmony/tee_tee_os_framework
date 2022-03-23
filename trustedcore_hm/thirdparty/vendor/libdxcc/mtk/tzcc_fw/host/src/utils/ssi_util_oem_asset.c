/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include "ssi_pal_types.h"
#include "ssi_pal_mem.h"
#include "ssi_util_int_defs.h"
#include "ssi_error.h"
#include "ssi_aes.h"
#include "sasi_aesccm.h"
#include "ssi_util_defs.h"
#include "ssi_util_error.h"
#include "ssi_util_oem_asset_defs.h"
#include "ssi_util_oem_asset.h"
#include "ssi_hal_plat.h"
#include "ssi_regs.h"
#include "ssi_pal_mutex.h"
#include "ssi_pal_abort.h"
#include "ssi_util_key_derivation.h"
#include "sasi_fips_defs.h"

extern SaSi_PalMutex sasiSymCryptoMutex;

/* !
 * @brief The function unpacks the asset packet and return the asster data required by OEM for TEE
 *
 * @param[in] pOemKey       - OEM key computed during boot using the GetProvisioningKey() ROM function
 * @param[in] assetId       - an asset identifier
 * @param[in] pAssetPackage       - a asset package byte-array formatted to unpack
 * @param[in] assetPackageLen   - a asset package length in bytes, must be multiple of 16 bytes
 * @param[out] pAssetData       - the decrypted contents of asset data
 * @param[in/out] pAssetDataLen - as input: the size of the allocated asset data buffer (max size is 512 bytes)
 *                 - as output: the actual size of the decrypted asset data buffer (max size is 512 bytes)
 * @param[out] pUserData       - may be NULL, otherwise the output will hold the user Data within the asset Package in
 * BE format
 *
 * @return SASI_UTIL_OK on success, otherwise failure
 */
SaSiUtilError_t SaSi_UtilOemAssetUnpack(SaSiUtilOemKey_t pOemKey, uint32_t assetId, uint8_t *pAssetPackage,
                                        uint32_t assetPackageLen, uint8_t *pAssetData, uint32_t *pAssetDataLen,
                                        uint32_t *pUserData)
{
    uint32_t rc                                              = 0;
    uint8_t keyProv[SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES] = { 0 };
    SaSiAesUserKeyData_t userKey;
    uint32_t enAssetDataSize = 0;
    uint32_t assetMacOffset  = 0;
    uint32_t tmpWord;

    uint8_t label[] = { KOEM_DATA_IN_PREFIX_DATA1 };
    uint8_t context[4];

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* check parameters validity */
    if ((pAssetData == NULL) || (pAssetDataLen == NULL)) {
        return SASI_UTIL_DATA_OUT_POINTER_INVALID_ERROR;
    }

    if ((pOemKey == NULL) || (pAssetPackage == NULL)) {
        return SASI_UTIL_DATA_IN_POINTER_INVALID_ERROR;
    }
    if (assetId == 0) {
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    /* make sure asster data buffer length allocated by user is big enough */
    CONVERT_BYTE_ARR_TO_WORD(&pAssetPackage[ASSET_PKG_EN_DATA_SIZE_OFFSET], enAssetDataSize);
    if ((assetPackageLen < ASSET_PKG_NONE_ASSET_DATA_SIZE + enAssetDataSize) || (*pAssetDataLen < enAssetDataSize)) {
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    rc = SaSi_PalMutexLock(&sasiSymCryptoMutex, SASI_INFINITE);
    if (rc != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }
    /* check LCS */
    SASI_UTIL_IS_SEC_LCS(rc);
    if (rc != SASI_TRUE) {
        rc = SaSi_PalMutexUnlock(&sasiSymCryptoMutex);
        if (rc != SASI_SUCCESS) {
            SaSi_PalAbort("Fail to release mutex\n");
        }
        return SASI_UTIL_LCS_INVALID_ERROR;
    }
    rc = SaSi_PalMutexUnlock(&sasiSymCryptoMutex);
    if (rc != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to release mutex\n");
    }

    /* check Token and Version */
    CONVERT_BYTE_ARR_TO_WORD(&pAssetPackage[ASSET_PKG_TOKEN_OFFSET], tmpWord);
    if ((unsigned int)OEM_ASSET_PACK_TOKEN != tmpWord) {
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    }
    CONVERT_BYTE_ARR_TO_WORD(&pAssetPackage[ASSET_PKG_VERSION_SIZE], tmpWord);
    if ((unsigned int)OEM_ASSET_VERSION != tmpWord) {
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    /* 1. derive a specific key KPROV = AES-CMAC (KOEM, 0x01 || 0x50 || 0x00 || asset_id || 0x80) */
    CONVERT_WORD_TO_BYTE_ARR(assetId, (unsigned char *)&context[0]);
    userKey.keySize = SASI_UTIL_AES_128BIT_SIZE;
    userKey.pKey    = pOemKey;
    rc              = SaSi_UtilKeyDerivation(SASI_UTIL_USER_KEY, &userKey, (const uint8_t *)&label, sizeof(label),
                                (const uint8_t *)&context, sizeof(context), keyProv,
                                SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES);

    /* 2. uses previous key generated in 1 to decrypt the Asset data within asset buffer using AES-CCM */
    assetMacOffset = ASSET_PKG_EN_DATA_OFFSET + enAssetDataSize;
    rc =
        SaSi_AESCCM_MTK(SASI_AES_DECRYPT, keyProv, SaSi_AES_Key128BitSize, &(pAssetPackage[ASSET_PKG_CCM_NONCE_OFFSET]),
                        ASSET_PKG_CCM_NONCE_SIZE, &(pAssetPackage[ASSET_PKG_CCM_ADDITIONAL_DATA_OFFSET]),
                        ASSET_PKG_CCM_ADDITIONAL_DATA_SIZE, &(pAssetPackage[ASSET_PKG_EN_DATA_OFFSET]), enAssetDataSize,
                        pAssetData, ASSET_PKG_MAC_SIZE, &(pAssetPackage[assetMacOffset]));
    if (rc != 0) {
        return rc;
    }

    if (pUserData != NULL) {
        CONVERT_BYTE_ARR_TO_WORD(&pAssetPackage[ASSET_PKG_USER_DATA_OFFSET], *pUserData);
    }
    *pAssetDataLen = enAssetDataSize;
    return rc;
}
