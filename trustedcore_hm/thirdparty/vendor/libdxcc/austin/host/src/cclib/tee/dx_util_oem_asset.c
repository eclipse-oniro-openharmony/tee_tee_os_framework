/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

/* ************ Include Files ************** */
#include "dx_pal_types.h"
#include "dx_pal_mem.h"
#include "dx_util.h"
#include "dx_util_defs.h"
#include "dx_error.h"
#include "crys_context_relocation.h"
#include "crys_aes.h"
#include "crys_aesccm.h"
#include "dx_util_oem_asset.h"
#include "dx_util_oem_asset_defs.h"
#include "dx_hal_plat.h"
#include "dx_cc_regs.h"
#include "dx_pal_mutex.h"
#include "dx_pal_abort.h"

/* device LCS */
#define OEM_ASSET_CHIP_MANUFACTURE_LCS   0x0
#define OEM_ASSET_DEVICE_MANUFACTURE_LCS 0x1
#define OEM_ASSET_SECURE_DISABLE_LCS     0x3
#define OEM_ASSET_SECURE_LCS             0x5

/* Check if secure LCS register */
#define DX_UTIL_IS_SEC_LCS(rc)                                                                \
    do {                                                                                      \
        rc = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, LCS_REG));                      \
        rc = (rc >> DX_LCS_REG_LCS_REG_BIT_SHIFT) & ((1 << DX_LCS_REG_LCS_REG_BIT_SIZE) - 1); \
        rc = (rc == OEM_ASSET_SECURE_LCS) ? DX_TRUE : DX_FALSE;                               \
    } while (0)

extern DX_PAL_MUTEX dxSymCryptoMutex;

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
 * @return DX_UTIL_OK on success, otherwise failure
 */
DxUTILError_t DX_UTIL_OemAssetUnpack(DX_UTIL_OemKey_t pOemKey, uint32_t assetId, uint8_t *pAssetPackage,
                                     uint32_t assetPackageLen, uint8_t *pAssetData, uint32_t *pAssetDataLen,
                                     uint32_t *pUserData)
{
    uint32_t rc                                            = 0;
    uint8_t keyProv[DX_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES] = { 0 };
    uint8_t dataIn[OEM_ASSET_DATA_IN_CMAC_LENGTH]          = { 0 };
    uint8_t i                                              = 0;
    uint32_t enAssetDataSize                               = 0;
    uint32_t assetMacOffset                                = 0;
    uint32_t tmpWord;

    /* check parameters validity */
    if ((pAssetData == NULL) || (pAssetDataLen == NULL)) {
        return DX_UTIL_DATA_OUT_POINTER_INVALID_ERROR;
    }

    if ((pOemKey == NULL) || (pAssetPackage == NULL)) {
        return DX_UTIL_DATA_IN_POINTER_INVALID_ERROR;
    }
    if (assetId == 0) {
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    /* make sure asster data buffer length allocated by user is big enough */
    CONVERT_BYTE_ARR_TO_WORD(&pAssetPackage[ASSET_PKG_EN_DATA_SIZE_OFFSET], enAssetDataSize);
    if ((assetPackageLen < ASSET_PKG_NONE_ASSET_DATA_SIZE + enAssetDataSize) || (*pAssetDataLen < enAssetDataSize)) {
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    rc = DX_PAL_MutexLock(&dxSymCryptoMutex, DX_INFINITE);
    if (rc != DX_SUCCESS) {
        DX_PAL_Abort("Fail to acquire mutex\n");
    }
    /* check LCS */
    DX_UTIL_IS_SEC_LCS(rc);
    if (rc != DX_TRUE) {
        rc = DX_PAL_MutexUnlock(&dxSymCryptoMutex);
        if (rc != DX_SUCCESS) {
            DX_PAL_Abort("Fail to release mutex\n");
        }
        return DX_UTIL_LCS_INVALID_ERROR;
    }
    rc = DX_PAL_MutexUnlock(&dxSymCryptoMutex);
    if (rc != DX_SUCCESS) {
        DX_PAL_Abort("Fail to release mutex\n");
    }

    /* check Token and Version */
    CONVERT_BYTE_ARR_TO_WORD(&pAssetPackage[ASSET_PKG_TOKEN_OFFSET], tmpWord);
    if ((unsigned int)OEM_ASSET_PACK_TOKEN != tmpWord) {
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    }
    CONVERT_BYTE_ARR_TO_WORD(&pAssetPackage[ASSET_PKG_VERSION_SIZE], tmpWord);
    if ((unsigned int)OEM_ASSET_VERSION != tmpWord) {
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    /* 1. derive a specific key KPROV = AES-CMAC (KOEM, 0x01 || 0x50 || 0x00 || asset_id || 0x80) */
    i           = 0;
    dataIn[i++] = KOEM_DATA_IN_PREFIX_DATA0;
    dataIn[i++] = KOEM_DATA_IN_PREFIX_DATA1;
    dataIn[i++] = KOEM_DATA_IN_PREFIX_DATA2;
    /* add asset ID */
    CONVERT_WORD_TO_BYTE_ARR(assetId, (unsigned char *)&dataIn[i]);
    i += sizeof(uint32_t);
    dataIn[i] = KOEM_DATA_IN_SUFIX_DATA;

    rc = CRYS_AES(NULL, pOemKey, CRYS_AES_Key128BitSize, CRYS_AES_Encrypt, CRYS_AES_CMAC_mode, dataIn, sizeof(dataIn),
                  &keyProv[0]);
    if (rc != 0) {
        return rc;
    }

    /* 2. uses previous key generated in 1 to decrypt the Asset data within asset buffer using AES-CCM */
    assetMacOffset = ASSET_PKG_EN_DATA_OFFSET + enAssetDataSize;
    rc = CRYS_AESCCM(CRYS_AES_Decrypt, keyProv, CRYS_AES_Key128BitSize, &(pAssetPackage[ASSET_PKG_CCM_NONCE_OFFSET]),
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
