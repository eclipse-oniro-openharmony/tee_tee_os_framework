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
#include "ssi_util_defs.h"
#include "ssi_util_cmac.h"
#include "ssi_pal_mutex.h"
#include "ssi_pal_abort.h"
#include "sym_adaptor_driver.h"
#include "ssi_util_error.h"
#include "ssi_error.h"
#include "sasi_context_relocation.h"
#include "sasi_common.h"
#include "sasi_common_math.h"
#include "sasi_rnd.h"
#include "sasi_rnd_error.h"
#include "ssi_hal.h"

/* !
 * Converts Symmetric Adaptor return code to SaSi error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return SaSiError_t one of SaSi_* error codes defined in sasi_error.h
 */
static SaSiUtilError_t SymAdaptor2CmacDeriveKeyErr(int symRetCode)
{
    switch (symRetCode) {
    case SASI_RET_INVARG:
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    case SASI_RET_INVARG_BAD_ADDR:
        return SASI_UTIL_BAD_ADDR_ERROR;
    case SASI_RET_INVARG_CTX:
    case SASI_RET_UNSUPP_ALG:
    default:
        return SASI_UTIL_FATAL_ERROR;
    }
}

/* ********************************************************************************* */
/* ***************         CMAC key derivation    ********************************** */
/* ********************************************************************************* */

SaSiUtilError_t SaSi_UtilCmacDeriveKey(SaSiUtilKeyType_t keyType, SaSiAesUserKeyData_t *pUserKey, uint8_t *pDataIn,
                                       size_t dataInSize, SaSiUtilAesCmacResult_t pCmacResult)
{
    int symRc;
    uint32_t kdrError = 0;
    uint32_t ctxBuff[SASI_UTIL_BUFF_IN_WORDS];

    struct drv_ctx_cipher *pAesContext = (struct drv_ctx_cipher *)SaSi_InitUserCtxLocation(
        ctxBuff, SASI_UTIL_BUFF_IN_BYTES, sizeof(struct drv_ctx_cipher));
    if (pAesContext == NULL) {
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    /* Check inputs */
    if (pDataIn == NULL) {
        return SASI_UTIL_DATA_IN_POINTER_INVALID_ERROR;
    }
    if (pCmacResult == NULL) {
        return SASI_UTIL_DATA_OUT_POINTER_INVALID_ERROR;
    }
    if ((dataInSize < SASI_UTIL_CMAC_DERV_MIN_DATA_IN_SIZE) || (dataInSize > SASI_UTIL_CMAC_DERV_MAX_DATA_IN_SIZE)) {
        return SASI_UTIL_DATA_IN_SIZE_INVALID_ERROR;
    }

    switch (keyType) {
    case SASI_UTIL_ROOT_KEY:
        /* Check KDR error bit in LCS register */
        SASI_UTIL_IS_OTP_KDR_ERROR(kdrError);
        if (kdrError != 0)
            return SASI_UTIL_KDR_INVALID_ERROR;

        /* Set AES key to ROOT KEY */
        pAesContext->crypto_key_type = DRV_ROOT_KEY;
        pAesContext->key_size        = SEP_AES_256_BIT_KEY_SIZE;
        break;

    case SASI_UTIL_USER_KEY:
        if ((pUserKey->keySize != SEP_AES_128_BIT_KEY_SIZE) && (pUserKey->keySize != SEP_AES_256_BIT_KEY_SIZE))
            return SASI_UTIL_INVALID_USER_KEY_SIZE;

        /* Set AES key to USER KEY, and copy the key to the context */
        pAesContext->crypto_key_type = DRV_USER_KEY;
        pAesContext->key_size        = pUserKey->keySize;
        SaSi_PalMemCopy(pAesContext->key, pUserKey->pKey, pUserKey->keySize);
        break;
    default:
        return SASI_UTIL_INVALID_KEY_TYPE;
    }

    /* call SaSi_AES_Init with CMAC */
    pAesContext->alg       = DRV_CRYPTO_ALG_AES;
    pAesContext->mode      = SEP_CIPHER_CMAC;
    pAesContext->direction = SEP_CRYPTO_DIRECTION_ENCRYPT;
    SaSi_PalMemSetZero(pAesContext->block_state, SEP_AES_BLOCK_SIZE);

    symRc = SymDriverAdaptorInit((struct drv_ctx_generic *)pAesContext);
    if (symRc != 0) {
        return SymAdaptor2CmacDeriveKeyErr(symRc);
    }

    /* call SaSi_AES_Finish with CMAC:  set the data unit size if first block */
    pAesContext->data_unit_size = dataInSize;
    symRc = SymDriverAdaptorFinalize((struct drv_ctx_generic *)pAesContext, pDataIn, (void *)pCmacResult, dataInSize);

    if (symRc != 0) {
        return SymAdaptor2CmacDeriveKeyErr(symRc);
    }

    return SASI_UTIL_OK;
}
