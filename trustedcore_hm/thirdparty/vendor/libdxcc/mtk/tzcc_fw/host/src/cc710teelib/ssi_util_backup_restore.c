/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_UTILS

/* ************ Include Files ************** */
#include "ssi_pal_log.h"
#include "ssi_pal_types.h"
#include "ssi_pal_mutex.h"
#include "ssi_pal_abort.h"
#include "ssi_util_int_defs.h"
#include "sasi_common.h"
#include "ssi_util_ccm.h"
#include "sasi_fips_defs.h"

#define UTIL_BACKUP_RESTORE_CCM_NONCE_SIZE 8
#define UTIL_BACKUP_RESTORE_CCM_TAG_SIZE   16

#define BLOCK_SIZE_LIMIT 0xFFFF

extern SaSi_PalMutex sasiSymCryptoMutex;

/* !
 * This function backup/restore on-chip secure RAM to/from external DRAM:
 * It encrypts/decrypts the provided block (using the always-on state counter to construct the AES-CCM nonce);
 * Also, computes AES-CCM signature, and appends/verifiys the signature.
 *
 * @param[in] pSrcBuff        - input Host memory buffer.
 * @param[in] pDstBuff        - output Host mamory buffer.
 * @param[in] blockSize     - number of bytes to process, not including ccm tag
 * @param[in] isSramBackup     - if TRUE, SRAM backup; else, SRAM restore
 *
 *
 * @return SaSiError_t         - On success: the value SASI_OK is returned,
 *                       On failure: a value from ssi_util_error.h
 *
 */

SaSiError_t SaSi_UtilBackupAndRestore(uint8_t *pSrcBuff, uint8_t *pDstBuff, uint32_t blockSize, SaSiBool_t isSramBackup)
{
    SaSiError_t rc;
    uint32_t stateCtr;
    uint8_t nonceBuff[UTIL_BACKUP_RESTORE_CCM_NONCE_SIZE] = { 0x0 };
    enum sep_crypto_direction direction;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* Check input parameters: in case of partial/full overlapping - exit with error */
    if ((blockSize <= 0) || (pSrcBuff == pDstBuff) || ((pSrcBuff < pDstBuff) && (pSrcBuff + blockSize) > pDstBuff) ||
        ((pDstBuff < pSrcBuff) && (pDstBuff + blockSize + UTIL_BACKUP_RESTORE_CCM_TAG_SIZE) > pSrcBuff) ||
        (blockSize > BLOCK_SIZE_LIMIT)) {
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    /* Check session key validity (required for CMAC derivation key) */
    SASI_UTIL_IS_SESSION_KEY_VALID(rc);
    if (rc == SASI_UTIL_SESSION_KEY_IS_UNSET) {
        return SASI_UTIL_SESSION_KEY_ERROR;
    }

    /* Protect HOST_CC_AO_STATE_COUNTER_INC access with mutex */
    rc = SaSi_PalMutexLock(&sasiSymCryptoMutex, SASI_INFINITE);
    if (rc != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }

    /* Case of Backup: change parameters and incremnet state counter */
    if (isSramBackup == SASI_TRUE) {
        /* Increment the AO state counter for backup operation only */
        SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_CC_AO_STATE_COUNTER_INC), 0x1);
    }

    /* Generates IV from state counter and src address */
    stateCtr = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_AO_CC_STATE_COUNTER));

    /* Release the mutex */
    if (SaSi_PalMutexUnlock(&sasiSymCryptoMutex) != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to release mutex\n");
    }

    SASI_PAL_LOG_DEBUG("stateCtr = %d \n", stateCtr);
    SaSi_COMMON_ReverseMemcpy((uint8_t *)nonceBuff, (uint8_t *)&stateCtr, sizeof(stateCtr));
    nonceBuff[4] = 0x1;
    nonceBuff[5] = 0x2;
    nonceBuff[6] = 0x3;
    nonceBuff[7] = 0x4;

    if (isSramBackup == SASI_TRUE) {
        direction = SEP_CRYPTO_DIRECTION_ENCRYPT;
    } else {
        direction = SEP_CRYPTO_DIRECTION_DECRYPT;
    }
    rc = SaSi_Util_Ccm(nonceBuff, UTIL_BACKUP_RESTORE_CCM_NONCE_SIZE, NULL, 0, SEP_AES_128_BIT_KEY_SIZE,
                       DRV_SESSION_KEY, direction, UTIL_BACKUP_RESTORE_CCM_TAG_SIZE, pSrcBuff, blockSize, pDstBuff);
    if (rc != SASI_OK) {
        return rc;
    }

    return SASI_OK;
}
