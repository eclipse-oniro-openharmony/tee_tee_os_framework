/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_UTIL_CCM_H
#define _SSI_UTIL_CCM_H

/* !
@file
@brief This file contains CryptoCell Util backup and restore functions and definitions.
*/

#ifdef __cplusplus
extern "C" {
#endif

#include "ssi_pal_types.h"
#include "ssi_util_error.h"
#include "ssi_util_defs.h"
#include "ssi_crypto_ctx.h"

/* *****************************************************************************
 *                            DEFINITIONS
 * *************************************************************************** */
/* !
@brief This function performs aes ccm encrypt or decrypt by calling MAC and CTR

@return SASI_OK    On success.
@return a non-zero value from sbrom_bsv_error.h on failure.
*/

uint32_t
SaSi_Util_Ccm(uint8_t *pNonce,                     /* !< [in] pointer to CCM nonce buffer */
              uint32_t nonceSize,                  /* !< [in] nonce size in bytes */
              uint8_t *pAdata,                     /* !< [in] pointer to CCM additional data buffer */
              uint32_t aDataSize,                  /* !< [in] additional data size in bytes */
              uint32_t keySize,                    /* !< [in] key size in bytes */
              enum drv_crypto_key_type keyType,    /* !< [in] key type */
              enum sep_crypto_direction direction, /* !< [in] encrypt or decrypt mode */
              uint32_t tagSize,                    /* !< [in] CCM tag size in bytes */
              uint8_t *pDataIn,                    /* !< [in] pointer to CCM input buffer.
                                          if encrypt mode, pDataIn is plain text; for decrypt pDataIn contains cipher text + mac */
              uint32_t dataInSize, /* !< [in] plain text or cipher text size in bytes (not including mac size) */
              uint8_t *pDataOut);  /* !< [in] pointer to CCM output buffer.
                        if encrypt mode, pDataOut is cipher text + mac; for pDataOut pDataIn contains plain text */

#ifdef __cplusplus
}
#endif

#endif /* _SSI_UTIL_CCM_H */
