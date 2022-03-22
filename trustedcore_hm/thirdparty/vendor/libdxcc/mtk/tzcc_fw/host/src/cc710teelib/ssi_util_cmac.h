/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_UTIL_CMAC_H
#define _SSI_UTIL_CMAC_H

#include "ssi_util_key_derivation.h"

/* *****************************************************************************
 *                            DEFINITIONS
 * *************************************************************************** */

/* !
 * This function is used to generate bytes stream for key derivation purposes.
 * The function gets an input data and can use use one of the following keys: KDR/Session/userKey.
 *
 * @param[in] aesKeyType     - SASI_UTIL_ROOT_KEY / SASI_UTIL_USER_KEY.
 * @param[in] pUserKey        - A pointer to the user's key buffer (case of SASI_UTIL_USER_KEY).
 * @param[in] pDataIn         - A pointer to input buffer.
 * @param[in] dataInSize     - Size of data in bytes.
 * @param[out] pCmacResult     - A pointer to output buffer 16 bytes array.
 *
 * @return SASI_UTIL_OK on success, otherwise failure
 *
 */
SaSiUtilError_t SaSi_UtilCmacDeriveKey(SaSiUtilKeyType_t keyType, SaSiAesUserKeyData_t *pUserKey, uint8_t *pDataIn,
                                       size_t dataInSize, SaSiUtilAesCmacResult_t pCmacResult);

#endif /* _SSI_UTIL_CMAC_H */
