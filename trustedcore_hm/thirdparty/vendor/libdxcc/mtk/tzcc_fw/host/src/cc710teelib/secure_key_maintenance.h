/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SECURE_KEY_MAINTENANCE_H__
#define _SECURE_KEY_MAINTENANCE_H__

#include "secure_key_defs.h"
#include "ssi_util.h"

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */

/* !
 * @brief Create a secured package in the ARM TrustZone CryptoCell environment with the session key.
 *  It is used for internal use only (the only supported skeyType is DX_SECURE_KEY_MAINTENANCE).
 *
 * @param[in] skeyNonceBuf       - A pointer to Nonce - unique value assigned to all data passed into CCM.
 *                NOTE: it should be different for each call to this API.
 * @param[in] skeyBuf            - A pointer to data: pairs of addr+value.
 * @param[in] skeyType           - An enum parameter, defines key type (aes128 / aes256 / multi2).
 * @param[in] skeyNumPairs       - Number of pairs (min=1, max=5).
 * @param[out] skeyPackageBuf    - A pointer to the generated secured key package:
 *                        Word No.    Bits        Field Name
 *                        0        31:0        Token
 *                        1-3                     Nonce
 *                         4           2:0         Secure key type  = DX_SECURE_KEY_MAINTENANCE
 *                                           3           Direction = enc
 *                                           7:4         Cipher mode = cbc
 *                                           15:8        Number of pairs
 *                                           31:16       reserved
 *                         5           31:0        0
 *                        6           31:0        0
 *                        7-16                    encrypted data of addr+value pairs
 *                        17-20                   mac results
 *
 * \return SaSiUtilError_t one of the error codes defined in ssi_util.h
 */

uint32_t SaSi_UtilGenerateSecureKeyMaintenance(skeyNonceBuf_t skeyNonceBuf, uint8_t *skeyBuf,
                                               enum secure_key_type skeyType, uint32_t skeyNumPairs,
                                               skeyPackageBuf_t skeyPackageBuf);

#endif /* _SECURE_KEY_MAINTENANCE_H__ */
