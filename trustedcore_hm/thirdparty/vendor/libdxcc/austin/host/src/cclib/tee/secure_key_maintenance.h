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

#ifndef _DX_SECURE_KEY_MAINTENANCE_H__
#define _DX_SECURE_KEY_MAINTENANCE_H__

#include "secure_key_defs.h"
#include "dx_util.h"

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */

/* !
 * @brief Create a secured package in the CC441 secure environment with the session key.
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
 * \return DxUTILError_t one of the error codes defined in dx_util.h
 */

uint32_t DX_UTIL_GenerateSecureKeyMaintenance(skeyNonceBuf_t skeyNonceBuf, uint8_t *skeyBuf,
                                              enum secure_key_type skeyType, uint32_t skeyNumPairs,
                                              skeyPackageBuf_t skeyPackageBuf);

#endif /* _DX_SECURE_KEY_MAINTENANCE_H__ */
