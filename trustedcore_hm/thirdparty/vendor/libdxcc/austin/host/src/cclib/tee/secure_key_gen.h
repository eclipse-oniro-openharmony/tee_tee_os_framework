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

#ifndef _DX_SECURE_KEY_GEN_H__
#define _DX_SECURE_KEY_GEN_H__

#include "secure_key_defs.h"
#include "dx_util.h"
/* *****************************************************************************
 *                Structure PROTOTYPES
 * *************************************************************************** */

struct DX_UTIL_NonceCtrProtParams_t {
    uint8_t *nonceCtrBuff;   // 16 bytes buffer for the Nonce/CTR
    uint32_t nonceLen;       // length of the nonce. 0 - no nonce protection
    uint32_t ctrLen;         // length of the counter. 0 no counter protection
    uint32_t dataRange;      // data range for the counter protection. used only if ctrLen is not 0.
    uint32_t isNonSecPathOp; // public to public operation. used in nonce protection operation.
};

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */

/* !
 * @brief Create a secured crypto package in the CC441 secure environment with the session key.
 *  It is built of the AES/Multi2 encrypted key and the restriction data with authentication (by AES-CCM).
 *
 * @param[in] skeyDirection      - An enum parameter, defines Encrypt operation or a Decrypt operation.
 * @param[in] skeyMode        - An enum parameter, defines cipher operation mode (cbc / ctr / ofb / cbc_cts).
 * @param[in] skeyLowerBound    - The restricted lower bound address.
 * @param[in] skeyUpperBound     - The restricted upper bound address.
 * @param[in] skeyNonceBuf       - A pointer to Nonce - unique value assigned to all data passed into CCM.
 *                NOTE: it should be different for each call to this API.
 * @param[in] skeyBuf            - A pointer to the input secured key data buffer. The pointer does not need to be
 * aligned.
 * @param[in] skeyType           - An enum parameter, defines key type (aes128 / aes256 / multi2).
 * @param[in] skeyNumRounds      - Number of rounds (for Multi2 only).
 * @param[in] protParams          - Parameters for protection operation (AES CTR only).
 * @param[out] skeyPackageBuf    - A pointer to the generated secured key package:
 *                        Word No.    Bits        Field Name
 *                        0        31:0        Token
 *                        1-3                     Nonce
 *                         4           2:0         Secure key type (aes128 / aes256 / multi2)
 *                                           3           Direction (enc / dec)
 *                                           7:4         Cipher mode (cbc / ctr / ofb / cbc_cts)
 *                                           15:8        Number of rounds (only for Multi2)
 *                                           31:16       reserved
 *                         5           31:0        Lower bound address
 *                        6           31:0        Upper bound address
 *                        7-16                    Restricted key  (encryption of the secured key padded with zeroes)
 *                        17-20                   mac results
 *
 * \return DxUTILError_t one of the error codes defined in dx_util.h
 */
uint32_t DX_UTIL_GenerateSecureKeyPackage(enum secure_key_direction skeyDirection, enum secure_key_cipher_mode skeyMode,
                                          uint64_t skeyLowerBound, uint64_t skeyUpperBound, skeyNonceBuf_t skeyNonceBuf,
                                          uint8_t *skeyBuf, enum secure_key_type skeyType, uint32_t skeyNumRounds,
                                          struct DX_UTIL_NonceCtrProtParams_t *skeyProtParams,
                                          skeyPackageBuf_t skeyPackageBuf);
#endif /* _DX_SECURE_KEY_GEN_H__ */
