/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SECURE_KEY_GEN_H__
#define _SECURE_KEY_GEN_H__

#ifdef __cplusplus
extern "C" {
#endif

/* ! @file
@brief This file contains secure key definitions and API.
*/

#include "secure_key_defs.h"
#include "ssi_util.h"
/* *****************************************************************************
 *                Structure PROTOTYPES
 * *************************************************************************** */
/* ! Definition of protection structure parameters */
struct SaSiUtilNonceCtrProtParams_t {
    uint8_t *nonceCtrBuff;   /* !< 16 bytes buffer for the Nonce/CTR */
    uint32_t nonceLen;       /* !< length of the nonce. 0 - no nonce protection */
    uint32_t ctrLen;         /* !< length of the counter. 0 no counter protection */
    uint32_t dataRange;      /* !< data range for the counter protection. used only if ctrLen is not 0. */
    uint32_t isNonSecPathOp; /* !< public to public operation. used in nonce protection operation. */
};

/* ! Bounds of the valid physical address range in which the plaintext data
    (input in case of Encrypt, output in case of Decrypt) is allowed to reside. */
struct SkeyRegBounds_t {
    uint64_t skeyLowerBound; /* !< Lower bound. */
    uint64_t skeyUpperBound; /* !< Upper bound. */
};

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */

/* !
 * @brief SaSi_UtilGenerateSecureKeyPackage is a CryptoCell TEE service for creating a secure key package for a specific
 * data stream that is passed to ARM CryptoCell REE. The secure key package contains all the characteristics and
 * restrictions to be imposed on a specific data stream. This service gets parameters such as: <ul><li> Type of
 * cryptographic operation - direction and mode.</li> <li> Bounds of valid address range in which the plaintext data is
 * allowed to reside.</li> <li>  Bounds of valid timestamp range.</li> <li> The key to be used for the cryptographic
 * operation - type and value.</li> <li> Parameters for counter protection and nonce protection modes.</li> <ul><li> The
 * AES CTR counter restriction is intended for cases where encrypted payload is decrypted into (or plaintext is
 * encrypted from) an unprotected buffer, up to a predefined buffer size limit.</li> <li> The AES CTR nonce protection
 * is intended for cases where encrypted payload is decrypted into (or plaintext is encrypted from) an unprotected
 * buffer, while restricting the nonce value to a predefined value.</li></ul></ul>
 *
 *      Another parameter which is set by the user is the nonce buffer which is contained in the generated package to be
 * used along with the session key (KSESS) for decrypting the above characteristics and restrictions in ARM CryptoCell
 * REE core.
 *
 *      The generated secure key package is passed to ARM TrustZone CryptoCell REE,
 *      to facilitate high-performance secure content path in the non-secure world.
 *
 * @return SaSiUtilError_t one of the error codes defined in ssi_util.h
 */
uint32_t SaSi_UtilGenerateSecureKeyPackage(

    enum secure_key_direction
        skeyDirection, /* !< [in] Cryptographic operation to be performed on the data - Encrypt or Decrypt. */
    enum secure_key_cipher_mode
        skeyMode, /* !< [in] Mode of cryptographic operation to be applied on the data: CBC, CTR, OFB or CBC-CTS. */
    struct SkeyRegBounds_t *skeyRegBounds, /* !< [in] Bounds of the valid physical address range in which the plaintext
                        data (input in case of Encrypt, output in case of Decrypt) is allowed to reside. */
    uint64_t startTimeStamp,               /* !< [in] Start of valid timestamp range. */
    uint64_t endTimeStamp,                 /* !< [in] End of valid timestamp range. */
    skeyNonceBuf_t skeyNonceBuf,   /* !< [in] Pointer to the nonce buffer. A different unique nonce must be used for each
                      call to this API. Usage of random nonce is recommended. */
    uint8_t *skeyBuf,              /* !< [in] Pointer to the key that is used for data encryption or decryption. */
    enum secure_key_type skeyType, /* !< [in] Type of the key that is used for data encryption or decryption.
                    Supported types are AES 128-bit, AES 256-bit and MULTI2. */
    uint32_t skeyNumRounds,        /* !< [in] Number of rounds. Relevant only for MULTI2 keys. */
    struct SaSiUtilNonceCtrProtParams_t *skeyProtParams, /* !< [in] Parameters for CTR secure operation:
                                    <ul><li>nonceCtrBuff - 16 bytes buffer for the Nonce/CTR</li>
                                    <li>nonceLen - Nonce length (0 = no nonce protection)</li>
                                    <li>ctrLen - Counter length (0 = no counter protection)</li>
                                    <li>dataRange - Counter protection data range (if ctrLen > 0)</li>
                                    <li>isNonSecPathOp - Non-secure (public to public) operation.
                                        Used in nonce protection operation.</li></ul> */
    skeyPackageBuf_t skeyPackageBuf /* !< [out] Pointer to the generated secure key package. */);

#ifdef __cplusplus
}
#endif

#endif /* _SECURE_KEY_GEN_H__ */
