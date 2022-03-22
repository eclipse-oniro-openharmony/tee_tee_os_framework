/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_RSA_KG_H
#define SaSi_RSA_KG_H

#include "sasi_rsa_types.h"
#include "sasi_rnd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* !
@file
@brief Generates a RSA pair of public and private keys.
*/

/* *********************** Defines **************************** */

/* Max allowed size and values of public exponent for key generation in SaSi */
#define SaSi_RSA_KG_PUB_EXP_MAX_SIZE_BITS 17
#define SaSi_RSA_KG_PUB_EXP_ALLOW_VAL_1   0x000003
#define SaSi_RSA_KG_PUB_EXP_ALLOW_VAL_2   0x000011
#define SaSi_RSA_KG_PUB_EXP_ALLOW_VAL_3   0x010001

/* ******************************************************************************************** */

/* !
@brief SaSi_RSA_KG_GenerateKeyPair_MTK generates a Pair of public and private keys on non CRT mode according to [ANSI
X9.31].

\note    To be FIPS 186-4 [5.1] compliant use only the following key sizes (in bits): 1024, 2048 and 3072.

@return SaSi_OK on success.
@return A non-zero value from sasi_rsa_error.h on failure.

*/
CIMPORT_C SaSiError_t SaSi_RSA_KG_GenerateKeyPair_MTK(
    SaSi_RND_Context_t *rndContext_ptr,     /* !< [in/out] Pointer to the RND context buffer. */
    uint8_t *pubExp_ptr,                    /* !< [in]  The pointer to the public exponent (public key). */
    uint16_t pubExpSizeInBytes,             /* !< [in]  The public exponent size in bytes. */
    uint32_t keySize,                       /* !< [in]  The size of the key, in bits. Supported sizes are
           512, 1024, 2048, 3072 and 4096 bit. */
    SaSi_RSAUserPrivKey_t *userPrivKey_ptr, /* !< [out] Pointer to the private-key structure. */
    SaSi_RSAUserPubKey_t *userPubKey_ptr,   /* !< [out] Pointer to the public-key structure. */
    SaSi_RSAKGData_t *keyGenData_ptr, /* !< [in]  Pointer to a temporary structure required for the KeyGen operation. */
    SaSi_RSAKGFipsContext_t
        *pFipsCtx /* !< [in]  Pointer to temporary buffer used in case FIPS certification if required. */
);

/* ******************************************************************************************** */
/* !
@brief Generates a pair of public and private keys on CRT mode according to [ANSI X9.31].

\note    To be FIPS 186-4 [5.1] compliant use only the following key sizes (in bits): 1024, 2048 and 3072.

@return SaSi_OK on success.
@return A non-zero value from sasi_rsa_error.h on failure.
*/

CIMPORT_C SaSiError_t SaSi_RSA_KG_GenerateKeyPairCRT_MTK(
    SaSi_RND_Context_t *rndContext_ptr,     /* !< [in/out] Pointer to the RND context buffer. */
    uint8_t *pubExp_ptr,                    /* !< [in]  The pointer to the public exponent (public key). */
    uint16_t pubExpSizeInBytes,             /* !< [in]  The public exponent size in bytes. */
    uint32_t keySize,                       /* !< [in]  The size of the key, in bits. Supported sizes are
                                                       512, 1024, 2048, 3072 and 4096 bit. */
    SaSi_RSAUserPrivKey_t *userPrivKey_ptr, /* !< [out] Pointer to the private-key structure. */
    SaSi_RSAUserPubKey_t *userPubKey_ptr,   /* !< [out] Pointer to the public-key structure. */
    SaSi_RSAKGData_t *keyGenData_ptr, /* !< [in] Pointer to a temporary structure required for the KeyGen operation. */
    SaSi_RSAKGFipsContext_t
        *pFipsCtx /* !< [in] Pointer to temporary buffer used in case FIPS certification if required. */
);

#ifdef __cplusplus
}
#endif

#endif
