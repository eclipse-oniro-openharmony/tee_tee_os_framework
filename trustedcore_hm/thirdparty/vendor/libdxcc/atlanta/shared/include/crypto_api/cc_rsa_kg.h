/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/

#ifndef _CC_RSA_KG_H
#define _CC_RSA_KG_H

#include "cc_rsa_types.h"
#include "cc_rnd.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief Generates a RSA pair of public and private keys.
*/

/************************ Defines ******************************/

/* Max allowed size and values of public exponent for key generation in CryptoCell*/
#define CC_RSA_KG_PUB_EXP_MAX_SIZE_BITS    17
#define CC_RSA_KG_PUB_EXP_ALLOW_VAL_1      0x000003
#define CC_RSA_KG_PUB_EXP_ALLOW_VAL_2      0x000011
#define CC_RSA_KG_PUB_EXP_ALLOW_VAL_3      0x010001




/***********************************************************************************************/

/*!
@brief CC_RsaKgKeyPairGenerate generates a Pair of public and private keys on non CRT mode according to ANSI X9.31-1988: Public Key
Cryptography Using Reversible Algorithms for the Financial Services Industry (rDSA).

\note    To be FIPS Publication 186-4: Digital Signature Standard (DSS) [5.1] compliant use only the following key sizes (in bits): 2048, 3072 and 4096.

@return CC_OK on success.
@return A non-zero value from cc_rsa_error.h on failure.

*/
CIMPORT_C CCError_t CC_RsaKgKeyPairGenerate(
                                        CCRndContext_t *rndContext_ptr,          /*!< [in/out] Pointer to the RND context buffer. */
                                        uint8_t             *pubExp_ptr,            /*!< [in]  The pointer to the public exponent (public key). */
                                        size_t               pubExpSizeInBytes,     /*!< [in]  The public exponent size in bytes. */
                                        size_t               keySize,               /*!< [in]  The size of the key, in bits. Supported sizes are
											       2048, 3072 and 4096 bit. */
                                        CCRsaUserPrivKey_t *userPrivKey_ptr,     /*!< [out] Pointer to the private-key structure. */
                                        CCRsaUserPubKey_t  *userPubKey_ptr,      /*!< [out] Pointer to the public-key structure. */
					CCRsaKgData_t      *keyGenData_ptr,      /*!< [in]  Pointer to a temporary structure required for the KeyGen operation. */
                                        CCRsaKgFipsContext_t    *pFipsCtx        /*!< [in]  Pointer to temporary buffer used in case FIPS certification if required
											    (may be NULL for all other cases). */
);

/***********************************************************************************************/
/*!
@brief Generates a pair of public and private keys on CRT mode according to ANSI X9.31-1988: Public Key
Cryptography Using Reversible Algorithms for the Financial Services Industry (rDSA).

\note To be FIPS Publication 186-4: Digital Signature Standard (DSS) compliant use only the following key sizes (in bits): 2048, 3072 and 4096.

@return CC_OK on success.
@return A non-zero value from cc_rsa_error.h on failure.
*/

CIMPORT_C CCError_t CC_RsaKgKeyPairCrtGenerate(
                                        CCRndContext_t *rndContext_ptr,         /*!< [in/out] Pointer to the RND context buffer. */
                                        uint8_t             *pubExp_ptr,           /*!< [in]  The pointer to the public exponent (public key). */
                                        size_t               pubExpSizeInBytes,    /*!< [in]  The public exponent size in bytes. */
                                        size_t               keySize,              /*!< [in]  The size of the key, in bits. Supported sizes are
                                                                                              2048, 3072 and 4096 bit. */
                                        CCRsaUserPrivKey_t *userPrivKey_ptr,    /*!< [out] Pointer to the private-key structure. */
                                        CCRsaUserPubKey_t  *userPubKey_ptr,     /*!< [out] Pointer to the public-key structure. */
                                        CCRsaKgData_t      *keyGenData_ptr,     /*!< [in] Pointer to a temporary structure required for the KeyGen operation. */
                                        CCRsaKgFipsContext_t    *pFipsCtx       /*!< [in] Pointer to temporary buffer used in case FIPS certification if required
											  (may be NULL for all other cases). */
);


#ifdef __cplusplus
}
#endif

#endif


