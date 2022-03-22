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

#ifndef CCSW_CRYS_RSA_KG_H
#define CCSW_CRYS_RSA_KG_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */

#include "dx_pal_types.h"
#include "ccsw_crys_rsa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Object %name    : %
 *  State           :  %state%
 *  Creation date   :  Sun Mar 06 15:55:45 2005
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief This module defines the API for key-pair generation functions
 *
 *  \version CRYS_RSA_KG.h#1:incl:1
 *  \author adams
 */

/*
   @brief CRYS_RSA_KG_GenerateKeyPair generates a Pair of public and private keys on non CRT mode.

   @param [in] PubExp_ptr - The pointer to the public exponent (public key)
   @param [in] PubExpSizeInBytes - The public exponent size in bytes.
   @param [in] KeySize  - The size of the key, in bits. Supported sizes are:
                            - for PKI without PKA HW: all 256 bit multiples between 512 - 2048;
                            - for PKI with PKA: HW all 32 bit multiples between 512 - 2112;
   @param [out] UserPrivKey_ptr - A pointer to the private key structure.
                           This structure is used as input to the CRYS_RSA_PRIM_Decrypt API.
   @param [out] UserPubKey_ptr - A pointer to the public key structure.
                           This structure is used as input to the CRYS_RSA_PRIM_Encrypt API.
   @param [in] KeyGenData_ptr - a pointer to a structure required for the KeyGen
          operation.
 * @param RndGenerateVectFunc - The pointer to actual working RND Generate
 *                    vector function given by the user (External or
 *                    CRYS function SW_CRYS_RND_GenerateVector).
 * @param rndCtx_ptr - The pointer to structure, containing context ID and void
 *              pointer to RND State structure, which should be converted to
 *              actual type inside of the function according to used platform
 *                  (External or CRYS).

   @return CRYSError_t - CRYS_OK,
                         CRYS_RSA_INVALID_EXPONENT_POINTER_ERROR,
                         CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
                         CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR,
                         CRYS_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID,
                         CRYS_RSA_INVALID_MODULUS_SIZE,
                         CRYS_RSA_INVALID_EXPONENT_SIZE
*/
CEXPORT_C CRYSError_t CRYS_SW_RSA_KG_GenerateKeyPair(uint8_t *PubExp_ptr, uint16_t PubExpSizeInBytes, uint32_t KeySize,
                                                     SW_CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
                                                     SW_CRYS_RSAUserPubKey_t *UserPubKey_ptr,
                                                     SW_CRYS_RSAKGData_t *KeyGenData_ptr);

/* ******************************************************************************************** */
/*
   @brief CRYS_SWRSA_KG_GenerateKeyPairCRT generates a Pair of public and private keys on CRT mode.

   @param [in] PubExp_ptr - The pointer to the public exponent (public key)
   @param [in] PubExpSizeInBytes - The public exponent size in bits.
   @param [in] KeySize  - The size of the key, in bits. Supported sizes are:
                            - for PKI without PKA HW: all 256 bit multiples between 512 - 2048;
                            - for PKI with PKA: HW all 32 bit multiples between 512 - 2112;
   @param [out] UserPrivKey_ptr - A pointer to the private key structure.
                           This structure is used as input to the CRYS_RSA_PRIM_Decrypt API.
   @param [out] UserPubKey_ptr - A pointer to the public key structure.
                           This structure is used as input to the CRYS_RSA_PRIM_Encryped API.
   @param [in] KeyGenData_ptr - a pointer to a structure required for the KeyGen operation.
 * @param [in] RndGenerateVectFunc - The pointer to actual working RND Generate
 *                    vector function given by the user (External or
 *                    CRYS function SW_CRYS_RND_GenerateVector).
 * @param [in/out] RndCtx_ptr - The pointer to structure, containing context ID and void
 *              pointer to RND State structure, which should be converted to
 *              actual type inside of the function according to used platform
 *                  (External or CRYS).

   @return CRYSError_t - CRYS_OK,
                         CRYS_RSA_INVALID_EXPONENT_POINTER_ERROR,
                         CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
                         CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR,
                         CRYS_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID,
                         CRYS_RSA_INVALID_MODULUS_SIZE,
                         CRYS_RSA_INVALID_EXPONENT_SIZE
*/

CEXPORT_C CRYSError_t CRYS_SW_RSA_KG_GenerateKeyPairCRT(uint8_t *PubExp_ptr, uint16_t PubExpSizeInBytes,
                                                        uint32_t KeySize, SW_CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
                                                        SW_CRYS_RSAUserPubKey_t *UserPubKey_ptr,
                                                        SW_CRYS_RSAKGData_t *KeyGenData_ptr);

#ifdef __cplusplus
}
#endif

#endif
