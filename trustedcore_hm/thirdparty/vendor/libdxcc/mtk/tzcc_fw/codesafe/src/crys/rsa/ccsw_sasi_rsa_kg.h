/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef CCSW_SaSi_RSA_KG_H
#define CCSW_SaSi_RSA_KG_H

#include "ssi_pal_types.h"
#include "ccsw_sasi_rsa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
   @brief SaSi_RSA_KG_GenerateKeyPair_MTK generates a Pair of public and private keys on non CRT mode.

   @param [in/out] rndContext_ptr  - Pointer to the RND context buffer.
   @param [in] PubExp_ptr - The pointer to the public exponent (public key)
   @param [in] PubExpSizeInBytes - The public exponent size in bytes.
   @param [in] KeySize  - The size of the key, in bits. Supported sizes are:
                            - for PKI without PKA HW: all 256 bit multiples between 512 - 2048;
                            - for PKI with PKA: HW all 32 bit multiples between 512 - 2112;
   @param [out] UserPrivKey_ptr - A pointer to the private key structure.
                           This structure is used as input to the SaSi_RSA_PRIM_Decrypt_MTK API.
   @param [out] UserPubKey_ptr - A pointer to the public key structure.
                           This structure is used as input to the SaSi_RSA_PRIM_Encrypt_MTK API.
   @param [in] KeyGenData_ptr - a pointer to a structure required for the KeyGen
          operation.
 * @param rndCtx_ptr - The pointer to structure, containing context ID and void
 *              pointer to RND State structure, which should be converted to
 *              actual type inside of the function according to used platform
 *                  (External or SaSi). Also contains the RND generate vecotr function pointer.

   @return SaSiError_t - SaSi_OK,
                         SaSi_RSA_INVALID_EXPONENT_POINTER_ERROR,
                         SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
                         SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR,
                         SaSi_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID,
                         SaSi_RSA_INVALID_MODULUS_SIZE,
                         SaSi_RSA_INVALID_EXPONENT_SIZE
*/
CEXPORT_C SaSiError_t SaSi_SW_RSA_KG_GenerateKeyPair(SaSi_RND_Context_t *rndContext_ptr, uint8_t *PubExp_ptr,
                                                     uint16_t PubExpSizeInBytes, uint32_t KeySize,
                                                     SW_SaSi_RSAUserPrivKey_t *UserPrivKey_ptr,
                                                     SW_SaSi_RSAUserPubKey_t *UserPubKey_ptr,
                                                     SW_SaSi_RSAKGData_t *KeyGenData_ptr);

/* ******************************************************************************************** */
/*
   @brief SaSi_SWRSA_KG_GenerateKeyPairCRT generates a Pair of public and private keys on CRT mode.

   @param [in/out] rndContext_ptr  - Pointer to the RND context buffer.
   @param [in] PubExp_ptr - The pointer to the public exponent (public key)
   @param [in] PubExpSizeInBytes - The public exponent size in bits.
   @param [in] KeySize  - The size of the key, in bits. Supported sizes are:
                            - for PKI without PKA HW: all 256 bit multiples between 512 - 2048;
                            - for PKI with PKA: HW all 32 bit multiples between 512 - 2112;
   @param [out] UserPrivKey_ptr - A pointer to the private key structure.
                           This structure is used as input to the SaSi_RSA_PRIM_Decrypt_MTK API.
   @param [out] UserPubKey_ptr - A pointer to the public key structure.
                           This structure is used as input to the SaSi_RSA_PRIM_Encryped API.
   @param [in] KeyGenData_ptr - a pointer to a structure required for the KeyGen operation.
 * @param [in/out] RndCtx_ptr - The pointer to structure, containing context ID and void
 *              pointer to RND State structure, which should be converted to
 *              actual type inside of the function according to used platform
 *                  (External or SaSi). Also contains the RND generate vecotr function pointer.

   @return SaSiError_t - SaSi_OK,
                         SaSi_RSA_INVALID_EXPONENT_POINTER_ERROR,
                         SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
                         SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR,
                         SaSi_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID,
                         SaSi_RSA_INVALID_MODULUS_SIZE,
                         SaSi_RSA_INVALID_EXPONENT_SIZE
*/

CEXPORT_C SaSiError_t SaSi_SW_RSA_KG_GenerateKeyPairCRT(SaSi_RND_Context_t *rndContext_ptr, uint8_t *PubExp_ptr,
                                                        uint16_t PubExpSizeInBytes, uint32_t KeySize,
                                                        SW_SaSi_RSAUserPrivKey_t *UserPrivKey_ptr,
                                                        SW_SaSi_RSAUserPubKey_t *UserPubKey_ptr,
                                                        SW_SaSi_RSAKGData_t *KeyGenData_ptr);

#ifdef __cplusplus
}
#endif

#endif
