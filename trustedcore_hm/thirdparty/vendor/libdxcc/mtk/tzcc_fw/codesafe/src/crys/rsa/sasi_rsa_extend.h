/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef __SaSi_RSA_EXTEND_H__
#define __SaSi_RSA_EXTEND_H__

#include "sasi_rsa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* !
@file
@brief This module defines the API that supports PKCS#1 v2.1 primitive functions
*/

/* ***********************         Defines       *********************************** */

/* *********************** Public functions prototipes  **************************** */

/* ****************************************************************************************** */
/* !
@brief
SaSi_RSA_PRIM_EncryptExactSize implements the RSAEP algorithm as defined in PKCS#1 v2.1 6.1.1

@param[in] UserPubKey_ptr - A pointer to the public key data structure
@param[in] PrimeData_ptr - A pointer to a structure containing internal temp buffers
@param[in] DataIn_ptr - A pointer to the plain data to encrypt
@param[in] DataInSize - The size, in bytes, of the data to encrypt.
                    NOTE! This value must be <= the size of the modulus.
@param[out] Output_ptr - Pointer to the encrypted data.
                        The buffer must be at least PubKey_ptr->N.len bytes long
                        (that is, the size of the modulus, in bytes).

@return SaSi_OK on success.
@return SaSi_DH error on failure as defined SaSi_RSA_error.h: \n
                    SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR, \n
                    SaSi_RSA_PUB_KEY_VALIDATION_TAG_ERROR, \n
                    SaSi_RSA_PRIM_DATA_STRUCT_POINTER_INVALID, \n
                    SaSi_RSA_DATA_POINTER_INVALID_ERROR, \n
                    SaSi_RSA_INVALID_OUTPUT_POINTER_ERROR, \n
                    SaSi_RSA_INVALID_MESSAGE_BUFFER_SIZE, \n
                    SaSi_RSA_INVALID_MESSAGE_DATA_SIZE, \n
                    SaSi_RSA_INVALID_MESSAGE_VAL
 */
#define SaSi_RSA_PRIM_EncryptExactSize(UserPubKey_ptr, PrimeData_ptr, Data_ptr, DataInSize, Output_ptr) \
    SaSi_RSA_PRIM_Encrypt_MTK(UserPubKey_ptr, PrimeData_ptr, Data_ptr, DataInSize, Output_ptr)

/* ****************************************************************************************** */
/* !
@brief
SaSi_RSA_PRIM_DecryptExactSize - implements the RSADP algorithm as defined in PKCS#1 v2.1 6.1.2

@note
The differnce of this function from SaSi_RSA_PRIM_Decrypt_MTK is that the function outputs the message of exact size,
given by user.

@return SaSi_OK on success.
@return SaSi_DH error on failure as defined SaSi_RSA_error.h: \n
                        SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR, \n
                        SaSi_RSA_PRIM_DATA_STRUCT_POINTER_INVALID, \n
                        SaSi_RSA_PRIV_KEY_VALIDATION_TAG_ERROR, \n
                        SaSi_RSA_DATA_POINTER_INVALID_ERROR, \n
                        SaSi_RSA_INVALID_OUTPUT_POINTER_ERROR, \n
                        SaSi_RSA_INVALID_MESSAGE_DATA_SIZE, \n
                        SaSi_RSA_INVALID_MESSAGE_VAL
*/
CIMPORT_C SaSiError_t SaSi_RSA_PRIM_DecryptExactSize(
    SaSi_RSAUserPrivKey_t
        *UserPrivKey_ptr,               /* !< [in]  Pointer to the private key data structure.
                                                    NOTE! The representation (pair or quintuple) and hence the algorithm (CRT or
                                           not-CRT)               is determined by the Private Key data structure - using SaSi_Build_PrivKey or
                                           SaSi_Build_PrivKeyCRT               determines which algorithm is used. */
    SaSi_RSAPrimeData_t *PrimeData_ptr, /* !< [in]  A pointer to a structure containing internal buffers required for the
                                           RSA operation. */
    uint8_t *DataIn_ptr, /* !< [in]  A pointer to the data to be decrypted. Size of this data must be equaled to key
                            modulus size exactly. */
    uint8_t *Output_ptr, /* !< [out] A pointer to the decrypted data. The buffer must be at least PrivKey_ptr->N.len
                            bytes long (that is, the size of the modulus, in bytes). */
    uint16_t DataOutSize /* !< [in]  The expected size of output data, in bytes. Must be not great than the size of the
                            modulus. */
);

/* ************************************************************************************ */
/* !
@brief The function calculates modular inverse of 32-bits numbers, if it exists.

Algorithm:
* invMod_ptr = 1/aVal mod modVal
If inverse is not exists, the function set output value to 0.

This API has two implementations:
-# Implementation based on Binary Right Shift algorithm, which uses multiplication
    and division operations. This is the default implementation.
-# Implementation based on shifting Euclidean algorithm, which not uses
    multiplication and division. For choosing this implementation the user must to
    define the flag SaSi_RSA_INV_MOD_SHIFTING_EUCLID_ALG in the project definitions
    (Make-file for SEP).


@return SaSi_OK on success.
@return SaSi_DH error on failure as defined SaSi_RSA_error.h: \n
                SaSi_RSA_INVALID_MODULUS_ERROR
*/
CIMPORT_C SaSiError_t SaSi_RSA_InvModWord(uint32_t aVal,       /* !< [in]  value to be inverted. */
                                          uint32_t modVal,     /* !< [in]  modulus. */
                                          uint32_t *invMod_ptr /* !< [out] pointer to the result buffer. */
);

/* ******************************************************************************************** */
/* !
@brief SaSi_RSA_KG_GeneratePQprimes generates two valid prime factors P,Q used in RSA key generation.

@return SaSi_OK on success.
@return SaSi_DH error on failure as defined SaSi_RSA_error.h: \n
                        SaSi_RSA_INVALID_EXPONENT_POINTER_ERROR, \n
                         SaSi_RSA_INVALID_EXPONENT_SIZE, \n
                         SaSi_RSA_INVALID_EXPONENT_VAL, \n
                         SaSi_RSA_INVALID_PTR_ERROR, \n
                         SaSi_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID, \n
                         SaSi_RSA_INVALID_MODULUS_SIZE \n
*/
CIMPORT_C SaSiError_t SaSi_RSA_KG_GeneratePQprimes(
    uint8_t *pubExp_ptr,        /* !< [in]  The pointer to the public exponent (little endian bytes array).
                                            Allowed values: Exp = 0x3, 0x11, 0x010001. */
    uint16_t pubExpSizeInBytes, /* !< [in]  The public exponent size in bytes (allowed sizes 1,3). */
    uint32_t primeSizeInBits,   /* !< [in]  The size of the prime factor in bits equaled to keySizeInBits/2).
                                            Supported sizes of the prime factors are all 128 bit multiples between 256 -
                                   1024. */
    uint32_t testsCount, /* !< [in]  count of Rabin-Miller tests needed for accepting the prime candidate as valid prime
                            number. */
    uint32_t *p_ptr,     /* !< [out] A pointer to the first prime factor in words (LSWord is the left most). */
    uint32_t *q_ptr,     /* !< [out] A pointer to the second prime factor in words (LSWord is the left most). */
    SaSi_RSAKGData_t *keyGenData_ptr /* !< [in]  A pointer to a temp buffer structure required for the KeyGen operation.
                                        The buffer not needs initialization. */
);

/* ******************************************************************************************** */
/* !
@brief SaSi_RSA_KG_ClculateKeyPairFromPQ calculates a Pair of public and private keys on NonCRT or CRT modes.

The function receives P,Q prime factors and calculates all parameters of private and public keys if appropriate pointer
is not NULL.

 @return SaSi_OK on success.
 @return SaSi_DH error on failure as defined SaSi_RSA_error.h: \n
                         SaSi_RSA_INVALID_EXPONENT_POINTER_ERROR, \n
                         SaSi_RSA_INVALID_PTR_ERROR, \n
                         SaSi_RSA_INVALID_DECRYPRION_MODE_ERROR, \n
                         SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR, \n
                         SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR, \n
                         SaSi_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID, \n
                         SaSi_RSA_INVALID_MODULUS_SIZE, \n
                         SaSi_RSA_INVALID_EXPONENT_SIZE, \n
                         SaSi_RSA_KEY_GEN_CONDITIONAL_TEST_FAIL_ERROR
*/
CIMPORT_C SaSiError_t SaSi_RSA_KG_CalculateKeyPairFromPQ(
    uint8_t *pubExp_ptr,        /* !< [in]  The pointer to the public exponent (little endian bytes array).
                                            Allowed values: Exp = 0x3, 0x11, 0x010001. */
    uint16_t pubExpSizeInBytes, /* !< [in]  The public exponent size in bytes (allowed sizes 1,3). */
    uint32_t *p_ptr, /* !< [in]  A pointer to the valid first prime factor in words (LSWord is the left most). */
    uint32_t *q_ptr, /* !< [in]  A pointer to the valid second prime factor in words (LSWord is the left most). */
    uint16_t primeSizeInBits, /* !< [in]  The size of the prime factor in bits equaled to keySizeInBits/2).
                                          Supported sizes of the prime factors are all 128 bit multiples between 256 -
                                 1024;. */
    SaSi_RSA_DecryptionMode_t
        privKeyMode, /* !< [in]  flag of private key mode: SaSi_RSA_NoCrt = 10 or SaSi_RSA_Crt = 11. */
    SaSi_RSAUserPrivKey_t *
        userPrivKey_ptr, /* !< [out] A pointer to the private key structure (if UserPrivKey_ptr == NULL, then private key
                            is not calculated). This structure is used as input to the SaSi_RSA_PRIM_Decrypt_MTK API. */
    SaSi_RSAUserPubKey_t
        *userPubKey_ptr, /* !< [out] A pointer to the public key structure (if UserPubKey_ptr == NULL, then public key is
                            not calculated). This structure is used as input to the SaSi_RSA_PRIM_Encrypt_MTK API. */
    SaSi_RSAKGData_t *keyGenData_ptr /* !< [in]  a pointer to a structure required for the KeyGen operation. */
);

/* ******************************************************************************************** */
/* !
@brief SaSi_RSA_KG_ExtendGenerateKeyPair generates a Pair of public and private keys on non CRT mode.

 @return SaSi_OK on success.
 @return SaSi_DH error on failure as defined SaSi_RSA_error.h: \n
                         SaSi_RSA_INVALID_EXPONENT_POINTER_ERROR, \n
                         SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR, \n
                         SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR, \n
                         SaSi_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID, \n
                         SaSi_RSA_INVALID_MODULUS_SIZE, \n
                         SaSi_RSA_INVALID_EXPONENT_SIZE
*/
CIMPORT_C SaSiError_t DX_RSA_KG_ExtendGenerateKeyPair(
    uint8_t *pubExp_ptr, /* !< [in]  The pointer to the public exponent (public key) Allowed values: Exp = 0x3, 0x11,
                            0x010001. */
    uint16_t pubExpSizeInBytes, /* !< [in]  The public exponent size in bytes (allowed sizes 1,3). */
    uint32_t keySizeBits,       /* !< [in]  The size of the key modulus, in bits. Supported sizes are: 256 bit multiples
                                   between 512 - 2048. */
    SaSi_RSA_DecryptionMode_t
        privKeyMode, /* !< [in]  flag of private key mode: SaSi_RSA_NoCrt = 10 or SaSi_RSA_Crt = 11. */
    SaSi_RSAUserPrivKey_t *userPrivKey_ptr, /* !< [in]  A pointer to the private key structure. This structure is used as
                                               input to the SaSi_RSA_PRIM_Decrypt_MTK API. */
    SaSi_RSAUserPubKey_t *userPubKey_ptr,   /* !< [in]  A pointer to the public key structure. This structure is used as
                                               input to the SaSi_RSA_PRIM_Encrypt_MTK API. */
    SaSi_RSAKGData_t *keyGenData_ptr        /* !< [in]  a pointer to a structure required for the KeyGen operation. */
);

#ifdef __cplusplus
}
#endif

#endif
