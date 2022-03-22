/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_RSA_PRIM_H
#define SaSi_RSA_PRIM_H

#include "sasi_rsa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* !
@file
@brief This module defines the API that implements the [PKCS1_2.1] primitive functions.

\note Direct use of primitive functions, rather than schemes to protect data, is strongly discouraged as primitive
functions are susceptible to well-known attacks.
*/

/* ******************************************************************************* */
/* !
@brief Implements the RSAEP algorithm, as defined in [PKCS1_2.1] - 6.1.1.

@return SaSi_OK on success.
@return A non-zero value from sasi_rsa_error.h on failure.
 */
CIMPORT_C SaSiError_t SaSi_RSA_PRIM_Encrypt_MTK(
    SaSi_RSAUserPubKey_t *UserPubKey_ptr, /* !< [in]  Pointer to the public-key data structure. */
    SaSi_RSAPrimeData_t *PrimeData_ptr,   /* !< [in]  Pointer to a temporary structure containing internal buffers. */
    uint8_t *Data_ptr,                    /* !< [in]  Pointer to the data to encrypt. */
    uint16_t DataSize,  /* !< [in]  The size (in bytes) of the data to encrypt. Data size must be &le; Modulus size.
It can be smaller than the modulus size but it is not recommended.
                                   If smaller, the data is zero-padded up to the modulus size.
                                   Since the result of decryption is always the size of the modulus,
                                   this causes the size of the decrypted data to be larger than the
originally encrypted data. */
    uint8_t *Output_ptr /* !< [out] Pointer to the encrypted data. The buffer size must be &ge; the modulus size. */
);

/* ******************************************************************************* */
/* !
@brief Implements the RSADP algorithm, as defined in [PKCS1_2.1] - 6.1.2.

@return SaSi_OK on success.
@return A non-zero value from sasi_rsa_error.h on failure.

*/
CIMPORT_C SaSiError_t SaSi_RSA_PRIM_Decrypt_MTK(
    SaSi_RSAUserPrivKey_t *UserPrivKey_ptr, /* !< [in]  Pointer to the private-key data structure.
                                                        The representation (pair or quintuple) and hence the algorithm
                (CRT or not-CRT) is determined by the Private Key data structure - using
                ::SaSi_RSA_Build_PrivKey_MTK or ::SaSi_RSA_Build_PrivKeyCRT_MTK
                                                        to determine which algorithm is used. */
    SaSi_RSAPrimeData_t *PrimeData_ptr, /* !< [in]  Pointer to a temporary structure containing internal buffers required
           for the RSA operation. */
    uint8_t *Data_ptr,                  /* !< [in]  Pointer to the data to be decrypted. */
    uint16_t DataSize,  /* !< [in]  The size (in bytes) of the data to decrypt. Must be equal to the modulus size. */
    uint8_t *Output_ptr /* !< [out] Pointer to the decrypted data. The buffer size must be &le; the modulus size. */
);

/* !
@brief Implements the RSASP1 algorithm, as defined in [PKCS1_2.1] - 6.2.1, as a call to ::SaSi_RSA_PRIM_Decrypt_MTK,
since the signature primitive is identical to the decryption primitive.
*/
#define SaSi_RSA_PRIM_Sign SaSi_RSA_PRIM_Decrypt_MTK

/* !
@brief Implements the RSAVP1 algorithm, as defined in [PKCS1_2.1] - 6.2.2, as a call to ::SaSi_RSA_PRIM_Encrypt_MTK.
*/
#define SaSi_RSA_PRIM_Verify SaSi_RSA_PRIM_Encrypt_MTK

#ifdef __cplusplus
}
#endif

#endif
