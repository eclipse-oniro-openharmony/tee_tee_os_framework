/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* !
@file
@brief This file contains all of the enums and definitions
that are used for the SaSi HMAC APIs, as well as the APIs themselves.

HMAC is a wrapping algorithm that uses a HASH function (one of the supported HASH algorithms, as specified in the HASH
chapter) and a key, to generate a unique authentication code over the input data. HMAC calculation can be performed in
either of the following two modes of operation: <ul><li> Integrated operation - Processes all data in a single function
call. This flow is applicable when all data is available prior to the cryptographic operation.</li> <li> Block operation
- Processes a subset of the data buffers, and is called multiple times in a sequence. This flow is applicable when the
next data buffer becomes available only during/after processing of the current data buffer.</li></ul>

The following is a typical HMAC Block operation flow:
<ol><li> ::SaSi_HMAC_Init_MTK: This function initializes the HMAC machine on the SaSi level by setting the context
pointer that is used on the entire HMAC operation.</li> <li> ::SaSi_HMAC_Update_MTK: This function runs an HMAC
operation on a block of data allocated by the user. This function may be called as many times as required.</li> <li>
::SaSi_HMAC_Finish_MTK: This function ends the HMAC operation. It returns the digest result and clears the
context.</li></ol>
*/

#ifndef SaSi_HMAC_H
#define SaSi_HMAC_H

#include "ssi_pal_types.h"
#include "sasi_error.h"

#include "sasi_hash.h"
#include "sasi_hmac_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines **************************** */

/* The HMAC key size after padding for MD5, SHA1, SHA256 */
#define SaSi_HMAC_KEY_SIZE_IN_BYTES 64

/* The HMAC key size after padding for SHA384, SHA512 */
#define SaSi_HMAC_SHA2_1024BIT_KEY_SIZE_IN_BYTES 128

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* ********************** Structures ************************** */

/* The user's context prototype - the argument type that is passed by the user
   to the APIs called */
typedef struct SaSi_HMACUserContext_t {
    uint32_t buff[SaSi_HMAC_USER_CTX_SIZE_IN_WORDS];

} SaSi_HMACUserContext_t;

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

/* !
@brief This function initializes the HMAC machine.

It allocates and initializes the HMAC Context. It initiates a HASH session and processes a HASH update on the Key XOR
ipad, then stores it in the context

@return SaSi_OK on success.
@return A non-zero value from sasi_hmac_error.h on failure.
*/
CIMPORT_C SaSiError_t SaSi_HMAC_Init_MTK(
    SaSi_HMACUserContext_t *ContextID_ptr, /* !< [in]  Pointer to the HMAC context buffer allocated by the user, which is
              used for the HMAC machine operation. */
    SaSi_HASH_OperationMode_t
        OperationMode, /* !< [in]  One of the supported HASH modes, as defined in SaSi_HASH_OperationMode_t. */
    uint8_t *key_ptr,  /* !< [in]  The pointer to the user's key buffer. */
    uint16_t keySize   /* !< [in]  The key size in bytes. */
);

/* !
@brief This function processes a block of data to be HASHed.

It receives a handle to the HMAC Context, and updates the HASH value with the new data.

@return SaSi_OK on success.
@return A non-zero value from sasi_hmac_error.h on failure.
*/

CIMPORT_C SaSiError_t SaSi_HMAC_Update_MTK(
    SaSi_HMACUserContext_t *ContextID_ptr, /* !< [in]  Pointer to the HMAC context buffer allocated by the user
              that is used for the HMAC machine operation. */
    uint8_t *DataIn_ptr,                   /* !< [in]  Pointer to the input data to be HASHed.
                                                      The size of the scatter/gather list representing the data buffer is limited to
              128 entries, and the size of each entry is limited to 64KB
              (fragments larger than 64KB are broken into fragments <= 64KB). */
    uint32_t DataInSize                    /* !< [in]  Byte size of the input data. Must be > 0.
                                                      If not a multiple of the HASH block size (64 for SHA-1 and SHA-224/256,
              128 for SHA-384/512), no further calls to ::SaSi_HMAC_Update_MTK are allowed in
              this context, and only ::SaSi_HMAC_Finish_MTK can be called to complete the
              computation. */
);

/* !
@brief This function finalizes the HMAC processing of a data block.

It receives a handle to the HMAC context that was previously initialized by ::SaSi_HMAC_Init_MTK, or by
::SaSi_HMAC_Update_MTK. It completes the HASH calculation on the ipad and text, and then executes a new HASH operation
with the key XOR opad and the previous HASH operation result.

@return SaSi_OK on success.
@return A non-zero value from sasi_hmac_error.h on failure.
*/

CIMPORT_C SaSiError_t SaSi_HMAC_Finish_MTK(
    SaSi_HMACUserContext_t *ContextID_ptr, /* !< [in]  Pointer to the HMAC context buffer allocated by the user, which is
              used for the HMAC machine operation. */
    SaSi_HASH_Result_t HmacResultBuff      /* !< [out] Pointer to the word-aligned 64 byte buffer. The actual size of the
              HASH result depends on SaSi_HASH_OperationMode_t. */
);

/* !
@brief This function is a service function that frees the context if the operation has failed.

The function executes the following major steps:
<ol><li> Checks the validity of all of the inputs of the function. </li>
<li> Clears the user's context.</li>
<li> Exits the handler with the OK code.</li></ol>

@return SaSi_OK on success.
@return a non-zero value from sasi_hmac_error.h on failure.
*/

CIMPORT_C SaSiError_t SaSi_HMAC_Free_MTK(
    SaSi_HMACUserContext_t *ContextID_ptr /* !< [in]  Pointer to the HMAC context buffer allocated by the user, which is
             used for the HMAC machine operation. */
);

/* !
@brief This function processes a single buffer of data, and returns the data buffer's message digest.

@return SaSi_OK on success.
@return A non-zero value from sasi_hmac_error.h on failure.
*/
CIMPORT_C SaSiError_t SaSi_HMAC_MTK(
    SaSi_HASH_OperationMode_t
        OperationMode,   /* !< [in]  One of the supported HASH modes, as defined in SaSi_HASH_OperationMode_t. */
    uint8_t *key_ptr,    /* !< [in]  The pointer to the user's key buffer. */
    uint16_t keySize,    /* !< [in]  The key size in bytes. */
    uint8_t *DataIn_ptr, /* !< [in]  Pointer to the input data to be HASHed.
                                    The size of the scatter/gather list representing the data buffer is limited to 128
entries, and the size of each entry is limited to 64KB (fragments larger than
64KB are broken into fragments <= 64KB). */
    uint32_t DataSize,   /* !< [in]  The size of the data to be hashed (in bytes). */
    SaSi_HASH_Result_t HmacResultBuff /* !< [out] Pointer to the word-aligned 64 byte buffer. The actual size of the
         HMAC result depends on SaSi_HASH_OperationMode_t. */
);
#ifdef __cplusplus
}
#endif

#endif
