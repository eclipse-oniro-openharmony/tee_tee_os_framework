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
that are used for the SaSi HASH APIs, as well as the APIs themselves.

This product supports the following HASH algorithms (or modes, according to product):
<ul><li> SaSi_HASH_MD5 (producing 16 byte output).</li>
<li> SaSi_HASH_SHA1 (producing 20 byte output).</li>
<li> SaSi_HASH_SHA224 (producing 28 byte output).</li>
<li> SaSi_HASH_SHA256 (producing 32 byte output).</li>
<li> SaSi_HASH_SHA384 (producing 48 byte output).</li>
<li> SaSi_HASH_SHA512 (producing 64 byte output).</li></ul>

HASH calculation can be performed in either of the following two modes of operation:
<ul><li> Integrated operation - Processes all data in a single function call. This flow is applicable when all data is
available prior to the cryptographic operation.</li> <li> Block operation - Processes a subset of the data buffers, and
is called multiple times in a sequence. This flow is applicable when the next data buffer becomes available only
during/after processing of the current data buffer.</li></ul>

The following is a typical HASH Block operation flow:
<ol><li> ::SaSi_HASH_Init_MTK - this function initializes the HASH machine on the SaSi level by setting the context
pointer that is used on the entire HASH operation.</li> <li> ::SaSi_HASH_Update_MTK - this function runs a HASH
operation on a block of data allocated by the user. This function may be called as many times as required.</li> <li>
::SaSi_HASH_Finish_MTK - this function ends the HASH operation. It returns the digest result and clears the
context.</li></ol>
*/

#ifndef SaSi_HASH_H
#define SaSi_HASH_H

#include "ssi_pal_types.h"
#include "sasi_error.h"
#include "sasi_hash_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines **************************** */
/* The hash result in words
#define SaSi_HASH_RESULT_SIZE_IN_WORDS 5 */
/* The maximum hash result is 512 bits for SHA512 */
#define SaSi_HASH_RESULT_SIZE_IN_WORDS 16

/* The MD5 digest result size in bytes */
#define SaSi_HASH_MD5_DIGEST_SIZE_IN_BYTES 16

/* The MD5 digest result size in words */
#define SaSi_HASH_MD5_DIGEST_SIZE_IN_WORDS 4

/* The SHA-1 digest result size in bytes */
#define SaSi_HASH_SHA1_DIGEST_SIZE_IN_BYTES 20

/* The SHA-1 digest result size in words */
#define SaSi_HASH_SHA1_DIGEST_SIZE_IN_WORDS 5

/* The SHA-256 digest result size in bytes */
#define SaSi_HASH_SHA224_DIGEST_SIZE_IN_WORDS 7

/* The SHA-256 digest result size in bytes */
#define SaSi_HASH_SHA256_DIGEST_SIZE_IN_WORDS 8

/* The SHA-384 digest result size in bytes */
#define SaSi_HASH_SHA384_DIGEST_SIZE_IN_WORDS 12

/* The SHA-512 digest result size in bytes */
#define SaSi_HASH_SHA512_DIGEST_SIZE_IN_WORDS 16

/* The SHA-256 digest result size in bytes */
#define SaSi_HASH_SHA224_DIGEST_SIZE_IN_BYTES 28

/* The SHA-256 digest result size in bytes */
#define SaSi_HASH_SHA256_DIGEST_SIZE_IN_BYTES 32

/* The SHA-384 digest result size in bytes */
#define SaSi_HASH_SHA384_DIGEST_SIZE_IN_BYTES 48

/* The SHA-512 digest result size in bytes */
#define SaSi_HASH_SHA512_DIGEST_SIZE_IN_BYTES 64

/* The SHA1 hash block size in words */
#define SaSi_HASH_BLOCK_SIZE_IN_WORDS 16

/* The SHA1 hash block size in bytes */
#define SaSi_HASH_BLOCK_SIZE_IN_BYTES 64

/* The SHA2 hash block size in words */
#define SaSi_HASH_SHA512_BLOCK_SIZE_IN_WORDS 32

/* The SHA2 hash block size in bytes */
#define SaSi_HASH_SHA512_BLOCK_SIZE_IN_BYTES 128

/* *********************** Enums ****************************** */

/* !
HASH operation mode
*/
typedef enum {
    SaSi_HASH_SHA1_mode   = 0, /* !< SHA1 */
    SaSi_HASH_SHA224_mode = 1, /* !< SHA224 */
    SaSi_HASH_SHA256_mode = 2, /* !< SHA256 */
    SaSi_HASH_SHA384_mode = 3, /* !< SHA384 */
    SaSi_HASH_SHA512_mode = 4, /* !< SHA512 */
    SaSi_HASH_MD5_mode    = 5, /* !< MD5 */

    SaSi_HASH_NumOfModes,

    SaSi_HASH_OperationModeLast = 0x7FFFFFFF,

} SaSi_HASH_OperationMode_t;

/* *********************** Typedefs  *************************** */

/* ! Defines the HASH result buffer. */
typedef uint32_t SaSi_HASH_Result_t[SaSi_HASH_RESULT_SIZE_IN_WORDS];

/* *********************** Structs  **************************** */
/* ! The user's context prototype - the argument type that is passed by the user
   to the APIs called. */
typedef struct SaSi_HASHUserContext_t {
    uint32_t buff[SaSi_HASH_USER_CTX_SIZE_IN_WORDS];
} SaSi_HASHUserContext_t;

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

/* ********************************************************************************************* */
/* !
@brief This function initializes the HASH machine and the HASH Context.

It receives as input a pointer to store the context handle to the HASH Context,
and initializes the HASH Context with the cryptographic attributes that are needed for the HASH block operation
(initializes H's value for the HASH algorithm).

@return SaSi_OK on success.
@return A non-zero value from sasi_hash_error.h on failure.
*/
CIMPORT_C SaSiError_t SaSi_HASH_Init_MTK(
    SaSi_HASHUserContext_t *ContextID_ptr, /* !< [in]  Pointer to the HASH context buffer allocated by the user that is
        used for the HASH machine operation. */
    SaSi_HASH_OperationMode_t
        OperationMode /* !< [in]  One of the supported HASH modes, as defined in SaSi_HASH_OperationMode_t. */
);

/* ********************************************************************************************* */
/* !
@brief This function processes a block of data to be HASHed.

It updates a HASH Context that was previously initialized by SaSi_HASH_Init_MTK or updated by a previous call to
SaSi_HASH_Update_MTK.

@return SaSi_OK on success.
@return A non-zero value from sasi_hash_error.h on failure.
*/

CIMPORT_C SaSiError_t SaSi_HASH_Update_MTK(
    SaSi_HASHUserContext_t *ContextID_ptr, /* !< [in]  Pointer to the HASH context buffer allocated by the user, which is
              used for the HASH machine operation. */
    uint8_t *DataIn_ptr,                   /* !< [in]  Pointer to the input data to be HASHed.
                                                      The size of the scatter/gather list representing the data buffer is limited to
              128 entries, and the size of each entry is limited to 64KB
              (fragments larger than 64KB are broken into fragments <= 64KB). */
    uint32_t DataInSize                    /* !< [in]  Byte size of the input data. Must be > 0.
                                                       If not a multiple of the HASH block size (64 for MD5, SHA-1 and SHA-224/256,
               128 for SHA-384/512), no further calls
                                                       to SaSi_HASH_Update_MTK are allowed in this context, and only SaSi_HASH_Finish_MTK
               can be called to complete the computation. */
);

/* ********************************************************************************************* */
/* !
@brief This function finalizes the hashing process of data block.

It receives a handle to the HASH Context, which was previously initialized by SaSi_HASH_Init_MTK or by
SaSi_HASH_Update_MTK. It "adds" a header to the data block according to the relevant HASH standard, and computes the
final message digest.

@return SaSi_OK on success.
@return A non-zero value from sasi_hash_error.h on failure.
*/

CIMPORT_C SaSiError_t SaSi_HASH_Finish_MTK(
    SaSi_HASHUserContext_t *ContextID_ptr, /* !< [in]  Pointer to the HASH context buffer allocated by the user that is
              used for the HASH machine operation. */
    SaSi_HASH_Result_t HashResultBuff /* !< [in]  Pointer to the word-aligned 64 byte buffer. The actual size of the HASH
         result depends on SaSi_HASH_OperationMode_t. */
);

/* ********************************************************************************************* */
/* !
@brief This function is a utility function that frees the context if the operation has failed.

The function executes the following major steps:
<ol><li> Checks the validity of all of the inputs of the function. </li>
<li> Clears the user's context.</li>
<li> Exits the handler with the OK code.</li></ol>

@return SaSi_OK on success.
@return A non-zero value from sasi_hash_error.h on failure.
*/

CIMPORT_C SaSiError_t SaSi_HASH_Free_MTK(
    SaSi_HASHUserContext_t *ContextID_ptr /* !< [in]  Pointer to the HASH context buffer allocated by the user that is
            used for the HASH machine operation. */
);

/* ********************************************************************************************* */
/* !
@brief This function processes a single buffer of data.

The function allocates an internal HASH Context, and initializes it with the cryptographic attributes
that are needed for the HASH block operation (initialize H's value for the HASH algorithm).
Then it processes the data block, calculating the HASH. Finally, it returns the data buffer's message digest.

@return SaSi_OK on success.
@return A non-zero value from sasi_hash_error.h on failure.
 */

CIMPORT_C SaSiError_t SaSi_HASH_MTK(
    SaSi_HASH_OperationMode_t
        OperationMode,   /* !< [in]  One of the supported HASH modes, as defined in SaSi_HASH_OperationMode_t. */
    uint8_t *DataIn_ptr, /* !< [in]  Pointer to the input data to be HASHed.
                                    The size of the scatter/gather list representing the data buffer is limited
to 128 entries, and the size of each entry is limited to 64KB
(fragments larger than 64KB are broken into fragments <= 64KB). */
    uint32_t DataSize,   /* !< [in]  The size of the data to be hashed in bytes. */
    SaSi_HASH_Result_t HashResultBuff /* !< [out] Pointer to a word-aligned 64 byte buffer. The actual size of the HASH
         result depends on SaSi_HASH_OperationMode_t. */
);

#ifdef __cplusplus
}
#endif

#endif
