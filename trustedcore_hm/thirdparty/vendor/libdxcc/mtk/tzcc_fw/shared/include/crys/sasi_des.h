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
that are used for the SaSi DES APIs, as well as the APIs themselves.

DES is a block cipher, i.e. it processes data in multiples of block size (8 bytes). DES data can be processed in one of
two modes of operation:

<ul><li> Integrated operation - Processes all data in a single function call. This flow is applicable when all data is
available prior to the cryptographic operation.</li> <li> Block operation - Processes a subset of the data buffers, and
is called multiple times in a sequence. This flow is applicable when the next data buffer becomes available only
during/after processing of the current data buffer.</li></ul>

The following is a typical DES Block operation flow:
<ol><li> ::SaSi_DES_Init_MTK - Initializes the SaSi DES machine by setting the context pointer that is used for the
entire DES operation.</li> <li> ::SaSi_DES_Block_MTK - Performs a DES operation on a block of data allocated by the
user. This function stores the relevant block information so that the user can operate on the next block by calling
SaSi_DES_Block_MTK again. It may be called as many times as required, until block n.</li> <li> ::SaSi_DES_Free_MTK -
This function releases the context data.</li></ol>

\note <ul id="noteb"><li> The input and output data buffers may point to the same memory, or they may be completely
disjoint. However, partially overlapping input and output data returns an error.</li> <li> In case FIPS certification
mode is set to ON: <ol><li> Illegal keys for TDEA (as defined in NIST SP 800-67) are not allowed.</li> <li> if the input
data size is bigger than 2^20 bytes than TDEA with 2 keys is not allowed (only 3 keys).</li></ol></ul>
*/

#ifndef SaSi_DES_H
#define SaSi_DES_H

#include "ssi_pal_types.h"
#include "sasi_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines **************************** */
/* ! The size of user's context prototype (see SaSi_DESUserContext_t) in words. */
/* In order to allow contiguous context the user context is doubled + 3 words for management */
#define SaSi_DES_USER_CTX_SIZE_IN_WORDS 131

/* ! The size of the IV or counter buffer (see ::SaSi_DES_Iv_t) in words. */
#define SaSi_DES_IV_SIZE_IN_WORDS 2
/* ! The size of the IV or counter buffer (see ::SaSi_DES_Iv_t) in bytes. */
#define SaSi_DES_IV_SIZE_IN_BYTES (SaSi_DES_IV_SIZE_IN_WORDS * sizeof(uint32_t))

/* ! The maximum number of KEYS supported by DES. */
#define SaSi_DES_MAX_NUMBER_OF_KEYS 3

/* ! The key size in words on the DES machine in words (see ::SaSi_DES_Key_32bit_t). */
#define SaSi_DES_KEY_SIZE_IN_WORDS 2
/* ! The key size in words on the DES machine in bytes (see ::SaSi_DES_Key_t). */
#define SaSi_DES_KEY_SIZE_IN_BYTES (SaSi_DES_KEY_SIZE_IN_WORDS * sizeof(uint32_t))

/* ! The DES block size in bytes. */
#define SaSi_DES_BLOCK_SIZE_IN_BYTES 8

/* ! The DES block size in words. */
#define SaSi_DES_BLOCK_SIZE_IN_WORDS 2

/* *********************** Enums ****************************** */

/* !
The number of keys supported on the DES machine.
*/
typedef enum {
    SaSi_DES_1_KeyInUse  = 1, /* !< Single key (56bit). */
    SaSi_DES_2_KeysInUse = 2, /* !< Two keys (112bit). */
    SaSi_DES_3_KeysInUse = 3, /* !< Three keys (168bit). */

    SaSi_DES_NumOfKeysOptions,

    SaSi_DES_NumOfKeysLast = 0x7FFFFFFF,

} SaSi_DES_NumOfKeys_t;

/* !
Encrypt or Decrypt operation mode.
*/
typedef enum {
    SaSi_DES_Encrypt = 0, /* !< Encrypt mode. */
    SaSi_DES_Decrypt = 1, /* !< Decrypt mode. */

    SaSi_DES_EncryptNumOfOptions,

    SaSi_DES_EncryptModeLast = 0x7FFFFFFF,

} SaSi_DES_EncryptMode_t;

/* !
DES operation mode.
*/
typedef enum {
    SaSi_DES_ECB_mode = 0, /* !< ECB mode. */
    SaSi_DES_CBC_mode = 1, /* !< CBC mode. */

    SaSi_DES_NumOfModes,

    SaSi_DES_OperationModeLast = 0x7FFFFFFF,

} SaSi_DES_OperationMode_t;

/* *********************** Typedefs  ************************** */

/* ! The IV buffer definition. */
typedef uint8_t SaSi_DES_Iv_t[SaSi_DES_IV_SIZE_IN_BYTES];

/* ! Defining the KEY argument - containing 3 keys maximum, in bytes. */
typedef struct SaSi_DES_Key_t {
    /* the key variables */
    uint8_t key1[SaSi_DES_KEY_SIZE_IN_BYTES];
    uint8_t key2[SaSi_DES_KEY_SIZE_IN_BYTES];
    uint8_t key3[SaSi_DES_KEY_SIZE_IN_BYTES];

} SaSi_DES_Key_t;

/* *********************** Structs  **************************** */

/* ! Defines the KEY argument - contains 3 keys maximum, in words. */
typedef struct {
    /* the key variables */
    uint32_t key1[SaSi_DES_KEY_SIZE_IN_WORDS];
    uint32_t key2[SaSi_DES_KEY_SIZE_IN_WORDS];
    uint32_t key3[SaSi_DES_KEY_SIZE_IN_WORDS];

} SaSi_DES_Key_32bit_t;

/* *********************** Structs  **************************** */

/* ! The user's context prototype - the argument type that is passed by the user
   to the APIs called. */
typedef struct SaSi_DESUserContext_t {
    uint32_t buff[SaSi_DES_USER_CTX_SIZE_IN_WORDS];
} SaSi_DESUserContext_t;

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

/* !
@brief This function is used to initialize the DES machine.
       To operate the DES machine, this should be the first function called.

@return SaSi_OK on success.
@return A non-zero value from sasi_des_error.h on failure.
*/
CIMPORT_C SaSiError_t SaSi_DES_Init_MTK(
    SaSi_DESUserContext_t *ContextID_ptr, /* !< [in]  Pointer to the DES context buffer allocated by the user, which is
                                             used for the DES machine operation. */
    SaSi_DES_Iv_t IV_ptr, /* !< [in]  The IV buffer. In ECB mode this parameter is not used. In CBC this parameter should
                             contain the IV values. */
    SaSi_DES_Key_t *Key_ptr, /* !< [in]  Pointer to the user's key buffer. */
    SaSi_DES_NumOfKeys_t
        NumOfKeys,                             /* !< [in]  The number of keys used: 1, 2 or 3 (defined by the enum).
                                                          One key implies DES encryption/decryption, two or three keys imply triple-DES. */
    SaSi_DES_EncryptMode_t EncryptDecryptFlag, /* !< [in]  A flag that determines whether the DES should perform an
                                                  Encrypt operation (0) or a Decrypt operation (1). */
    SaSi_DES_OperationMode_t OperationMode     /* !< [in]  The operation mode: ECB or CBC. */
);

/* !
@brief This function is used to process a block on the DES machine.
        This function should be called after the SaSi_DES_Init_MTK function was called.

@return SaSi_OK on success.
@return A non-zero value from sasi_des_error.h on failure.
*/
CIMPORT_C SaSiError_t SaSi_DES_Block_MTK(
    SaSi_DESUserContext_t
        *ContextID_ptr,  /* !< [in] Pointer to the DES context buffer allocated by the user, which is used for the DES
                            machine operation.
                                     This should be the same context used on the previous call of this session. */
    uint8_t *DataIn_ptr, /* !< [in]  The pointer to input data.
                                     The size of the scatter/gather list representing the data buffer is limited to 128
                            entries, and the size of each entry is limited to 64KB (fragments larger than 64KB are
                            broken into fragments <= 64KB). */
    uint32_t DataInSize, /* !< [in]  The size of the input data. Must be a multiple of the DES block size, 8 bytes. */
    uint8_t *DataOut_ptr /* !< [out] The pointer to the output data.
                                     The size of the scatter/gather list representing the data buffer is limited to 128
                            entries, and the size of each entry is limited to 64KB (fragments larger than 64KB are
                            broken into fragments <= 64KB). */
);

/* !
@brief This function is used to end the DES processing session.
       It is the last function called for the DES process.

@return SaSi_OK on success.
@return A non-zero value from sasi_des_error.h on failure.
*/
CIMPORT_C SaSiError_t SaSi_DES_Free_MTK(
    SaSi_DESUserContext_t *
        ContextID_ptr /* !< [in]  Pointer to the DES context buffer allocated by the user that is used for the DES
                         machine operation. This should be the same context that was used on the previous call of this
                         session. */
);

/* !
@brief This function is used to operate the DES machine in one integrated operation.

@return SaSi_OK on success.
@return A non-zero value from sasi_des_error.h on failure.
*/
CIMPORT_C SaSiError_t SaSi_DES_MTK(
    SaSi_DES_Iv_t IV_ptr,    /* !< [in]  The IV buffer in CBC mode. In ECB mode this parameter is not used. */
    SaSi_DES_Key_t *Key_ptr, /* !< [in]  Pointer to the user's key buffer. */
    SaSi_DES_NumOfKeys_t
        NumOfKeys, /* !< [in]  The number of keys used: single (56bit), double (112bit) or triple (168bit). */
    SaSi_DES_EncryptMode_t EncryptDecryptFlag, /* !< [in]  A flag that determines if the DES should perform an Encrypt
                                                  operation (0) or a Decrypt operation (1). */
    SaSi_DES_OperationMode_t OperationMode,    /* !< [in]  The operation mode: ECB or CBC. */
    uint8_t *DataIn_ptr,                       /* !< [in]  The pointer to the input data.
                                                             The size of the scatter/gather list representing the data buffer is limited to
                                                  128 entries,                       and the size of each entry is limited to 64KB (fragments larger than 64KB are
                                                  broken into fragments <= 64KB). */
    uint32_t DataInSize, /* !< [in]  The size of the input data. Must be a multiple of the DES block size, 8 bytes. */
    uint8_t *DataOut_ptr /* !< [out] The pointer to the output data.
                                       The size of the scatter/gather list representing the data buffer is limited to
                            128 entries, and the size of each entry is limited to 64KB (fragments larger than 64KB are
                            broken into fragments <= 64KB). */
);

#ifdef __cplusplus
}
#endif

#endif
