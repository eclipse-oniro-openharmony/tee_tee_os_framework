/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_AESCCM_H
#define SaSi_AESCCM_H

#include "ssi_pal_types.h"
#include "sasi_error.h"

#include "ssi_aes.h"
#include "ssi_aes_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* !
@file
@brief This file contains all of the enums and definitions that are used for the SaSi AESCCM APIs, as well as the APIs
themselves.
*/

/* *********************** Defines **************************** */

/* In order to allow contiguous context the user context is doubled + 3 words for management */
#define SaSi_AESCCM_USER_CTX_SIZE_IN_WORDS 133

/* key and key buffer sizes definitions */
#define SaSi_AESCCM_KEY_SIZE_WORDS 8

/* nonce and AESCCM-MAC sizes definitions */
#define SaSi_AESCCM_NONCE_MIN_SIZE_BYTES 7
#define SaSi_AESCCM_NONCE_MAX_SIZE_BYTES 13
#define SaSi_AESCCM_MAC_MIN_SIZE_BYTES   4
#define SaSi_AESCCM_MAC_MAX_SIZE_BYTES   16

/* AES CCM encrypt-decrypt mode */
#define SaSi_AESCCM_Decrypt SASI_AES_DECRYPT
#define SaSi_AESCCM_Encrypt SASI_AES_ENCRYPT

/* *********************** Typedefs  ************************** */

typedef enum {
    SaSi_AES_Key128BitSize = 0,
    SaSi_AES_Key192BitSize = 1,
    SaSi_AES_Key256BitSize = 2,
    SaSi_AES_Key512BitSize = 3,

    SaSi_AES_KeySizeNumOfOptions,

    SaSi_AES_KeySizeLast = 0x7FFFFFFF,

} SaSi_AESCCM_KeySize_t;

/* Defines the AES_CCM key buffer */
typedef uint8_t SaSi_AESCCM_Key_t[SaSi_AESCCM_KEY_SIZE_WORDS * sizeof(uint32_t)];
typedef uint8_t SaSi_AESCCM_Mac_Res_t[SASI_AES_BLOCK_SIZE_IN_BYTES];

/* ****************** Context Structure  ********************* */
/* The user's context structure - the argument type that is passed by the user
   to the APIs called */
typedef struct SaSi_AESCCM_UserContext_t {
    /* Allocated buffer must be double the size of actual context
     * + 1 word for offset management */
    uint32_t buff[SaSi_AESCCM_USER_CTX_SIZE_IN_WORDS];
} SaSi_AESCCM_UserContext_t;

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

/* !
@brief This function initializes the AES CCM context.

It formats of the input data, calculates AES-MAC value for the formatted B0 block containing control information and CCM
unique value (Nonce), and initializes the AES context structure including the initial CTR0 value. \note To be
FIPS-compliant, the user must use the AES CCM integrated function only.
@return SaSi_OK on success.
@return A non-zero value on failure as defined sasi_aesccm_error.h.
*/
SaSiError_t SaSi_AESCCM_Init(
    SaSi_AESCCM_UserContext_t *ContextID_ptr, /* !< [in]  Pointer to the AES context buffer that is allocated by the user
                                                 and is used for the AES operation. */
    SaSiAesEncryptMode_t EncrDecrMode,        /* !< [in]  Flag specifying whether Encrypt (::SASI_AES_ENCRYPT) or Decrypt
                                                 (::SASI_AES_DECRYPT) operation should be performed. */
    SaSi_AESCCM_Key_t CCM_Key,                /* !< [in]  Pointer to the AES-CCM key. */
    SaSi_AESCCM_KeySize_t KeySizeId,          /* !< [in]  Enumerator defining the key size (128, 192 or 256 bits). */
    uint32_t AdataSize,                       /* !< [in]  Full byte length of additional (associated) data.
                                                          If set to zero, calling ::SaSi_AESCCM_BlockAdata_MTK on the same context would
                                                 return an error. */
    uint32_t TextSize,                        /* !< [in]  Full length of plain text data. */
    uint8_t *N_ptr,                           /* !< [in]  Pointer to the Nonce. */
    uint8_t SizeOfN,                          /* !< [in]  Nonce byte size. Valid range = [7 .. 13]. */
    uint8_t SizeOfT /* !< [in]  AES-CCM MAC (tag) byte size. Valid range = [4, 6, 8, 10, 12, 14, 16]. */
);

/* !
@brief This function receives a CCM context and a block of additional data, and adds it to the AES MAC calculation.
This API can be called only once per operation context. It should not be called in case AdataSize was set to zero in
SaSi_AESCCM_BlockAdata_MTK. \note To be FIPS-compliant, the user must use the AES CCM integrated function only.
@return SaSi_OK on success.
@return A non-zero value on failure as defined sasi_aesccm_error.h.
*/
SaSiError_t
SaSi_AESCCM_BlockAdata_MTK(SaSi_AESCCM_UserContext_t *ContextID_ptr, /* !< [in]  Pointer to the context buffer. */
                           uint8_t *DataIn_ptr,                      /* !< [in]  Pointer to the additional input data.
                                                                                 The size of the scatter/gather list representing the data
                                             buffer is limited to 128 entries,                      and the size of each entry is limited to 64KB (fragments
                                             larger than 64KB are broken into                      fragments <= 64KB). */
                           uint32_t DataInSize /* !< [in]  Byte size of the additional data. Must match AdataSize
                                                  parameter provided to ::SaSi_AESCCM_Init. */
);

/* !
@brief This function can be invoked for any block of Text data whose size is a multiple of 16 bytes,
excluding the last block that has to be processed by ::SaSi_AESCCM_Finish.

<ul><li> If encrypting:
Continues calculation of the intermediate AES_MAC value of the text data, while simultaneously encrypting the text data
using AES_CTR, starting from CTR value = CTR0+1.</li> <li> If decrypting: Continues decryption of the text data, while
calculating the intermediate AES_MAC value of decrypted data.</li></ul> \note To be FIPS-compliant, the user must use
the AES CCM integrated function only.
@return SaSi_OK on success.
@return A non-zero value on failure as defined sasi_aesccm_error.h.
*/
SaSiError_t SaSi_AESCCM_BlockTextData(
    SaSi_AESCCM_UserContext_t *ContextID_ptr, /* !< [in]  Pointer to the context buffer. */
    uint8_t *DataIn_ptr,                      /* !< [in]  Pointer to the input data. */
    uint32_t
        DataInSize, /* !< [in]  Byte size of the text data block. Must be <= 512KB. Must be a multiple of 16 bytes. */
    uint8_t *
        DataOut_ptr /* !< [out] Pointer to the output data. The size of the output buffer must be at least DataInSize. */
);

/* !
@brief This function must be the last to be called on the text data.

It can either be called on the entire text data (if transferred as one block), or on the last block of the text data,
even if total size of text data is equal to 0. It performs the same operations as SaSi_AESCCM_BlockTextData, but
additionally: <ul><li> If encrypting: <ul><li> If the size of text data is not in multiples of 16 bytes, it pads the
remaining bytes with zeroes to a full 16-bytes block and processes the data using AES_MAC and AES_CTR algorithms.</li>
  <li> Encrypts the AES_MAC result with AES_CTR using the CTR0 value saved in the context and places the SizeOfT bytes
of MAC (tag) at the end.</li></ul> <li> If decrypting: <ul><li> Processes the text data, except for the last SizeOfT
bytes (tag), using AES_CTR and then AES_MAC algorithms.</li> <li> Encrypts the calculated MAC using AES_CTR based on the
saved CTR0 value, and compares it with SizeOfT last bytes of input data (i.e. tag value).</li> <li> The function saves
the validation result (Valid/Invalid) in the context.</li> <li> Returns (as the error code) the final CCM-MAC
verification result.</li></ul></ul> \note To be FIPS-compliant, the user must use the AES CCM integrated function only.
@return SaSi_OK on success.
@return A non-zero value on failure as defined sasi_aesccm_error.h.
*/
CEXPORT_C SaSiError_t SaSi_AESCCM_Finish(
    SaSi_AESCCM_UserContext_t *ContextID_ptr, /* !< [in]  Pointer to the context buffer. */
    uint8_t *DataIn_ptr,                      /* !< [in]  Pointer to the last input data. */
    uint32_t DataInSize,                      /* !< [in]  Byte size of the last text data block. Can be zero. */
    uint8_t *DataOut_ptr, /* !< [out]  Pointer to the output (cipher or plain text data) data. If DataInSize = 0, output
                             buffer is not required. */
    SaSi_AESCCM_Mac_Res_t MacRes, /* !< [in/out]  MAC result buffer pointer. */
    uint8_t *SizeOfT              /* !< [in]  AES-CCM MAC byte size as defined in SaSi_AESCCM_Init. */
);

/* ************************************************************************************************* */
/* *******                       AESCCM  FUNCTION                                              **** */
/* ************************************************************************************************* */
/* !
@brief This API performs AES CCM operation on a given data.
\note To be FIPS-compliant, the user must use the AES CCM integrated function only.
@return SaSi_OK on success.
@return A non-zero value on failure as defined sasi_aesccm_error.h.
*/
CIMPORT_C SaSiError_t SaSi_AESCCM_MTK(
    SaSiAesEncryptMode_t EncrDecrMode, /* !< [in]  A flag specifying whether an AES Encrypt (SaSi_AES_Encrypt) or Decrypt
                                          (SaSi_AES_Decrypt) operation should be performed. */
    SaSi_AESCCM_Key_t CCM_Key,         /* !< [in]  Pointer to AES-CCM key. */
    SaSi_AESCCM_KeySize_t KeySizeId,   /* !< [in]  Enumerator defining the key size (128, 192 or 256 bits). */
    uint8_t *N_ptr,                    /* !< [in]  Pointer to the Nonce. */
    uint8_t SizeOfN,                   /* !< [in]  Nonce byte size. Valid range = [7 .. 13]. */
    uint8_t *ADataIn_ptr,     /* !< [in]  Pointer to the additional input data. The size of the scatter/gather list
                                 representing the data buffer is limited to 128 entries, and the size of each entry is
                                 limited to 64KB (fragments larger than 64KB are broken into fragments <= 64KB). */
    uint32_t ADataInSize,     /* !< [in]  Byte size of the additional data. */
    uint8_t *TextDataIn_ptr,  /* !< [in]  Pointer to the plain-text data for encryption or cipher-text data for
                                 decryption. The size of the scatter/gather list representing the data buffer is limited
                                 to 128 entries, and the size of each entry is limited to 64KB (fragments larger than
                                 64KB are broken into fragments <= 64KB).  */
    uint32_t TextDataInSize,  /* !< [in]  Byte size of the full text data.  */
    uint8_t *TextDataOut_ptr, /* !< [out] Pointer to the output (cipher or plain text data according to encrypt-decrypt
                                 mode) data. The size of the scatter/gather list representing the data buffer is limited
                                 to 128 entries, and the size of each entry is limited to 64KB (fragments larger than
                                 64KB are broken into fragments <= 64KB).  */
    uint8_t SizeOfT,          /* !< [in]  AES-CCM MAC (tag) byte size. Valid range = [4, 6, 8, 10, 12, 14, 16]. */
    SaSi_AESCCM_Mac_Res_t Mac_Res /* !< [in/out] Pointer to the MAC result buffer. */
);

#ifdef __cplusplus
}
#endif

#endif /* #ifndef SaSi_AESCCM_H */
