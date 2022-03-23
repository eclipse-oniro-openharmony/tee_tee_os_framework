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

/*!
@file
@brief This file contains all of the enums and definitions
that are used for the CryptoCell HMAC APIs, as well as the APIs themselves.

HMAC is a wrapping algorithm that uses a HASH function (one of the supported HASH algorithms, as specified in the HASH chapter) and a key,
to generate a unique authentication code over the input data.
HMAC calculation can be performed in either of the following two modes of operation:
<ul><li> Integrated operation - Processes all data in a single function call. This flow is applicable when all data is available prior to
the cryptographic operation.</li>
<li> Block operation - Processes a subset of the data buffers, and is called multiple times in a sequence. This flow is applicable when
the next data buffer becomes available only during/after processing of the current data buffer.</li></ul>

The following is a typical HMAC Block operation flow:
<ol><li> ::CC_HmacInit: This function initializes the HMAC machine on the CryptoCell level by setting the context pointer that is
	used on the entire HMAC operation.</li>
<li> ::CC_HmacUpdate: This function runs an HMAC operation on a block of data allocated by the user. This function may be called as
     many times as required.</li>
<li> ::CC_HmacFinish: This function ends the HMAC operation. It returns the digest result and clears the context.</li></ol>
*/

#ifndef _CC_HMAC_H
#define _CC_HMAC_H


#include "cc_pal_types.h"
#include "cc_error.h"

#include "cc_hash.h"
#include "cc_hmac_defs.h"

#ifdef __cplusplus
extern "C"
{
#endif


/************************ Defines ******************************/

/* The HMAC key size after padding for MD5, SHA1, SHA256 */
#define CC_HMAC_KEY_SIZE_IN_BYTES 64

/* The HMAC key size after padding for SHA384, SHA512 */
#define CC_HMAC_SHA2_1024BIT_KEY_SIZE_IN_BYTES 128

/************************ Enums ********************************/

/************************ Typedefs  ****************************/

/*********************** Structures ****************************/


/* The user's context prototype - the argument type that is passed by the user
   to the APIs called */
typedef struct CCHmacUserContext_t {
	uint32_t buff[CC_HMAC_USER_CTX_SIZE_IN_WORDS];

}CCHmacUserContext_t;

/************************ Structs  ******************************/


/************************ Public Variables **********************/


/************************ Public Functions **********************/

/*!
@brief This function initializes the HMAC machine.

It allocates and initializes the HMAC Context. It initiates a HASH session and processes a HASH update on the Key XOR ipad,
then stores it in the context

@return CC_OK on success.
@return A non-zero value from cc_hmac_error.h on failure.
*/
CIMPORT_C CCError_t CC_HmacInit(
                        CCHmacUserContext_t     *ContextID_ptr,        /*!< [in]  Pointer to the HMAC context buffer allocated by the user, which is used
										      for the HMAC machine operation. */
                        CCHashOperationMode_t  OperationMode,          /*!< [in]  One of the supported HASH modes, as defined in CCHashOperationMode_t. */
                        uint8_t                    *key_ptr,           /*!< [in]  The pointer to the user's key buffer. */
                        size_t                    keySize              /*!< [in]  The key size in bytes. f the key size is bigger than the HASH block, the key will be hashed.
										 The limitations on the key size are the same as the limitations on MAX hash size.*/
);


/*!
@brief This function processes a block of data to be HASHed.

It receives a handle to the HMAC Context, and updates the HASH value with the new data.

@return CC_OK on success.
@return A non-zero value from cc_hmac_error.h on failure.
*/

CIMPORT_C CCError_t CC_HmacUpdate(
                        CCHmacUserContext_t  *ContextID_ptr,           /*!< [in]  Pointer to the HMAC context buffer allocated by the user
										   that is used for the HMAC machine operation. */
                        uint8_t                 *DataIn_ptr,           /*!< [in]  Pointer to the input data to be HASHed.
                                                                                   The size of the scatter/gather list representing the data buffer is limited to
										   128 entries, and the size of each entry is limited to 64KB
										   (fragments larger than 64KB are broken into fragments <= 64KB). */
                        size_t                  DataInSize             /*!< [in]  Byte size of the input data. Must be > 0.
                                                                                   If not a multiple of the HASH block size (64 for SHA-1 and SHA-224/256,
										   128 for SHA-384/512), no further calls to ::CC_HmacUpdate are allowed in
										   this context, and only ::CC_HmacFinish can be called to complete the
										   computation. */
);


/*!
@brief This function finalizes the HMAC processing of a data block.

It receives a handle to the HMAC context that was previously initialized by ::CC_HmacInit, or by ::CC_HmacUpdate.
It completes the HASH calculation on the ipad and text, and then executes a new HASH operation with the key XOR opad and the previous
HASH operation result.

@return CC_OK on success.
@return A non-zero value from cc_hmac_error.h on failure.
*/

CIMPORT_C CCError_t CC_HmacFinish(
                        CCHmacUserContext_t  *ContextID_ptr,         /*!< [in]  Pointer to the HMAC context buffer allocated by the user, which is used
										   for the HMAC machine operation. */
                        CCHashResultBuf_t       HmacResultBuff         /*!< [out] Pointer to the word-aligned 64 byte buffer. The actual size of the
										   HASH result depends on CCHashOperationMode_t. */
);


/*!
@brief This function is a service function that frees the context if the operation has failed.

The function executes the following major steps:
<ol><li> Checks the validity of all the inputs of the function. </li>
<li> Clears the user's context.</li>
<li> Exits the handler with the OK code.</li></ol>

@return CC_OK on success.
@return a non-zero value from cc_hmac_error.h on failure.
*/

CIMPORT_C CCError_t  CC_HmacFree(
                        CCHmacUserContext_t  *ContextID_ptr         /*!< [in]  Pointer to the HMAC context buffer allocated by the user, which is used for
										  the HMAC machine operation. */
);


/*!
@brief This function processes a single buffer of data, and returns the data buffer's message digest.

@return CC_OK on success.
@return A non-zero value from cc_hmac_error.h on failure.
*/
CIMPORT_C CCError_t CC_Hmac  (
                        CCHashOperationMode_t  OperationMode,       /*!< [in]  One of the supported HASH modes, as defined in CCHashOperationMode_t. */
                        uint8_t                    *key_ptr,            /*!< [in]  The pointer to the user's key buffer. */
                        size_t                    keySize,            /*!< [in]  The key size in bytes. If the key size is bigger than the HASH block, the key will be hashed.
										 The limitations on the key size are the same as the limitations on MAX hash size.*/
                        uint8_t                    *DataIn_ptr,         /*!< [in]  Pointer to the input data to be HASHed.
                                                                                   The size of the scatter/gather list representing the data buffer is limited to 128
										   entries, and the size of each entry is limited to 64KB (fragments larger than
										   64KB are broken into fragments <= 64KB). */
                        size_t                      DataSize,           /*!< [in]  The size of the data to be hashed (in bytes). */
                        CCHashResultBuf_t          HmacResultBuff      /*!< [out] Pointer to the word-aligned 64 byte buffer. The actual size of the
										   HMAC result depends on CCHashOperationMode_t. */
);
#ifdef __cplusplus
}
#endif

#endif
