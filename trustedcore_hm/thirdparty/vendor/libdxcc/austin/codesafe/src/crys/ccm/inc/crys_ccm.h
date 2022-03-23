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

#ifndef CRYS_CCM_H
#define CRYS_CCM_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */

#include "crys_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Object %name    : %
 *  State           :  %state%
 *  Creation date   :  Wed Nov 17 17:44:53 2004
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief A brief description of this module
 *
 *  \version CRYS_CCM.h#1:incl:12
 *  \author adams
 */

/* *********************** Defines **************************** */

/* *********************** Enums ****************************** */
/* The enum determining the type of context to be allocated using the CRYS_CCM_GetContext function or released
   using the CRYS_CCM_ReleaseContext function */

typedef enum ContextType_enum {
    DX_HASH_MD5_CONTEXT,
    DX_HASH_SHA1_CONTEXT,
    DX_HMAC_CONTEXT,
    DX_DES_1KEY_CONTEXT,
    DX_DES_2KEY_CONTEXT,
    DX_DES_3KEY_CONTEXT,
    DX_RSA_SIGN_CONTEXT,
    DX_RSA_VERIFY_CONTEXT,
    DX_AES_CONTEXT,
    DX_RC4_CONTEXT,
    DX_ECDSA_SIGN_CONTEXT,
    DX_ECDSA_VERIFY_CONTEXT,
    DX_C2_CIPHER_CONTEXT,
    DX_C2_HASH_CONTEXT,
    DX_OTF_CONTEXT,
    DX_AESCCM_CONTEXT,

    ContextTypeLast = 0x7FFFFFFF,

} ContextType_t;

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

/* ------------------------------------------------------------
**
* @brief This function does the following:
*        1) activates a semaphore on the required context.
*        2) Allocates a free context managed by the context manager.
*        3) copies the information from the users context to the allocated context.
*        4) Decrypts the information in the context.
*
* @param[in] UserContext_ptr - The users context pointer.
* @param[in] Decrypt_flag - Weather or not to make a decrypt operation. e.g. in AES_Init a decrypt is not needed.
* @param[out] CRYS_GlobalContext_ptr - The returned pointer of the allocated context.
* @param[out] Type - The context type.
*
* @return CRYSError_t - On success CRYS_OK.
*/
CRYSError_t CRYS_CCM_GetContext(void *UserContext_ptr, void **CRYS_GlobalContext_ptr, ContextType_t Type);

#define CRYS_CCM_ReleaseContext(user, global, type) CRYS_OK

#define CRYS_CCM_Init() CRYS_OK

#define CRYS_CCM_Terminate() CRYS_OK

#ifdef __cplusplus
}
#endif

#endif
