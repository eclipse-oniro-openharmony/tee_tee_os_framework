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

#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_ASYM_RSA_DH

/* ************ Include Files ************** */

#include "dx_pal_mem.h"
#include <stdbool.h>
#include "crys_rsa_error.h"
#ifndef DX_OEM_FW
#include "crys.h"
#else
#include "oem_crys.h"
#endif
#include "crys_common_math.h"
#include "crys_ccm.h"
#include "crys_rsa_local.h"
#include "crys_bypass_api.h"

#ifndef DX_OEM_FW
#include "cc_acl.h"
#endif

/* *********************** Defines **************************** */

/* canceling the lint warning:
   Use of goto is deprecated */

#if (CRYS_HASH_USER_CTX_SIZE_IN_WORDS > CRYS_PKA_RSA_HASH_CTX_SIZE_IN_WORDS)
#error CRYS_PKA_RSA_HASH_CTX_SIZE_IN_WORDS OR CRYS_HASH_USER_CTX_SIZE_IN_WORDS do not defined correctly.
#endif

/* *********************** Enums **************************** */
/* *********************** Typedefs ************************* */
/* *********************** Global Data ********************** */

/* ************ Private function prototype ****************** */

#ifndef _INTERNAL_CRYS_NO_RSA_VERIFY_SUPPORT

/* *********************** Private Functions **************************** */

/*
   \brief  RSA_VerifyInit initializes the Verify
   multi-call algorithm as defined in PKCS#1 v1.5 and 2.1

    The actual macro that will be used by the user is:
    CRYS_RSA_PKCS1v15_VerifyInit - for v1.5
    CRYS_RSA_PSS_VerifyInit      - for v2.1

    NOTE: 1. In PSS_Sign v2.1 MD5 is not supported, since it is not recommended
         by the PKCS#1 v2.1.
          2. According to thesaid standard, implementation of the function
         for version v1.5 is based on DER encoding of the algorithm info.


   @param[in] UserContext_ptr - A pointer to the public Context
             structure of the User.
   @param[in] UserPubKey_ptr - A pointer to the public key data
               structure.
   @param[in] rsaHashMode - The hash function to be used. Currently
             avaliable HASH functions: SHA1/SHA-256/384/512/MD5
             (MD5 - allowed only for PKCS#1 v1.5).
             Also allowed "After" HASH modes for said functions.
   @param[in] MGF - The mask generation function, relevant only for PKCS#1 v2.1.
            The currently allowed value for v2.1 is CRYS_PKCS1_MGF1.
   @param[in] SaltLen - The Length of the Salt buffer. Relevant for PKCS#1 Ver 2.1 only.
            Typical lengths are 0 and hashLen (20 for SHA1).
            The maximum length allowed is NSize - hLen - 2.
            If the salt length is not available in this process, the user
            can use the define: CRYS_RSA_VERIFY_SALT_LENGTH_UNKNOWN.
            Security Note: it is recommended not to use this flag and provide
                    the Salt length on each verify
   @param[in] PKCS1_ver - Ver 1.5 or 2.1, according to the functionality required.

   @return CRYSError_t - CRYS_OK, CRYS_INVALID_SIGNATURE,
             CRYS_BAD_PARAM, CRYS_OUT_OF_RANGE
*/

CEXPORT_C CRYSError_t _DX_RSA_VerifyInit(CRYS_RSAPubUserContext_t *UserContext_ptr,
                                         CRYS_RSAUserPubKey_t *UserPubKey_ptr, CRYS_RSA_HASH_OpMode_t rsaHashMode,
                                         CRYS_PKCS1_MGF_t MGF, uint16_t SaltLen, CRYS_PKCS1_version PKCS1_ver)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    CRYSError_t Error = CRYS_OK;

    /* defining a pointer to the active context allcated by the CCM */
    RSAPubContext_t *ccmWorkingContext_ptr;
    /* Pointer to the public key for lengths checking */
    CRYSRSAPubKey_t *PubKey_ptr;
    /* The size of the modulus for lengths checking */
    uint32_t ModulusSizeBytes;

    /* FUNCTION LOGIC */

    /* ............... local initializations .............................. */
    /* -------------------------------------------------------------------- */

    /* initialize the module size to cancel compilers warnings */
    ModulusSizeBytes = 0;

    /* ............... if not supported exit .............................. */
    /* -------------------------------------------------------------------- */

    RETURN_IF_RSA_UNSUPPORTED(UserContext_ptr, UserPubKey_ptr, rsaHashMode, MGF, SaltLen, PKCS1_ver,
                              ccmWorkingContext_ptr, PubKey_ptr, ModulusSizeBytes, Error, Error, Error, Error, Error,
                              Error, Error, Error, Error, Error, Error, Error, Error);

#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context ID pointer is DX_NULL return an error */
    if (UserContext_ptr == DX_NULL)
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;

    /* if the private key object is DX_NULL return an error */
    if (UserPubKey_ptr == DX_NULL)
        return CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

    /* check if the hash operation mode is legal */
    if (rsaHashMode >= CRYS_RSA_HASH_NumOfModes)
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;

    /* check if the MGF operation mode is legal */
    if (CRYS_RSA_NumOfMGFFunctions <= MGF)
        return CRYS_RSA_MGF_ILLEGAL_ARG_ERROR;

    /* check that the PKCS1 version argument is legal */
    if (PKCS1_ver >= CRYS_RSA_NumOf_PKCS1_versions)
        return CRYS_RSA_PKCS1_VER_ARG_ERROR;

    /* According to the PKCS1 ver 2.1 standart it is not recommended to use MD5 hash
         therefore we do not support it */
    if (PKCS1_ver == CRYS_PKCS1_VER21 && rsaHashMode == CRYS_RSA_HASH_MD5_mode)
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;

#ifndef DX_OEM_FW
    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, UserContext_ptr, sizeof(CRYS_RSAPubUserContext_t)) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ, UserPubKey_ptr, sizeof(CRYS_RSAUserPubKey_t))) {
        return CRYS_RSA_ILLEGAL_PARAMS_ACCORDING_TO_PRIV_ERROR;
    }
#endif

    /* If the validation tag is incorrect */
    if (UserPubKey_ptr->valid_tag != CRYS_RSA_PUB_KEY_VALIDATION_TAG)
        return CRYS_RSA_PUB_KEY_VALIDATION_TAG_ERROR;

    /* Checking if a check on salt length is needed */
    if (SaltLen != CRYS_RSA_VERIFY_SALT_LENGTH_UNKNOWN && PKCS1_ver == CRYS_PKCS1_VER21) {
        /* Initializing the Modulus Size in Bytes needed for SaltLength parameter check */
        PubKey_ptr = (CRYSRSAPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;

        /* Note: the (-1) is due to the PKCS#1 Ver2.1 standard section 9.1.1 */
        ModulusSizeBytes = (PubKey_ptr->nSizeInBits - 1) / 8;
        if ((PubKey_ptr->nSizeInBits - 1) % 8)
            ModulusSizeBytes++;
    }

    /* ............... initializing local variables ................ */
    /* ------------------------------------------------------------- */

    ccmWorkingContext_ptr = (RSAPubContext_t *)UserContext_ptr->context_buff;

    /* Reset the Context handler for improper previous values initialized */
    DX_PAL_MemSet(UserContext_ptr, 0, sizeof(CRYS_RSAPubUserContext_t));

    /* Initializing the Hash operation mode in the RSA Context level */
    /* ------------------------------------------------------------- */

    ccmWorkingContext_ptr->doHash               = true;
    ccmWorkingContext_ptr->RsaHashOperationMode = rsaHashMode;
    ccmWorkingContext_ptr->HashBlockSize        = CRYS_HASH_BLOCK_SIZE_IN_WORDS;

    /*  Set other HASH parameters */
    switch (ccmWorkingContext_ptr->RsaHashOperationMode) {
    case CRYS_RSA_HASH_MD5_mode:
    case CRYS_RSA_After_MD5_mode:
        ccmWorkingContext_ptr->HASH_Result_Size  = CRYS_HASH_MD5_DIGEST_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashOperationMode = CRYS_HASH_MD5_mode;
        break;
    case CRYS_RSA_HASH_SHA1_mode:
    case CRYS_RSA_After_SHA1_mode:
        ccmWorkingContext_ptr->HASH_Result_Size  = CRYS_HASH_SHA1_DIGEST_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashOperationMode = CRYS_HASH_SHA1_mode;
        break;
    case CRYS_RSA_HASH_SHA224_mode:
    case CRYS_RSA_After_SHA224_mode:
        ccmWorkingContext_ptr->HASH_Result_Size  = CRYS_HASH_SHA224_DIGEST_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashOperationMode = CRYS_HASH_SHA224_mode;
        break;
    case CRYS_RSA_HASH_SHA256_mode:
    case CRYS_RSA_After_SHA256_mode:
        ccmWorkingContext_ptr->HASH_Result_Size  = CRYS_HASH_SHA256_DIGEST_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashOperationMode = CRYS_HASH_SHA256_mode;
        break;
    case CRYS_RSA_HASH_SHA384_mode:
    case CRYS_RSA_After_SHA384_mode:
        ccmWorkingContext_ptr->HASH_Result_Size  = CRYS_HASH_SHA384_DIGEST_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashBlockSize     = CRYS_HASH_SHA512_BLOCK_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashOperationMode = CRYS_HASH_SHA384_mode;
        break;
    case CRYS_RSA_HASH_SHA512_mode:
    case CRYS_RSA_After_SHA512_mode:
        ccmWorkingContext_ptr->HASH_Result_Size  = CRYS_HASH_SHA512_DIGEST_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashBlockSize     = CRYS_HASH_SHA512_BLOCK_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashOperationMode = CRYS_HASH_SHA512_mode;
        break;
    default:
        Error = CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
        goto END_WITH_ERROR;
    }

    /* set doHash=false for after Hash modes */
    switch (ccmWorkingContext_ptr->RsaHashOperationMode) {
    case CRYS_RSA_After_MD5_mode:
    case CRYS_RSA_After_SHA1_mode:
    case CRYS_RSA_After_SHA224_mode:
    case CRYS_RSA_After_SHA256_mode:
    case CRYS_RSA_After_SHA384_mode:
    case CRYS_RSA_After_SHA512_mode:
        ccmWorkingContext_ptr->doHash = false;
        break;
    default:
        break;
    }

    /* Init HASH */
    if (ccmWorkingContext_ptr->doHash) {
        Error = CRYS_HASH_Init(((CRYS_HASHUserContext_t *)((ccmWorkingContext_ptr->CRYSPKAHashCtxBuff))),
                               ccmWorkingContext_ptr->HashOperationMode);
        if (Error != CRYS_OK)
            goto END_WITH_ERROR;
    }

    /* Switch to appropriate PKCS1_version */
    /* ------------------------------------- */
    switch (PKCS1_ver) {
    case CRYS_PKCS1_VER15:
        ccmWorkingContext_ptr->PKCS1_Version = CRYS_PKCS1_VER15;
        break;
    case CRYS_PKCS1_VER21:
        ccmWorkingContext_ptr->PKCS1_Version = CRYS_PKCS1_VER21;
        /* Checking restriction of Salt Length ; Hash output size and the mosulus */
        if (SaltLen != CRYS_RSA_VERIFY_SALT_LENGTH_UNKNOWN &&
            ModulusSizeBytes < (uint32_t)(ccmWorkingContext_ptr->HASH_Result_Size * 4 + SaltLen + 2)) {
            Error = CRYS_RSA_PSS_ENCODING_MODULUS_HASH_SALT_LENGTHS_ERROR;
            goto END_WITH_ERROR;
        }
        break;
    default:
        Error = CRYS_RSA_PKCS1_VER_ARG_ERROR;
        goto END_WITH_ERROR;
    }

    switch (MGF) {
    case CRYS_PKCS1_MGF1:
    case CRYS_PKCS1_NO_MGF:
        ccmWorkingContext_ptr->MGF_2use = MGF;
        break;
    default:
        Error = CRYS_RSA_MGF_ILLEGAL_ARG_ERROR;
        goto END_WITH_ERROR;
    }

    /* Copy the RSA Pub key to the context */
    DX_PAL_MemCopy((uint8_t *)&ccmWorkingContext_ptr->PubUserKey, (uint8_t *)UserPubKey_ptr,
                   sizeof(CRYS_RSAUserPubKey_t));

    /* Initial the Salt random length relevant for PKCS#1 Ver2.1 */
    ccmWorkingContext_ptr->SaltLen = SaltLen;

    /* Initialize the size of the modulus */
    ccmWorkingContext_ptr->nSizeInBytes = (((CRYSRSAPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff)->nSizeInBits + 7) / 8;

    /* set the RSA tag to the users context */
    UserContext_ptr->valid_tag = CRYS_RSA_VERIFY_CONTEXT_VALIDATION_TAG;

    return Error;

END_WITH_ERROR:

    /* .............. clearing the users context in case of error.......... */
    /* -------------------------------------------------------------------- */
    DX_PAL_MemSet(UserContext_ptr, 0, sizeof(CRYS_RSAPubUserContext_t));

    return Error;

#endif /* !CRYS_NO_HASH_SUPPORT */
#endif /* !CRYS_NO_PKI_SUPPORT */

} /* END OF _DX_RSA_VerifyInit */

/* ******************************************************************************************************* */
/*
   \brief RSA_VerifyUpdate processes the data to be verified
   in a given context, according to PKCS1 v1.5 and 2.1

   \note RSA_VerifyUpdate can be called multiple times with data

    The actual macro that will be used by the user is:
    CRYS_RSA_PKCS1v15_VerifyUpdate        - for v1.5
    CRYS_RSA_PSS_VerifyUpdate        - for v2.1

   @param[in] UserContext_ptr - A pointer to the public Context
                               structure of the User.
   @param[in] DataIn_ptr - A pointer to the data whose signature is
                         to be verified.
   @param[in] DataInSize - The size, in bytes, of the data whose
                         signature is to be verified.

   @return CRYSError_t - CRYS_OK, CRYS_INVALID_SIGNATURE,
                         CRYS_BAD_PARAM, CRYS_OUT_OF_RANGE
*/

CEXPORT_C CRYSError_t _DX_RSA_VerifyUpdate(CRYS_RSAPubUserContext_t *UserContext_ptr, uint8_t *DataIn_ptr,
                                           uint32_t DataInSize)
{
    /* FUNCTION DECLERATIONS */

    /* The return error identifier */
    CRYSError_t Error = CRYS_OK;
    /* defining a pointer to the active context allcated by the CCM */
    RSAPubContext_t *ccmWorkingContext_ptr;

    /* FUNCTION LOGIC */

    /* ............... if not supported exit .............................. */
    /* -------------------------------------------------------------------- */

    RETURN_IF_RSA_UNSUPPORTED(UserContext_ptr, DataIn_ptr, DataInSize, ccmWorkingContext_ptr, Error, Error, Error,
                              Error, Error, Error, Error, Error, Error, Error, Error, Error, Error, Error, Error, Error,
                              Error, Error);

#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context pointer is DX_NULL return an error */
    if (UserContext_ptr == DX_NULL)
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;

    /* if the users Data In pointer is illegal return an error */
    if (DataIn_ptr == DX_NULL && DataInSize)
        return CRYS_RSA_DATA_POINTER_INVALID_ERROR;

    /* if the data size is larger then 2^29 (to prevant an overflow on the transition to bits )
       return error */
    if (DataInSize >= (1UL << 29))
        return CRYS_RSA_INVALID_MESSAGE_DATA_SIZE;

#ifndef DX_OEM_FW
    /* DataIn can be smart pointer but it is tested either in the hash or in bypass operations */
    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, UserContext_ptr, sizeof(CRYS_RSAPubUserContext_t)) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ, DataIn_ptr, DataInSize)) {
        return CRYS_RSA_ILLEGAL_PARAMS_ACCORDING_TO_PRIV_ERROR;
    }
#endif

    /* if the users context TAG is illegal return an error - the context is invalid */
    if (UserContext_ptr->valid_tag != CRYS_RSA_VERIFY_CONTEXT_VALIDATION_TAG)
        return CRYS_RSA_USER_CONTEXT_VALIDATION_TAG_ERROR;

    /*  extract the RSA context structure */
    ccmWorkingContext_ptr = (RSAPubContext_t *)UserContext_ptr->context_buff;

    switch (ccmWorkingContext_ptr->RsaHashOperationMode) {
    /* The mode is either SHA1 or MD5 */
    case CRYS_RSA_HASH_SHA1_mode:
    case CRYS_RSA_HASH_MD5_mode:
    case CRYS_RSA_HASH_SHA224_mode:
    case CRYS_RSA_HASH_SHA256_mode:
    case CRYS_RSA_HASH_SHA384_mode:
    case CRYS_RSA_HASH_SHA512_mode:
        /* Operate the Hash update function for relevant versions */
        Error = CRYS_HASH_Update(((CRYS_HASHUserContext_t *)(ccmWorkingContext_ptr->CRYSPKAHashCtxBuff)), DataIn_ptr,
                                 DataInSize);
        if (Error != CRYS_OK)
            goto END_WITH_ERROR;
        break;

    case CRYS_RSA_After_SHA1_mode:
    case CRYS_RSA_After_SHA224_mode:
    case CRYS_RSA_After_SHA256_mode:
    case CRYS_RSA_After_SHA384_mode:
    case CRYS_RSA_After_SHA512_mode:
    case CRYS_RSA_After_MD5_mode:
        /* DataInSize must fit exactly to the size of Hash output that we support */
        if (DataInSize != ccmWorkingContext_ptr->HASH_Result_Size * sizeof(uint32_t)) {
            Error = CRYS_RSA_INVALID_MESSAGE_DATA_SIZE_IN_SSL_CASE;
            goto END_WITH_ERROR;
        }
        /* Copy the DataIn_ptr to the HashResult in case it is an SSL mode */
        Error = CRYS_Bypass(DataIn_ptr, DataInSize, (uint8_t *)ccmWorkingContext_ptr->HASH_Result);
        if (Error != CRYS_OK)
            goto END_WITH_ERROR;
        break;

    default:
        Error = CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
        goto END_WITH_ERROR;
    }

    return Error;

END_WITH_ERROR:

    /* ..... clearing the users context in case of error  .... */
    DX_PAL_MemSet(UserContext_ptr, 0, sizeof(CRYS_RSAPubUserContext_t));

    return Error;

#endif /* !CRYS_NO_HASH_SUPPORT */
#endif /* !CRYS_NO_PKI_SUPPORT */

} /* END OF _DX_RSA_VerifyUpdate */

/* ******************************************************************************************************* */
/*

   \brief RSA_VerifyFinish implements the Finish Phase of the Verify algorithm
   as defined in PKCS#1 v2.1 or PKCS#1 v1.5

    The actual macro that will be used by the user is:
    CRYS_RSA_PKCS1v15_VerifyFinish - for v1.5
    CRYS_RSA_PSS_VerifyFinish       - for v2.1

   @param[in] UserContext_ptr - A pointer to the public Context
                               structure of the User.
   @param[in] Sig_ptr - A pointer to the signature to be verified.
                        The length of the signature is PubKey_ptr->N.len bytes
                        (that is, the size of the modulus, in bytes).

   @return CRYSError_t - CRYS_OK, CRYS_INVALID_SIGNATURE,
                         CRYS_BAD_PARAM, CRYS_OUT_OF_RANGE
*/

CEXPORT_C CRYSError_t _DX_RSA_VerifyFinish(CRYS_RSAPubUserContext_t *UserContext_ptr, uint8_t *Sig_ptr)
{
    /* FUNCTION DECLERATIONS */

    /* The return error identifier */
    CRYSError_t Error = CRYS_OK;

    /* defining a pointer to the active context allcated by the CCM */
    RSAPubContext_t *ccmWorkingContext_ptr;

    /* Parameter for the new size of the modulus N in bytes according to PKCS1 Ver 2.1 */
    uint16_t modSizeBytes; /* rounded number of Bytes for padding2 length */

    /* Temporary for the N size */
    CRYSRSAPubKey_t *PubKey_ptr;

    /* FUNCTION LOGIC */

    /* ............... if not supported exit .............................. */
    /* -------------------------------------------------------------------- */
    RETURN_IF_RSA_UNSUPPORTED(UserContext_ptr, Sig_ptr, ccmWorkingContext_ptr, Error, modSizeBytes, PubKey_ptr, Error,
                              Error, Error, Error, Error, Error, Error, Error, Error, Error, Error, Error, Error, Error,
                              Error, Error);

#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context pointer is DX_NULL return an error */
    if (UserContext_ptr == DX_NULL)
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;

    /* if the users context pointer is DX_NULL return an error */
    if (Sig_ptr == DX_NULL)
        return CRYS_RSA_INVALID_SIGNATURE_BUFFER_POINTER;

#ifndef DX_OEM_FW
    /* sizeof signature need to be fixed */
    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, UserContext_ptr, sizeof(CRYS_RSAPubUserContext_t)) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, Sig_ptr, sizeof(uint32_t))) {
        return CRYS_RSA_ILLEGAL_PARAMS_ACCORDING_TO_PRIV_ERROR;
    }
#endif

    /* if the users context TAG is illegal return an error - the context is invalid */
    if (UserContext_ptr->valid_tag != CRYS_RSA_VERIFY_CONTEXT_VALIDATION_TAG)
        return CRYS_RSA_USER_CONTEXT_VALIDATION_TAG_ERROR;

    /* ................. aquiring the RSA context ............................. */
    ccmWorkingContext_ptr = (RSAPubContext_t *)UserContext_ptr->context_buff;
    PubKey_ptr            = (CRYSRSAPubKey_t *)ccmWorkingContext_ptr->PubUserKey.PublicKeyDbBuff;
    modSizeBytes          = (uint16_t)((PubKey_ptr->nSizeInBits + 7) / 8);

    /* execute the RSA encription of formatted sign block */
    Error = CRYS_RSA_PRIM_Encrypt(&ccmWorkingContext_ptr->PubUserKey, &ccmWorkingContext_ptr->PrimeData, Sig_ptr,
                                  modSizeBytes, (uint8_t *)ccmWorkingContext_ptr->EBD);
    if (Error != CRYS_OK)
        goto END_WITH_ERROR;

    /* Initialize the Effective size in bits of the result */
    ccmWorkingContext_ptr->EBDSizeInBits =
        CRYS_COMMON_GetBytesCounterEffectiveSizeInBits((uint8_t *)&ccmWorkingContext_ptr->EBD, modSizeBytes);

    /* Operating the HASH Finish function only in case that Hash operation is needed */
    if (ccmWorkingContext_ptr->doHash) {
        /* Operating the HASH Finish function */
        Error = CRYS_HASH_Finish(((CRYS_HASHUserContext_t *)(ccmWorkingContext_ptr->CRYSPKAHashCtxBuff)),
                                 ccmWorkingContext_ptr->HASH_Result);
    }
    if (Error != CRYS_OK)
        goto END_WITH_ERROR;

    /* ------------------------------------- */
    /* switch to appropriate PKCS1 Version */
    /* ------------------------------------- */
    switch (ccmWorkingContext_ptr->PKCS1_Version) {
#ifndef _INTERNAL_CRYS_NO_RSA_SCHEME_21_SUPPORT
    case CRYS_PKCS1_VER21:
        /* Operating the Verify primitive */
        Error = CRYS_RSA_PSS_Verify21(ccmWorkingContext_ptr);
        if (Error != CRYS_OK)
            goto END_WITH_ERROR;
        break;
#endif

#ifndef _INTERNAL_CRYS_NO_RSA_SCHEME_15_SUPPORT
    case CRYS_PKCS1_VER15:

        /* Create expected decrypted signature buff.  */
        Error = DX_RSA_EMSA_PKCS1_v15_Encode(modSizeBytes, ccmWorkingContext_ptr->HashOperationMode,
                                             (uint8_t *)ccmWorkingContext_ptr->HASH_Result,
                                             ccmWorkingContext_ptr->HASH_Result_Size * sizeof(uint32_t),
                                             (uint8_t *)&ccmWorkingContext_ptr->PrimeData /* expected buff */);
        if (Error != CRYS_OK)
            goto END_WITH_ERROR;

        /* compare actual and expected values of signature buffer */
        if (DX_PAL_MemCmp(&ccmWorkingContext_ptr->PrimeData, (uint8_t *)ccmWorkingContext_ptr->EBD, modSizeBytes)) {
            Error = CRYS_RSA_ERROR_VER15_INCONSISTENT_VERIFY;
            goto END_WITH_ERROR;
        }
        break;
#endif
    default:
        Error = CRYS_RSA_PKCS1_VER_ARG_ERROR;
        goto END_WITH_ERROR;

    } /* End of switch() */

END_WITH_ERROR:
    /* ..... clearing the users context in case of error ..... */
    DX_PAL_MemSet(UserContext_ptr, 0, sizeof(CRYS_RSAPubUserContext_t));

    return Error;

#endif /* !CRYS_NO_HASH_SUPPORT */
#endif /* !CRYS_NO_PKI_SUPPORT */

} /* END OF _DX_RSA_VerifyFinish */

/* ******************************************************************************************************* */
/*
   \brief RSA_Verify implements the RSASSA-PKCS1v15 algorithm
    in a single function as defined in PKCS#1 v2.1 (including v1.5).

    The user can call the function by appropriate macro according to choosen
    (and allowed) HASH algorithm SHA1, SHA224... (see macros below).

    NOTE: 1. In PSS_Verify v2.1 MD5 is not supported, since it is not recommended
         by the PKCS#1 ver2.1.
          2. According to the said standard, implementation of the function
         for version v1.5 is based on DER encoding of hash algorithm ID.


   @param[in] UserContext_ptr - A pointer to the public Context,
                   for the use of the function as a space to work on
   @param[in] UserPubKey_ptr - A pointer to the public key data
                           structure of the user.
   @param[in] rsaHashMode - The hash function to be used. Currently
              avaliable HASH functions: SHA1/SHA-224/256/384/512, MD5
              (MD5 - allowed only for PKCS#1 v1.5).
              Also allowed "After" HASH modes for said functions.
   @param[in] MGF - The mask generation function. only for PKCS#1 v2.1
                    defines MGF1, so the only value allowed for v2.1
                    is CRYS_PKCS1_MGF1.
   @param[in] SaltLen - The Length of the Salt buffer. relevant for PKCS#1 Ver 2.1 Only
            Typical lengths are 0 and hLen (20 for SHA1)
            The maximum length allowed is NSize - hLen - 2
   @param[in] DataIn_ptr - A pointer to the data whose signature is
                         to be verified.
   @param[in] DataInSize - The size, in bytes, of the data whose
                         signature is to be verified.
   @param[in] Sig_ptr - A pointer to the signature to be verified.
                        The length of the signature is PubKey_ptr->N.len bytes
                        (that is, the size of the modulus, in bytes).
   @param[in] PKCS1_ver - Ver 1.5 or 2.1, according to the functionality required

   @return CRYSError_t - CRYS_OK, CRYS_INVALID_SIGNATURE,
                         CRYS_BAD_PARAM, CRYS_OUT_OF_RANGE
*/

CEXPORT_C CRYSError_t _DX_RSA_Verify(CRYS_RSAPubUserContext_t *UserContext_ptr, CRYS_RSAUserPubKey_t *UserPubKey_ptr,
                                     CRYS_RSA_HASH_OpMode_t rsaHashMode, CRYS_PKCS1_MGF_t MGF, uint16_t SaltLen,
                                     uint8_t *DataIn_ptr, uint32_t DataInSize, uint8_t *Sig_ptr,
                                     CRYS_PKCS1_version PKCS1_ver)
{
    /* FUNCTION DECLERATIONS */

    /* The return error identifier */
    CRYSError_t Error = CRYS_OK;

    /* FUNCTION LOGIC */

    /* ............... if not supported exit .............................. */
    /* -------------------------------------------------------------------- */

    RETURN_IF_RSA_UNSUPPORTED(UserContext_ptr, UserPubKey_ptr, rsaHashMode, MGF, SaltLen, DataIn_ptr, DataInSize,
                              Sig_ptr, PKCS1_ver, Error, Error, Error, Error, Error, Error, Error, Error, Error, Error,
                              Error, Error, Error);

#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

    /* *********************************************************************
     *  RSA_VerifyInit
     * ******************************************************************* */
    Error = _DX_RSA_VerifyInit(UserContext_ptr, UserPubKey_ptr, rsaHashMode, MGF, SaltLen, PKCS1_ver);
    if (Error != CRYS_OK)
        return Error;

    /* *********************************************************************
     *  RSA_VerifyUpdate
     * ******************************************************************* */
    Error = _DX_RSA_VerifyUpdate(UserContext_ptr, DataIn_ptr, DataInSize);
    if (Error != CRYS_OK)
        return Error;

    /* *********************************************************************
     *  RSA_VerifyFinish
     * ******************************************************************* */
    Error = _DX_RSA_VerifyFinish(UserContext_ptr, Sig_ptr);

    return Error;

#endif /* !CRYS_NO_HASH_SUPPORT */
#endif /* !CRYS_NO_PKI_SUPPORT */

} /* END OF _DX_RSA_Verify */

#endif /* _INTERNAL_CRYS_NO_RSA_VERIFY_SUPPORT */
