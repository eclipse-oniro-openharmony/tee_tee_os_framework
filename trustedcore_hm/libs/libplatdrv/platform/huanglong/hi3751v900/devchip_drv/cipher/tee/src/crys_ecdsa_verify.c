/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: ecdsa verify
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "crys_ecpki_error.h"
#include "crys_ecpki_local.h"
#include "crys_ecpki_ecdsa.h"
#include "crys_cipher_common.h"
#include "drv_osal_lib.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"

#define BYTE_BIT_WIDTH 8
#define OFFSET_31 31
#define OFFSET_7 7

/*  canceling the lint warning:
   Warning 548: else expected  */
/* lint --e{548}  */
/*  canceling the lint warning:
Info 801: Use of goto is deprecated  */
/* lint --e{801}  */
/* *********************** Defines **************************************** */
#if (CRYS_HASH_USER_CTX_SIZE_IN_WORDS > CRYS_PKA_RSA_HASH_CTX_SIZE_IN_WORDS)
#error CRYS_PKA_RSA_HASH_CTX_SIZE_IN_WORDS OR CRYS_HASH_USER_CTX_SIZE_IN_WORDS do not defined correctly.
#endif

/* *********************** Public Functions ******************************* */
static CEXPORT_C CRYSError_t crys_ecdsa_hash_info(CRYS_ECPKI_HASH_OpMode_t hash_mode,
                                                 CRYS_HASH_OperationMode_t *operation_mode,
                                                 hi_u32 *hash_word_len,
                                                 hi_bool *is_after_hash)
{
    *operation_mode = CRYS_HASH_NumOfModes;
    *hash_word_len = 0;
    *is_after_hash = HI_FALSE;

    switch (hash_mode) {
        case CRYS_ECPKI_AFTER_HASH_SHA1_mode:
            *is_after_hash = HI_TRUE;
            *operation_mode = CRYS_HASH_SHA1_mode;
            *hash_word_len = CRYS_HASH_SHA1_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_HASH_SHA1_mode:
            *operation_mode = CRYS_HASH_SHA1_mode;
            *hash_word_len = CRYS_HASH_SHA1_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_AFTER_HASH_SHA224_mode:
            *is_after_hash = HI_TRUE;
            *operation_mode = CRYS_HASH_SHA224_mode;
            *hash_word_len = CRYS_HASH_SHA224_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_HASH_SHA224_mode:
            *operation_mode = CRYS_HASH_SHA224_mode;
            *hash_word_len = CRYS_HASH_SHA224_DIGEST_SIZE_IN_WORDS;
            break;

        case CRYS_ECPKI_AFTER_HASH_SHA256_mode:
            *is_after_hash = HI_TRUE;
            *operation_mode = CRYS_HASH_SHA256_mode;
            *hash_word_len = CRYS_HASH_SHA256_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_HASH_SHA256_mode:
            *operation_mode = CRYS_HASH_SHA256_mode;
            *hash_word_len = CRYS_HASH_SHA256_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_AFTER_HASH_SHA384_mode:
            *is_after_hash = HI_TRUE;
            *operation_mode = CRYS_HASH_SHA384_mode;
            *hash_word_len = CRYS_HASH_SHA384_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_HASH_SHA384_mode:
            *operation_mode = CRYS_HASH_SHA384_mode;
            *hash_word_len = CRYS_HASH_SHA384_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_AFTER_HASH_SHA512_mode:
            *is_after_hash = HI_TRUE;
            *operation_mode = CRYS_HASH_SHA512_mode;
            *hash_word_len = CRYS_HASH_SHA512_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_HASH_SHA512_mode:
            *operation_mode = CRYS_HASH_SHA512_mode;
            *hash_word_len = CRYS_HASH_SHA512_DIGEST_SIZE_IN_WORDS;
            break;
        default:
            hi_log_error("Invalid hash mode %d\n", hash_mode);
            return CRYS_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR;
    }

    return CRYS_OK;
}

/**************************************************************************
 *                  CRYS_ECDSA_VerifyInit  function
 **************************************************************************/
/**
   @brief  Prepares a context that is used by the Update and Finish functions
           but does not perform elliptic curve cryptographic processing

            The function:
            - Receives and decrypts user data (working context).
            - Checks input parameters of  ECDSA Vrifying primitive.
            - Calls hash init function.
            - Initializes variables and structures for calling next functions.
            - Encrypts and releases working context.

            NOTE: Using of HASH functions with HASH size great, than EC modulus size,
            is not recommended!

   @param[in,out] VerifyUserContext_ptr - A pointer to the user buffer for verifying database.
   @param[in] Signerpub_key - A pointer to a Signer public key structure.
   @param[in] HashMode - The enumerator variable defines the hash function to be used.

   @return <b>CRYSError_t</b>: <br>
             CRYS_OK<br>
                         CRYS_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR <br>
             CRYS_ECDSA_VERIFY_INVALID_SIGNER_PUBL_KEY_PTR_ERROR <br>
                         CRYS_ECDSA_VERIFY_SIGNER_PUBL_KEY_VALIDATION_TAG_ERROR <br>
                         CRYS_ECDSA_VERIFY_INVALID_DOMAIN_ID_ERROR <br>
             CRYS_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR <br>
**/
CEXPORT_C CRYSError_t _CRYS_ECDSA_VerifyInit(
        CRYS_ECDSA_VerifyUserContext_t *VerifyUserContext_ptr, /* in/out */
        CRYS_ECPKI_UserPublKey_t *Signerpub_key, /* in */
        CRYS_ECPKI_HASH_OpMode_t HashMode /* in */)
{
    CRYSError_t error;
    CRYSError_t end_error;
    ECDSA_VerifyContext_t *working_context = HI_NULL;
    CRYS_ECPKI_PublKey_t *pub_key = HI_NULL;
    CRYS_ECPKI_DomainID_t domain_id;
    CRYS_HASH_OperationMode_t operation_mode = CRYS_HASH_NumOfModes;
    hi_u32 hash_word_len = 0;
    hi_bool is_after_hash = HI_FALSE;

    /* if the users context ID pointer is DX_NULL return an error */
    if (VerifyUserContext_ptr == DX_NULL) {
        return CRYS_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR;
    }

    /* if the private key pointer is DX_NULL or its validation tag is not valid return an error */
    if (Signerpub_key == DX_NULL) {
        return CRYS_ECDSA_VERIFY_INVALID_SIGNER_PUBL_KEY_PTR_ERROR;
    }

    /* check if the hash operation mode is legal */
    if (HashMode >= CRYS_ECPKI_HASH_NumOfModes) {
        return CRYS_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR;
    }

    if (Signerpub_key->valid_tag != CRYS_ECPKI_PUBL_KEY_VALIDATION_TAG) {
        return CRYS_ECDSA_VERIFY_SIGNER_PUBL_KEY_VALIDATION_TAG_ERROR;
    }

    /* Initializing the domain_id */
    pub_key = (CRYS_ECPKI_PublKey_t *)((void *)Signerpub_key->PublKeyDbBuff);
    domain_id = pub_key->DomainID;

    /* ...... Continue checking: check the EC domain ID.................... */
    if (domain_id >= CRYS_ECPKI_DomainID_OffMode) {
        return CRYS_ECDSA_VERIFY_INVALID_DOMAIN_ID_ERROR;
    }

    working_context = (ECDSA_VerifyContext_t *)VerifyUserContext_ptr->context_buff;

    /* Reset the Context handler for improper previous values initialized */
    error = memset_s(working_context, sizeof(ECDSA_VerifyContext_t), 0, sizeof(ECDSA_VerifyContext_t));
    if (error != 0) {
        hi_log_print_func_err(memset_s, error);
        return error;
    }

    error = crys_ecdsa_hash_info(HashMode, &operation_mode, &hash_word_len, &is_after_hash);
    if (error != CRYS_OK) {
        hi_log_print_func_err(crys_ecdsa_hash_info, error);
        goto END_WITH_ERROR;
    }

    if (is_after_hash == HI_FALSE) {
        error = CRYS_HASH_Init(((CRYS_HASHUserContext_t *)(working_context->CRYSPKAHashCtxBuff)),
                               operation_mode);
        if (error != CRYS_OK) {
            hi_log_print_func_err(CRYS_HASH_Init, error);
            goto END_WITH_ERROR;
        }
    }

    /* Copying the ECPKI Public key value to the context */
    error = memcpy_s((DxUint8_t *)&working_context->ECDSA_SignerPublKey,
                     sizeof(working_context->ECDSA_SignerPublKey),
                     (DxUint8_t *)Signerpub_key, sizeof(CRYS_ECPKI_UserPublKey_t));
    if (error != CRYS_OK) {
        hi_log_print_func_err(memcpy_s, error);
        goto END_WITH_ERROR;
    }

    /* set the ECDSA tag to the users context */
    VerifyUserContext_ptr->valid_tag = CRYS_ECDSA_VERIFY_CONTEXT_VALIDATION_TAG;
    working_context->HashMode = HashMode;
    working_context->HASH_Result_Size = hash_word_len;

    return error;

END_WITH_ERROR:

    /* .............. clearing the users context in case of error.......... */
    /* -------------------------------------------------------------------- */
    end_error = memset_s(VerifyUserContext_ptr, sizeof(CRYS_ECDSA_VerifyUserContext_t),
                         0, sizeof(CRYS_ECDSA_VerifyUserContext_t));
    if (end_error != 0) {
        hi_log_print_func_err(memset_s, end_error);
        return end_error;
    }

    hi_log_print_err_code(error);
    return error;
} /* _DX_ECDSA_VerifyInit */

/**************************************************************************
 *                  CRYS_ECDSA_VerifyUpdate function
 **************************************************************************/
/**
   @brief  Performs a hash  operation on data allocated by the user
           before finally verifying its signature.

          In case user divides signing data by block, he must call the Update function
          continuously a number of times until processing of the entire data block is complete.

       NOTE: Using of HASH functions with HASH size great, than EC modulus size,
             is not recommended!

   @param[in,out] VerifyUserContext_ptr A pointer to the user buffer for verifying database.
   @param[in]       MessageDataIn_ptr   Message data for calculating Hash.
   @param[in]     DataInSize            The size of the message data block, in bytes.

   @return <b>CRYSError_t</b>: <br>
             CRYS_OK<br>
                         CRYS_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR <br>
             CRYS_ECDSA_VERIFY_USER_CONTEXT_VALIDATION_TAG_ERROR <br>
             CRYS_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_PTR_ERROR <br>
             CRYS_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_SIZE_ERROR <br>
             CRYS_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR <br>
 **/
CEXPORT_C CRYSError_t _CRYS_ECDSA_VerifyUpdate(
        CRYS_ECDSA_VerifyUserContext_t *VerifyUserContext_ptr, /* in/out */
        DxUint8_t *MessageDataIn_ptr, /* in */
        DxUint32_t DataInSize /* in */)
{
    /* The return error identifier */
    CRYSError_t error;
    CRYSError_t end_error;

    /* defining a pointer to the active context allcated by the CCM */
    ECDSA_VerifyContext_t *working_context = HI_NULL;
    CRYS_HASH_OperationMode_t operation_mode = CRYS_HASH_NumOfModes;
    hi_u32 hash_word_len = 0;
    hi_bool is_after_hash = HI_FALSE;

    /* if the users context pointer is DX_NULL return an error */
    if (VerifyUserContext_ptr == DX_NULL) {
        return CRYS_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR;
    }

    /* if the users context TAG is illegal return an error - the context is invalid */
    if (VerifyUserContext_ptr->valid_tag != CRYS_ECDSA_VERIFY_CONTEXT_VALIDATION_TAG) {
        return CRYS_ECDSA_VERIFY_USER_CONTEXT_VALIDATION_TAG_ERROR;
    }

    /* if the users MessageDataIn pointer is illegal return an error */
    if (MessageDataIn_ptr == DX_NULL && DataInSize) {
        return CRYS_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_PTR_ERROR;
    }

    /* if the data size is larger then 2^29 (to prevent an overflow on the transition to bits )
      return error */
    if (DataInSize >= (1UL << 29)) { /* left shift 29 */
        return CRYS_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_SIZE_ERROR;
    }

    working_context = (ECDSA_VerifyContext_t *)VerifyUserContext_ptr->context_buff;

    error = crys_ecdsa_hash_info(working_context->HashMode, &operation_mode, &hash_word_len, &is_after_hash);
    if (error != CRYS_OK) {
        hi_log_print_func_err(crys_ecdsa_hash_info, error);
        goto END_WITH_ERROR;
    }

    if (is_after_hash == HI_FALSE) {
        /* Operate the Hash update function for relevant version */
        error = CRYS_HASH_Update(((CRYS_HASHUserContext_t *)(working_context->CRYSPKAHashCtxBuff)),
                                 MessageDataIn_ptr, DataInSize);
    } else {
        if (DataInSize != hash_word_len * 4) { /* 4 bits */
            /* DataInSize must fit exactly to the size of Hash output that we support */
            error = CRYS_ECDSA_SIGN_INVALID_MESSAGE_DATA_IN_SIZE_ERROR;
            goto END_WITH_ERROR;
        }

        if (MessageDataIn_ptr != DX_NULL) {
            /* Copy the DataIn_ptr to the hash_result */
            error = memcpy_s((DxUint8_t *)working_context->HASH_Result,
                             sizeof(working_context->HASH_Result), MessageDataIn_ptr, DataInSize);
            if (error != CRYS_OK) {
                hi_log_print_func_err(memcpy_s, error);
                return error;
            }
        }
    }

    return error;

END_WITH_ERROR:

    /* .............. clearing the users context in case of error.......... */
    /* -------------------------------------------------------------------- */
    end_error = memset_s(VerifyUserContext_ptr, sizeof(CRYS_ECDSA_VerifyUserContext_t),
                         0, sizeof(CRYS_ECDSA_VerifyUserContext_t));
    if (end_error != 0) {
        hi_log_print_func_err(memset_s, end_error);
        return end_error;
    }

    hi_log_print_err_code(error);
    return error;
} /* CRYS_ECDSA_VerifyUpdate */

/**************************************************************************
 *                  CRYS_ECDSA_VerifyFinish function
 **************************************************************************/
/**
   @brief  Performs initialization of variables and structures,
           calls the hash function for the last block of data (if necessary),
              than calls LLF_ECDSA_VerifyCalcCall function for verifying signature
           according to EC DSA algorithm.

       NOTE: Using of HASH functions with HASH size great, than EC modulus size,
             is not recommended!

   @param[in] VerifyUserContext_ptr - A pointer to the user buffer for verifying the database.
   @param[in] SignatureIn_ptr       - A pointer to a buffer for the signature to be compared
   @param[in] SignatureSizeBytes    - The size of a user passed signature (must be 2*OrderSizeInBytes).

   @return <b>CRYSError_t</b>: <br>
              CRYS_OK <br>
              CRYS_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR <br>
              CRYS_ECDSA_VERIFY_USER_CONTEXT_VALIDATION_TAG_ERROR <br>
              CRYS_ECDSA_VERIFY_INVALID_SIGNATURE_IN_PTR_ERROR <br>
              CRYS_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR <br>
              CRYS_ECDSA_VERIFY_INVALID_SIGNATURE_SIZE_ERROR <br>
              CRYS_ECDSA_VERIFY_INVALID_DOMAIN_ID_ERROR <br>
              CRYS_ECDSA_VERIFY_INCONSISTENT_VERIFY_ERROR <br>
**/
CEXPORT_C CRYSError_t _CRYS_ECDSA_VerifyFinish(
        CRYS_ECDSA_VerifyUserContext_t *VerifyUserContext_ptr, /* in */
        DxUint8_t *SignatureIn_ptr, /* in */
        DxUint32_t SignatureSizeBytes /* in */)
{
    CRYSError_t error;
    CRYSError_t end_error;
    ECDSA_VerifyContext_t *working_context = HI_NULL;
    CRYS_ECPKI_PublKey_t *pub_key = HI_NULL;
    CRYS_ECPKI_DomainID_t domain_id;
    DxUint32_t mod_size_in_byte;
    DxUint32_t hash_size_in_byte;
    DxUint8_t *temp_buff = HI_NULL;
    CRYS_HASH_OperationMode_t operation_mode = CRYS_HASH_NumOfModes;
    hi_u32 hash_word_len = 0;
    hi_bool is_after_hash = HI_FALSE;
    hi_u32 pad_len = 0;
    ecc_param_t ecc;
    hi_u8 *signature = HI_NULL;

    /* if the users context pointer is DX_NULL return an error */
    if (VerifyUserContext_ptr == DX_NULL) {
        return CRYS_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR;
    }

    /* if the users context TAG is illegal return an error - the context is invalid */
    if (VerifyUserContext_ptr->valid_tag != CRYS_ECDSA_VERIFY_CONTEXT_VALIDATION_TAG) {
        return CRYS_ECDSA_VERIFY_USER_CONTEXT_VALIDATION_TAG_ERROR;
    }

    /* if the users Signature pointer is illegal then return an error */
    if (SignatureIn_ptr == DX_NULL) {
        return CRYS_ECDSA_VERIFY_INVALID_SIGNATURE_IN_PTR_ERROR;
    }

    working_context = (ECDSA_VerifyContext_t *)VerifyUserContext_ptr->context_buff;

    if (working_context->HashMode >= CRYS_ECPKI_HASH_NumOfModes) {
        error = CRYS_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR;
        hi_log_print_err_code(error);
        goto END_WITH_ERROR;
    }

    pub_key = (CRYS_ECPKI_PublKey_t *)(void *)working_context->ECDSA_SignerPublKey.PublKeyDbBuff;
    domain_id = pub_key->DomainID;
    error = crys_ecdsa_hash_info(working_context->HashMode, &operation_mode, &hash_word_len, &is_after_hash);
    if (error != CRYS_OK) {
        hi_log_print_func_err(crys_ecdsa_hash_info, error);
        goto END_WITH_ERROR;
    }

    error = crys_ecp_load_group(domain_id, &ecc, &pad_len);
    if (error != CRYS_OK) {
        hi_log_print_func_err(crys_ecp_load_group, error);
        goto END_WITH_ERROR;
    }

    signature = crypto_calloc(1, ecc.ksize + ecc.ksize);
    if (signature == HI_NULL) {
        hi_log_print_func_err(malloc, error);
        goto END_WITH_ERROR;
    }

    /*  Modulus sizes  */
    mod_size_in_byte = ecc.ksize - pad_len;
    hash_size_in_byte = hash_word_len * WORD_WIDTH;

    /* Temp buffers */
    temp_buff = (hi_u8 *)working_context->crysEcdsaVerIntBuff;

    /* if the user signature size is not equal to 2*mod_size_in_bytes, then return an error */
    if (SignatureSizeBytes != 2 * mod_size_in_byte) {
        error = CRYS_ECDSA_VERIFY_INVALID_SIGNATURE_SIZE_ERROR;
        hi_log_print_err_code(error);
        goto END_WITH_ERROR;
    }

    /* Operating the HASH Finish function only in case that Hash operation is needed */
    if (is_after_hash == HI_FALSE) {
        error = CRYS_HASH_Finish(((CRYS_HASHUserContext_t *)(working_context->CRYSPKAHashCtxBuff)),
                                 working_context->HASH_Result);
        if (error != CRYS_OK) {
            hi_log_print_func_err(CRYS_HASH_Finish, error);
            goto END_WITH_ERROR;
        }
    }

    error = memset_s(temp_buff, CRYS_PKA_ECDSA_VERIFY_BUFF_MAX_LENGTH_IN_WORDS * WORD_WIDTH, 0,
        CRYS_PKA_ECDSA_VERIFY_BUFF_MAX_LENGTH_IN_WORDS * WORD_WIDTH);
    if (error != CRYS_OK) {
        hi_log_print_func_err(memset_s, error);
        goto END_WITH_ERROR;
    }

    error = crys_bn2bin(pub_key->PublKeyX, temp_buff + pad_len, mod_size_in_byte);
    if (error != CRYS_OK) {
        hi_log_print_func_err(crys_bn2bin, error);
        goto END_WITH_ERROR;
    }

    error = crys_bn2bin(pub_key->PublKeyY, temp_buff + ecc.ksize + pad_len, mod_size_in_byte);
    if (error != CRYS_OK) {
        hi_log_print_func_err(crys_bn2bin, error);
        goto END_WITH_ERROR;
    }

    asm_memmove(signature + pad_len, SignatureIn_ptr, mod_size_in_byte);
    asm_memmove(signature + ecc.ksize + pad_len, SignatureIn_ptr + mod_size_in_byte, mod_size_in_byte);

    error = kapi_ecdsa_verify_hash(&ecc, temp_buff, temp_buff + ecc.ksize,
                                   (hi_u8 *)working_context->HASH_Result, hash_size_in_byte,
                                   signature, signature + ecc.ksize);
    if (error != CRYS_OK) {
        hi_log_print_func_err(mbedtls_ecdsa_verify, error);
        goto END_WITH_ERROR;
    }
    error = memset_s(VerifyUserContext_ptr, sizeof(CRYS_ECDSA_VerifyUserContext_t),
                     0, sizeof(CRYS_ECDSA_VerifyUserContext_t));
    if (error != 0) {
        hi_log_print_func_err(memset_s, error);
        goto END_WITH_ERROR;
    }

    return HI_SUCCESS;

END_WITH_ERROR:
    if (signature != HI_NULL) {
        free(signature);
    }

    end_error = memset_s(VerifyUserContext_ptr, sizeof(CRYS_ECDSA_VerifyUserContext_t),
                         0, sizeof(CRYS_ECDSA_VerifyUserContext_t));
    if (end_error != 0) {
        hi_log_print_func_err(memset_s, end_error);
        return end_error;
    }

    hi_log_print_err_code(error);
    return error;
} /* End DX_ECDSA_VerifyFinish */

CEXPORT_C CRYSError_t CRYS_ECDSA_VerifyInit(
        CRYS_ECDSA_VerifyUserContext_t *VerifyUserContext_ptr, /* in/out */
        CRYS_ECPKI_UserPublKey_t *Signerpub_key, /* in */
        CRYS_ECPKI_HASH_OpMode_t HashMode /* in */)
{
    CRYS_ECPKI_UserPublKey_t *verify_pub_key = HI_NULL;
    CRYSError_t error;

    if (Signerpub_key == DX_NULL) {
        return CRYS_ECDSA_SIGN_INVALID_USER_PRIV_KEY_PTR_ERROR;
    }

    verify_pub_key = (CRYS_ECPKI_UserPublKey_t *)crypto_malloc(sizeof(CRYS_ECPKI_UserPublKey_t));
    if (verify_pub_key == HI_NULL) {
        hi_log_error("malloc for pstSignerPrivKey falied\n");
        return CRYS_FATAL_ERROR;
    }
    error = memcpy_s(verify_pub_key, sizeof(CRYS_ECPKI_UserPublKey_t), Signerpub_key,
                     sizeof(CRYS_ECPKI_UserPublKey_t));
    if (error != CRYS_OK) {
        hi_log_print_func_err(memcpy_s, error);
        goto END_WITH_ERROR;
    }

    error = _CRYS_ECDSA_VerifyInit(VerifyUserContext_ptr, verify_pub_key, HashMode);
    if (error != CRYS_OK) {
        hi_log_print_func_err(_CRYS_ECDSA_VerifyInit, error);
        goto END_WITH_ERROR;
    }

END_WITH_ERROR:
    if (verify_pub_key != HI_NULL) {
        crypto_free(verify_pub_key);
        verify_pub_key = HI_NULL;
    }

    return error;
}

CEXPORT_C CRYSError_t CRYS_ECDSA_VerifyUpdate(
        CRYS_ECDSA_VerifyUserContext_t *VerifyUserContext_ptr, /* in/out */
        DxUint8_t *MessageDataIn_ptr, /* in */
        DxUint32_t DataInSize /* in */)
{
    CRYS_ECDSA_VerifyUserContext_t *verify_user_context = HI_NULL;
    CRYSError_t error;

    if (VerifyUserContext_ptr == DX_NULL) {
        return CRYS_ECDSA_SIGN_INVALID_USER_PRIV_KEY_PTR_ERROR;
    }

    verify_user_context = (CRYS_ECDSA_VerifyUserContext_t *)crypto_malloc(sizeof(CRYS_ECDSA_VerifyUserContext_t));
    if (verify_user_context == HI_NULL) {
        hi_log_error("malloc for sign_user_context falied\n");
        return CRYS_FATAL_ERROR;
    }
    error = memcpy_s(verify_user_context, sizeof(CRYS_ECDSA_VerifyUserContext_t),
                     VerifyUserContext_ptr, sizeof(CRYS_ECDSA_VerifyUserContext_t));
    if (error != CRYS_OK) {
        hi_log_print_func_err(memcpy_s, error);
        goto END_WITH_ERROR;
    }

    error = _CRYS_ECDSA_VerifyUpdate(verify_user_context, MessageDataIn_ptr, DataInSize);
    if (error != CRYS_OK) {
        hi_log_print_func_err(_CRYS_ECDSA_VerifyUpdate, error);
        goto END_WITH_ERROR;
    }

    error = memcpy_s(VerifyUserContext_ptr, sizeof(CRYS_ECDSA_VerifyUserContext_t),
                     verify_user_context, sizeof(CRYS_ECDSA_VerifyUserContext_t));
    if (error != CRYS_OK) {
        hi_log_print_func_err(memcpy_s, error);
        goto END_WITH_ERROR;
    }

END_WITH_ERROR:
    if (verify_user_context != HI_NULL) {
        crypto_free(verify_user_context);
        verify_user_context = HI_NULL;
    }

    return error;
}

CEXPORT_C CRYSError_t CRYS_ECDSA_VerifyFinish(
        CRYS_ECDSA_VerifyUserContext_t *VerifyUserContext_ptr, /* in */
        DxUint8_t *SignatureIn_ptr, /* in */
        DxUint32_t SignatureSizeBytes /* in */)
{
    CRYS_ECDSA_VerifyUserContext_t *verify_user_context = HI_NULL;
    CRYSError_t error;

    if (VerifyUserContext_ptr == DX_NULL) {
        return CRYS_ECDSA_SIGN_INVALID_USER_PRIV_KEY_PTR_ERROR;
    }

    verify_user_context = (CRYS_ECDSA_VerifyUserContext_t *)crypto_malloc(sizeof(CRYS_ECDSA_VerifyUserContext_t));
    if (verify_user_context == HI_NULL) {
        hi_log_error("malloc for sign_user_context falied\n");
        return CRYS_FATAL_ERROR;
    }
    error = memcpy_s(verify_user_context, sizeof(CRYS_ECDSA_VerifyUserContext_t),
                     VerifyUserContext_ptr, sizeof(CRYS_ECDSA_VerifyUserContext_t));
    if (error != CRYS_OK) {
        hi_log_print_func_err(memcpy_s, error);
        goto END_WITH_ERROR;
    }

    error = _CRYS_ECDSA_VerifyFinish(verify_user_context, SignatureIn_ptr, SignatureSizeBytes);
    if (error != CRYS_OK) {
        hi_log_print_func_err(_CRYS_ECDSA_VerifyFinish, error);
        goto END_WITH_ERROR;
    }

END_WITH_ERROR:
    if (verify_user_context != HI_NULL) {
        crypto_free(verify_user_context);
        verify_user_context = HI_NULL;
    }

    return error;
}

/**************************************************************************
 *                  CRYS_ECDSA_Verify integrated function
 **************************************************************************/
/**
   @brief  Performs all ECDSA verifying operations simultaneously.

       This function simply calls the Init, Update and Finish functions continuously.
          This function's prototype is similar to the prototypes of the called functions
          and includes all of their input and output arguments.

       NOTE: Using of HASH functions with HASH size great, than EC modulus size,
             is not recommended!


   @param[in]  VerifyUserContext_ptr - A pointer to the user buffer for verifying database.
   @param[in]  Userpub_key       - A pointer to a user public key structure.
   @param[in]  HashMode              - The enumerator variable defines the hash function to be used.
   @param[in]  MessageDataIn_ptr     - Message data for calculating hash.
   @param[in]  Messagn_size_in_bytes    - Size of block of message data in bytes.
   @param[in]  SignatureIn_ptr       - A pointer to a buffer for output of signature.
   @param[in]  SignatureSizeBytes    - Size of signature, in bytes (must be 2*OrderSizeInBytes).

   @return <b>CRYSError_t</b>: <br>
            CRYS_OK <br>
            CRYS_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR <br>
            CRYS_ECDSA_VERIFY_USER_CONTEXT_VALIDATION_TAG_ERROR <br>
            CRYS_ECDSA_VERIFY_INVALID_DOMAIN_ID_ERROR <br>
            CRYS_ECDSA_VERIFY_INVALID_SIGNER_PUBL_KEY_PTR_ERROR <br>
            CRYS_ECDSA_VERIFY_SIGNER_PUBL_KEY_VALIDATION_TAG_ERROR <br>
            CRYS_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR <br>
            CRYS_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_PTR_ERROR <br>
            CRYS_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_SIZE_ERROR <br>
            CRYS_ECDSA_VERIFY_INVALID_SIGNATURE_IN_PTR_ERROR <br>
            CRYS_ECDSA_VERIFY_INVALID_SIGNATURE_SIZE_ERROR <br>
            CRYS_ECDSA_VERIFY_INCONSISTENT_VERIFY_ERROR <br>
**/
CEXPORT_C CRYSError_t CRYS_ECDSA_Verify(CRYS_ECDSA_VerifyUserContext_t *VerifyUserContext_ptr, /* in/out */
                                        CRYS_ECPKI_UserPublKey_t *Userpub_key, /* in */
                                        CRYS_ECPKI_HASH_OpMode_t HashMode, /* in */
                                        DxUint8_t *SignatureIn_ptr, /* in */
                                        DxUint32_t SignatureSizeBytes, /* in */
                                        DxUint8_t *MessageDataIn_ptr, /* in */
                                        DxUint32_t Messagn_size_in_bytes /* in */)
{
    CRYSError_t error;

    error = CRYS_ECDSA_VerifyInit(VerifyUserContext_ptr, Userpub_key, HashMode);
    if (error != CRYS_OK) {
        return error;
    }

    error = CRYS_ECDSA_VerifyUpdate(VerifyUserContext_ptr, MessageDataIn_ptr,
        Messagn_size_in_bytes);
    if (error != CRYS_OK) {
        return error;
    }

    error = CRYS_ECDSA_VerifyFinish(VerifyUserContext_ptr, SignatureIn_ptr,
                                    SignatureSizeBytes);
    return error;
} /* END OF CRYS_ECDSA_Verify */
