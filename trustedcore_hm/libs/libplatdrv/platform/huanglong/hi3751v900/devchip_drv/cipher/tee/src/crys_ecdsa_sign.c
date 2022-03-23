/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: ecdsa sign
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

static CEXPORT_C CRYSError_t crys_ecdsa_hash_info(CRYS_ECPKI_HASH_OpMode_t hash_mode,
                                                 CRYS_HASH_OperationMode_t *hash_operation_mode,
                                                 hi_u32 *hash_word_len,
                                                 hi_bool *is_aften_hash)
{
    *hash_operation_mode = CRYS_HASH_NumOfModes;
    *hash_word_len = 0;
    *is_aften_hash = HI_FALSE;

    switch (hash_mode) {
        case CRYS_ECPKI_AFTER_HASH_SHA1_mode:
            *is_aften_hash = HI_TRUE;
            *hash_operation_mode = CRYS_HASH_SHA1_mode;
            *hash_word_len = CRYS_HASH_SHA1_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_HASH_SHA1_mode:
            *hash_operation_mode = CRYS_HASH_SHA1_mode;
            *hash_word_len = CRYS_HASH_SHA1_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_AFTER_HASH_SHA224_mode:
            *is_aften_hash = HI_TRUE;
            *hash_operation_mode = CRYS_HASH_SHA224_mode;
            *hash_word_len = CRYS_HASH_SHA224_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_HASH_SHA224_mode:
            *hash_operation_mode = CRYS_HASH_SHA224_mode;
            *hash_word_len = CRYS_HASH_SHA224_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_AFTER_HASH_SHA256_mode:
            *is_aften_hash = HI_TRUE;
            *hash_operation_mode = CRYS_HASH_SHA256_mode;
            *hash_word_len = CRYS_HASH_SHA256_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_HASH_SHA256_mode:
            *hash_operation_mode = CRYS_HASH_SHA256_mode;
            *hash_word_len = CRYS_HASH_SHA256_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_AFTER_HASH_SHA384_mode:
            *is_aften_hash = HI_TRUE;
            *hash_operation_mode = CRYS_HASH_SHA384_mode;
            *hash_word_len = CRYS_HASH_SHA384_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_HASH_SHA384_mode:
            *hash_operation_mode = CRYS_HASH_SHA384_mode;
            *hash_word_len = CRYS_HASH_SHA384_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_AFTER_HASH_SHA512_mode:
            *is_aften_hash = HI_TRUE;
            *hash_operation_mode = CRYS_HASH_SHA512_mode;
            *hash_word_len = CRYS_HASH_SHA512_DIGEST_SIZE_IN_WORDS;
            break;
        case CRYS_ECPKI_HASH_SHA512_mode:
            *hash_operation_mode = CRYS_HASH_SHA512_mode;
            *hash_word_len = CRYS_HASH_SHA512_DIGEST_SIZE_IN_WORDS;
            break;

        default:
            hi_log_error("Invalid hash mode %d\n", hash_mode);
            return CRYS_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR;
    }

    return CRYS_OK;
}

/**************************************************************************
 *                  CRYS_ECDSA_Sign_Init function
 **************************************************************************/
/**
   \brief
   The CRYS_ECDSA_Sign_Init functions user shall call first to perform the
   EC DSA Signing operation.

   The function performs the following steps:
   -# Validates all the inputs of the function. If one of the received
      parameters is not valid, the function returns an error.
   -# Decrypts the received context to the working context after capturing
      the working context by calling the CRYS_CCM_GetContext() function.
   -# Initializes the working context and other variables and structures.
   -# Calls the CRYS_HASH_Init() function.
   -# Calls the CRYS_CCM_EncryptAndReleaseContext() function to encrypt
      the information in the working context, store it in the user's
      received context, and then release the working context.
   -# Exits the handler with the OK code.

   This function does not do ECDSA cryptographic processing. Rather, it
   prepares a context that is used by the Update() and Finish() functions.

   NOTE: Using of HASH functions with HASH size great, than EC modulus size, is not recommended!


   @param[in,out] SignUserContext_ptr A pointer to the user buffer for signing data.
   @param[in]       Signerprivate_key   A pointer to the private key that will be used to
                                      sign the data.
   @param[in]     hash_mode            Defines the hash mode used for DSA.

   @return <b>CRYSError_t</b>: <br>
             CRYS_OK<br>
             CRYS_ECDSA_SIGN_INVALID_USER_CONTEXT_PTR_ERROR
             CRYS_ECDSA_SIGN_INVALID_USER_PRIV_KEY_PTR_ERROR
             CRYS_ECDSA_SIGN_USER_PRIV_KEY_VALIDATION_TAG_ERROR
             CRYS_ECDSA_SIGN_INVALID_DOMAIN_ID_ERROR
             CRYS_ECDSA_SIGN_ILLEGAL_HASH_OP_MODE_ERROR
 */
CEXPORT_C CRYSError_t _CRYS_ECDSA_SignInit(CRYS_ECDSA_SignUserContext_t *SignUserContext_ptr, /* in/out */
                                           CRYS_ECPKI_UserPrivKey_t *Signerprivate_key, /* in */
                                           CRYS_ECPKI_HASH_OpMode_t hash_mode /* in */)
{
    CRYSError_t error;
    CRYSError_t end_error;
    ECDSA_SignContext_t *ecdsa_context = HI_NULL;
    CRYS_ECPKI_PrivKey_t *private_key = HI_NULL;
    CRYS_HASH_OperationMode_t operation_mode = CRYS_HASH_NumOfModes;
    hi_u32 hash_word_len = 0;
    hi_bool is_after_hash = HI_TRUE;

    /* if the users context ID pointer is DX_NULL return an error */
    if (SignUserContext_ptr == DX_NULL) {
        return CRYS_ECDSA_SIGN_INVALID_USER_CONTEXT_PTR_ERROR;
    }

    /* if the private key pointer is DX_NULL or its validation tag is not valid return an error */
    if (Signerprivate_key == DX_NULL) {
        return CRYS_ECDSA_SIGN_INVALID_USER_PRIV_KEY_PTR_ERROR;
    }

    /* check if the hash operation mode is legal */
    if (hash_mode >= CRYS_ECPKI_HASH_NumOfModes) {
        hi_log_print_err_code(CRYS_ECDSA_SIGN_ILLEGAL_HASH_OP_MODE_ERROR);
        return CRYS_ECDSA_SIGN_ILLEGAL_HASH_OP_MODE_ERROR;
    }

    if (Signerprivate_key->valid_tag != CRYS_ECPKI_PRIV_KEY_VALIDATION_TAG) {
        hi_log_print_err_code(CRYS_ECDSA_SIGN_USER_PRIV_KEY_VALIDATION_TAG_ERROR);
        return CRYS_ECDSA_SIGN_USER_PRIV_KEY_VALIDATION_TAG_ERROR;
    }

    /* initialize the priv key pointer */
    private_key = (CRYS_ECPKI_PrivKey_t *)(void *)(Signerprivate_key->PrivKeyDbBuff);

    /* check the EC domain ID */
    if (private_key->DomainID >= CRYS_ECPKI_DomainID_OffMode) {
        hi_log_print_err_code(CRYS_ECDSA_SIGN_INVALID_DOMAIN_ID_ERROR);
        return CRYS_ECDSA_SIGN_INVALID_DOMAIN_ID_ERROR;
    }

    ecdsa_context = (ECDSA_SignContext_t *)SignUserContext_ptr->context_buff;

    /* Reset the Context handler for improper previous values initialized */
    error = memset_s(ecdsa_context, sizeof(ECDSA_SignContext_t), 0, sizeof(ECDSA_SignContext_t));
    if (error != 0) {
        hi_log_error("Cipher memset_s failed.\n");
        return error;
    }

    error = crys_ecdsa_hash_info(hash_mode, &operation_mode, &hash_word_len, &is_after_hash);
    if (error != CRYS_OK) {
        hi_log_print_func_err(crys_ecdsa_hash_info, error);
        goto END_WITH_ERROR;
    }

    if (is_after_hash == HI_FALSE) {
        error = CRYS_HASH_Init(((CRYS_HASHUserContext_t *)(ecdsa_context->CRYSPKAHashCtxBuff)), operation_mode);
        if (error != CRYS_OK) {
            hi_log_print_func_err(CRYS_HASH_Init, error);
            goto END_WITH_ERROR;
        }
    }

    /* Copying the ECPKI Private key value to the context */
    error = memcpy_s((DxUint8_t *)&ecdsa_context->ECDSA_SignerPrivKey, sizeof(ecdsa_context->ECDSA_SignerPrivKey),
                     (DxUint8_t *)Signerprivate_key, sizeof(CRYS_ECPKI_UserPrivKey_t));
    if (error != HI_SUCCESS) {
        hi_log_error("Cipher memcpy_s failed.\n");
        goto END_WITH_ERROR;
    }

    /* set the ECDSA tag to the users context */
    SignUserContext_ptr->valid_tag = CRYS_ECDSA_SIGN_CONTEXT_VALIDATION_TAG;
    ecdsa_context->HashMode = hash_mode;
    ecdsa_context->HASH_Result_Size = hash_word_len;

    return error;

END_WITH_ERROR:

    /* clearing the users context in case of error */
    end_error = memset_s(SignUserContext_ptr, sizeof(CRYS_ECDSA_SignUserContext_t), 0,
                         sizeof(CRYS_ECDSA_SignUserContext_t));
    if (end_error != 0) {
        hi_log_print_func_err(memset_s, end_error);
        return end_error;
    }

    hi_log_print_err_code(error);

    return error;
} /* _DX_ECDSA_SignInit */

/**************************************************************************
 *                  CRYS_ECDSA_Sign_Update function
 **************************************************************************/
/**
   @brief  Performs a hash  operation on data allocated by the user
           before finally signing it.

          In case user divides signing data by block, he must call the Update function
          continuously a number of times until processing of the entire data block is complete.

       NOTE: Using of HASH functions with HASH size great, than EC modulus size,
             is not recommended!

   @param[in,out] SignUserContext_ptr A pointer to the user buffer for signing the database.
   @param[in]       MessageDataIn_ptr   Message data for calculating Hash.
   @param[in]     DataInSize          The size of the message data block, in bytes.

   @return <b>CRYSError_t</b>: <br>
             CRYS_OK<br>
                    CRYS_ECDSA_SIGN_INVALID_USER_CONTEXT_PTR_ERROR
                         CRYS_ECDSA_SIGN_USER_CONTEXT_VALIDATION_TAG_ERROR
             CRYS_ECDSA_SIGN_INVALID_MESSAGE_DATA_IN_PTR_ERROR
             CRYS_ECDSA_SIGN_INVALID_MESSAGE_DATA_IN_SIZE_ERROR
             CRYS_ECDSA_SIGN_ILLEGAL_HASH_OP_MODE_ERROR

 */
CEXPORT_C CRYSError_t _CRYS_ECDSA_SignUpdate(CRYS_ECDSA_SignUserContext_t *SignUserContext_ptr, /* in/out */
                                             DxUint8_t *MessageDataIn_ptr, /* in */
                                             DxUint32_t DataInSize /* in */)
{
    CRYSError_t error;
    CRYSError_t end_error;
    ECDSA_SignContext_t *ecdsa_context = HI_NULL;
    CRYS_HASH_OperationMode_t operation_mode = CRYS_HASH_NumOfModes;
    hi_u32 hash_word_len = 0;
    hi_bool is_after_hash = HI_TRUE;

    /* if the users context pointer is DX_NULL return an error */
    if (SignUserContext_ptr == DX_NULL) {
        return CRYS_ECDSA_SIGN_INVALID_USER_CONTEXT_PTR_ERROR;
    }

    /* if the users context TAG is illegal return an error - the context is invalid */
    if (SignUserContext_ptr->valid_tag != CRYS_ECDSA_SIGN_CONTEXT_VALIDATION_TAG) {
        return CRYS_ECDSA_SIGN_USER_CONTEXT_VALIDATION_TAG_ERROR;
    }

    /* if the users MessageDataIn pointer is illegal return an error */
    if (MessageDataIn_ptr == DX_NULL && DataInSize) {
        return CRYS_ECDSA_SIGN_INVALID_MESSAGE_DATA_IN_PTR_ERROR;
    }

    /* if the data size is larger then 2^29 (to prevent an overflow on the transition to bits )
    return error */
    if (DataInSize >= (1UL << 29)) { /* left shift 29 */
        return CRYS_ECDSA_SIGN_INVALID_MESSAGE_DATA_IN_SIZE_ERROR;
    }

    ecdsa_context = (ECDSA_SignContext_t *)SignUserContext_ptr->context_buff;

    error = crys_ecdsa_hash_info(ecdsa_context->HashMode, &operation_mode, &hash_word_len, &is_after_hash);
    if (error != CRYS_OK) {
        hi_log_print_func_err(crys_ecdsa_hash_info, error);
        goto END_WITH_ERROR;
    }

    if (is_after_hash == HI_FALSE) {
        error = CRYS_HASH_Update(((CRYS_HASHUserContext_t *)(ecdsa_context->CRYSPKAHashCtxBuff)),
            MessageDataIn_ptr, DataInSize);
    } else {
        if (DataInSize != hash_word_len * WORD_WIDTH) {
            /* DataInSize must fit exactly to the size of Hash output that we support */
            error = CRYS_ECDSA_SIGN_INVALID_MESSAGE_DATA_IN_SIZE_ERROR;
            goto END_WITH_ERROR;
        }

        if (MessageDataIn_ptr != DX_NULL) {
            /* Copy the DataIn_ptr to the hash_result */
            error = memcpy_s((DxUint8_t *)ecdsa_context->HASH_Result, sizeof(ecdsa_context->HASH_Result),
                MessageDataIn_ptr, DataInSize);
            if (error != HI_SUCCESS) {
                hi_log_error("Cipher memcpy_s failed.\n");
                goto END_WITH_ERROR;
            }
        }
    }

    return error;

END_WITH_ERROR:

    /* clearing the users context in case of error */
    end_error = memset_s(SignUserContext_ptr, sizeof(CRYS_ECDSA_SignUserContext_t), 0,
                         sizeof(CRYS_ECDSA_SignUserContext_t));
    if (end_error != 0) {
        hi_log_print_func_err(memset_s, end_error);
        return end_error;
    }

    hi_log_print_err_code(error);
    return error;
} /* CRYS_ECDSA_SignUpdate */

/**************************************************************************
 *                  _DX_ECDSA_Sign_Finish function
 **************************************************************************/
/**
   @brief  Performs initialization of variables and structures, calls the hash function
           for the last block of data (if necessary) and then calculates digital
           signature according to the EC DSA algorithm.

          NOTE: Using of HASH functions with HASH size great, than EC modulus size,
             is not recommended!

   @param[in] SignUserContext_ptr      A pointer to the user buffer for signing database.
   @param[in] SignatureOut_ptr         A pointer to a buffer for output of signature.
   @param[in,out] SignatureOutSize_ptr The size of a user passed buffer for signature (in)
                                       and size of actual signature (out). The size of buffer
                    must be not less than 2*OrderSizeInBytes.
   @param[out] IsEphemerKeyInternal    A parameter defining whether the ephemeral key
                                       is internal or external (1 or 0).
   @param[out] EphemerKeyData_ptr      A pointer to external ephemeral key data buffer of size
                    not less, than size of CRYS_ECPKI_KG_TempData_t. The buffer must
                                        contain at the first place the ephemeral private key,
                    given as big endian bytes array.
   @return <b>CRYSError_t</b>: <br>
             CRYS_OK<br>
                         CRYS_ECDSA_SIGN_INVALID_USER_CONTEXT_PTR_ERROR <br>
             CRYS_ECDSA_SIGN_USER_CONTEXT_VALIDATION_TAG_ERROR <br>
             CRYS_ECDSA_SIGN_INVALID_SIGNATURE_OUT_PTR_ERROR <br>
             CRYS_ECDSA_SIGN_ILLEGAL_HASH_OP_MODE_ERROR <br>
             CRYS_ECDSA_SIGN_INVALID_SIGNATURE_OUT_SIZE_PTR_ERROR <br>
             CRYS_ECDSA_SIGN_INVALID_SIGNATURE_OUT_SIZE_ERROR <br>
             CRYS_ECDSA_SIGN_INVALID_DOMAIN_ID_ERROR <br>
             CRYS_ECDSA_SIGN_INVALID_IS_EPHEMER_KEY_INTERNAL_ERROR <br>
             CRYS_ECDSA_SIGN_INVALID_EPHEMERAL_KEY_PTR_ERROR <br>
**/
CEXPORT_C CRYSError_t DX_ECDSA_SignFinish(CRYS_ECDSA_SignUserContext_t *SignUserContext_ptr, /* in */
                                          DxUint8_t *SignatureOut_ptr, /* out */
                                          DxUint32_t *SignatureOutSize_ptr, /* in/out */
                                          int8_t IsEphemerKeyInternal, /* in */
                                          DxUint32_t *EphemerKeyData_ptr /* in */)
{
    CRYSError_t error;
    CRYSError_t end_error;

    ECDSA_SignContext_t *ecdsa_context = HI_NULL;
    CRYS_ECPKI_PrivKey_t *private_key = HI_NULL;
    CRYS_ECPKI_DomainID_t domain_id;
    DxUint32_t mod_size_in_byte;
    DxUint32_t hash_size_in_byte;
    DxUint8_t *temp_buffer = HI_NULL;
    CRYS_HASH_OperationMode_t operation_mode = CRYS_HASH_NumOfModes;
    hi_u32 hash_word_len = 0;
    hi_bool is_after_hash = HI_TRUE;
    DxUint32_t signature_out_size;
    hi_u32 pad_len = 0;
    ecc_param_t ecc;
    hi_u8 *signature = HI_NULL;

    /* if the users context pointer is DX_NULL return an error */
    if (SignUserContext_ptr == DX_NULL) {
        return CRYS_ECDSA_SIGN_INVALID_USER_CONTEXT_PTR_ERROR;
    }

    /* if the users context tag is illegal return an error - the context is invalid */
    if (SignUserContext_ptr->valid_tag != CRYS_ECDSA_SIGN_CONTEXT_VALIDATION_TAG) {
        return CRYS_ECDSA_SIGN_USER_CONTEXT_VALIDATION_TAG_ERROR;
    }

    /* if the users SignatureOut pointer is illegal return an error */
    if (SignatureOut_ptr == DX_NULL) {
        return CRYS_ECDSA_SIGN_INVALID_SIGNATURE_OUT_PTR_ERROR;
    }

    /* if the users SignatureOutSize pointer is illegal return an error */
    if (SignatureOutSize_ptr == DX_NULL) {
        return CRYS_ECDSA_SIGN_INVALID_SIGNATURE_OUT_SIZE_PTR_ERROR;
    }

    /* if user set an illegal IsEphemerKeyInternal value or illegal pointer return an error */
    if (IsEphemerKeyInternal != 1 && IsEphemerKeyInternal != 0) {
        return CRYS_ECDSA_SIGN_INVALID_IS_EPHEMER_KEY_INTERNAL_ERROR;
    }

    if (IsEphemerKeyInternal == 0 && EphemerKeyData_ptr == DX_NULL) {
        return CRYS_ECDSA_SIGN_INVALID_EPHEMERAL_KEY_PTR_ERROR;
    }

    signature_out_size = *SignatureOutSize_ptr;
    ecdsa_context = (ECDSA_SignContext_t *)SignUserContext_ptr->context_buff;

    if (ecdsa_context->HashMode >= CRYS_ECPKI_HASH_NumOfModes) {
        error = CRYS_ECDSA_SIGN_ILLEGAL_HASH_OP_MODE_ERROR;
        goto END_WITH_ERROR;
    }
    private_key = (CRYS_ECPKI_PrivKey_t *)(void *)ecdsa_context->ECDSA_SignerPrivKey.PrivKeyDbBuff;
    domain_id = private_key->DomainID;

    error = crys_ecdsa_hash_info(ecdsa_context->HashMode, &operation_mode, &hash_word_len, &is_after_hash);
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

    /* Modulus sizes */
    mod_size_in_byte = ecc.ksize - pad_len;
    hash_size_in_byte = hash_word_len * WORD_WIDTH;

    /* Temp buffers */
    temp_buffer = (hi_u8 *)ecdsa_context->crysEcdsaSignIntBuff;

    /* If the received output buffer is small than 2*OrderSizeInBytes then return an error */
    if (signature_out_size < 2 * mod_size_in_byte) {
        error = CRYS_ECDSA_SIGN_INVALID_SIGNATURE_OUT_SIZE_ERROR;
        goto END_WITH_ERROR;
    }

    /* Operating the HASH Finish function only in case that Hash operation is needed */
    if (is_after_hash == HI_FALSE) {
        error = CRYS_HASH_Finish(((CRYS_HASHUserContext_t *)(ecdsa_context->CRYSPKAHashCtxBuff)),
                                 ecdsa_context->HASH_Result);
        if (error != CRYS_OK) {
            goto END_WITH_ERROR;
        }
    }

    error = memset_s(temp_buffer, CRYS_PKA_ECDSA_SIGNE_BUFF_MAX_LENGTH_IN_WORDS * WORD_WIDTH, 0,
        CRYS_PKA_ECDSA_SIGNE_BUFF_MAX_LENGTH_IN_WORDS * WORD_WIDTH);
    if (error != EOK) {
        hi_log_print_func_err(memset_s, error);
        goto END_WITH_ERROR;
    }
    error = crys_bn2bin(private_key->PrivKey, temp_buffer + pad_len, mod_size_in_byte);
    if (error != CRYS_OK) {
        goto END_WITH_ERROR;
    }

    /* CALL LLF ECDSA Sinature function */
    error = kapi_ecdsa_sign_hash(&ecc, temp_buffer, (hi_u8 *)ecdsa_context->HASH_Result,
                                 hash_size_in_byte, signature, signature + ecc.ksize);
    if (error != CRYS_OK) {
        goto END_WITH_ERROR;
    }

    asm_memmove(SignatureOut_ptr, signature + pad_len, mod_size_in_byte);
    asm_memmove(SignatureOut_ptr + mod_size_in_byte, signature + ecc.ksize + pad_len, mod_size_in_byte);

    *SignatureOutSize_ptr = 2 * mod_size_in_byte; /* out size is 2 times of mode size */

    error = memset_s(SignUserContext_ptr, sizeof(CRYS_ECDSA_SignUserContext_t), 0,
                     sizeof(CRYS_ECDSA_SignUserContext_t));
    if (error != 0) {
        hi_log_print_func_err(memset_s, error);
        goto END_WITH_ERROR;
    }

    return HI_SUCCESS;

END_WITH_ERROR:
    if (signature != HI_NULL) {
        free(signature);
    }

    end_error = memset_s(SignUserContext_ptr, sizeof(CRYS_ECDSA_SignUserContext_t), 0,
                         sizeof(CRYS_ECDSA_SignUserContext_t));
    if (end_error != 0) {
        hi_log_print_func_err(memset_s, end_error);
        return end_error;
    }

    hi_log_print_err_code(error);
    return error;
} /* _DX_ECDSA_SignFinish */

CEXPORT_C CRYSError_t CRYS_ECDSA_SignInit(CRYS_ECDSA_SignUserContext_t *SignUserContext_ptr, /* in/out */
                                          CRYS_ECPKI_UserPrivKey_t *Signerprivate_key, /* in */
                                          CRYS_ECPKI_HASH_OpMode_t hash_mode /* in */)
{
    CRYS_ECPKI_UserPrivKey_t *signer_priv_key = HI_NULL;
    CRYSError_t error;

    if (Signerprivate_key == DX_NULL) {
        return CRYS_ECDSA_SIGN_INVALID_USER_PRIV_KEY_PTR_ERROR;
    }

    signer_priv_key = (CRYS_ECPKI_UserPrivKey_t *)crypto_malloc(sizeof(CRYS_ECPKI_UserPrivKey_t));
    if (signer_priv_key == HI_NULL) {
        hi_log_error("malloc for signer_priv_key falied\n");
        return CRYS_FATAL_ERROR;
    }
    error = memcpy_s(signer_priv_key, sizeof(CRYS_ECPKI_UserPrivKey_t), Signerprivate_key,
                     sizeof(CRYS_ECPKI_UserPrivKey_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto END_WITH_ERROR;
    }

    error = _CRYS_ECDSA_SignInit(SignUserContext_ptr, signer_priv_key, hash_mode);
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(_CRYS_ECDSA_SignInit, error);
    }

END_WITH_ERROR:
    if (signer_priv_key != HI_NULL) {
        crypto_free(signer_priv_key);
        signer_priv_key = HI_NULL;
    }
    return error;
}

CEXPORT_C CRYSError_t CRYS_ECDSA_SignUpdate(CRYS_ECDSA_SignUserContext_t *SignUserContext_ptr, /* in/out */
                                            DxUint8_t *MessageDataIn_ptr, /* in */
                                            DxUint32_t DataInSize /* in */)
{
    CRYS_ECDSA_SignUserContext_t *sign_user_context = HI_NULL;
    CRYSError_t error;

    if (SignUserContext_ptr == DX_NULL) {
        return CRYS_ECDSA_SIGN_INVALID_USER_PRIV_KEY_PTR_ERROR;
    }

    sign_user_context = (CRYS_ECDSA_SignUserContext_t *)crypto_malloc(sizeof(CRYS_ECDSA_SignUserContext_t));
    if (sign_user_context == HI_NULL) {
        hi_log_error("malloc for sign_user_context falied\n");
        return CRYS_FATAL_ERROR;
    }
    error = memcpy_s(sign_user_context, sizeof(CRYS_ECDSA_SignUserContext_t),
                     SignUserContext_ptr, sizeof(CRYS_ECDSA_SignUserContext_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto END_WITH_ERROR;
    }

    error = _CRYS_ECDSA_SignUpdate(sign_user_context, MessageDataIn_ptr, DataInSize);
    if (CRYS_OK != CRYS_OK) {
        hi_log_print_func_err(_CRYS_ECDSA_SignUpdate, error);
        goto END_WITH_ERROR;
    }

    error = memcpy_s(SignUserContext_ptr, sizeof(CRYS_ECDSA_SignUserContext_t),
                     sign_user_context, sizeof(CRYS_ECDSA_SignUserContext_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
    }

END_WITH_ERROR:
    if (sign_user_context != HI_NULL) {
        crypto_free(sign_user_context);
        sign_user_context = HI_NULL;
    }

    return error;
}

CEXPORT_C CRYSError_t _DX_ECDSA_SignFinish(CRYS_ECDSA_SignUserContext_t *SignUserContext_ptr, /* in */
                                           DxUint8_t *SignatureOut_ptr, /* out */
                                           DxUint32_t *SignatureOutSize_ptr, /* in/out */
                                           int8_t IsEphemerKeyInternal, /* in */
                                           DxUint32_t *EphemerKeyData_ptr /* in */)
{
    CRYS_ECDSA_SignUserContext_t *sign_user_context = HI_NULL;
    CRYSError_t error;

    if (SignUserContext_ptr == DX_NULL) {
        return CRYS_ECDSA_SIGN_INVALID_USER_PRIV_KEY_PTR_ERROR;
    }

    sign_user_context = (CRYS_ECDSA_SignUserContext_t *)crypto_malloc(sizeof(CRYS_ECDSA_SignUserContext_t));
    if (sign_user_context == HI_NULL) {
        hi_log_error("malloc for sign_user_context falied\n");
        return CRYS_FATAL_ERROR;
    }
    error = memcpy_s(sign_user_context, sizeof(CRYS_ECDSA_SignUserContext_t),
                     SignUserContext_ptr, sizeof(CRYS_ECDSA_SignUserContext_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto END_WITH_ERROR;
    }

    error = DX_ECDSA_SignFinish(sign_user_context, SignatureOut_ptr,
                                SignatureOutSize_ptr, IsEphemerKeyInternal, EphemerKeyData_ptr);
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(DX_ECDSA_SignFinish, error);
    }

END_WITH_ERROR:
    if (sign_user_context != HI_NULL) {
        crypto_free(sign_user_context);
        sign_user_context = HI_NULL;
    }

    return error;
}

/**************************************************************************
 *                  CRYS_ECDSA_Sign - integrated function
 **************************************************************************/
/**
   @brief  Performs all of the ECDSA signing operations simultaneously.
           This function simply calls the Init, Update and Finish functions continuously.
              This function's prototype is similar to the prototypes of the called functions
              and includes all of their input and output arguments.

   NOTE: Using of HASH functions with HASH size great, than EC modulus size, is not recommended!

   @param[in,out] SignUserContext_ptr - A pointer to the user buffer for signing database.
   @param[in]     Signerprivate_key   - A pointer to a user private key structure.
   @param[in]     hash_mode            - The enumerator variable defines hash function to be used.
   @param[in]       MessageDataIn_ptr   - A message data for calculation of hash.
   @param[in]     Messagn_size_in_bytes  - A size of block of message data in bytes.
   @param[in]     SignatureOut_ptr    - A pointer to a buffer for output of signature.
   @param[in,out] SignatureOutSize_ptr- Size of user passed buffer for signature (in)
                                        and size of actual signature (out). The size of buffer
                                        must be not less than 2*OrderSizeInBytes.
   @return <b>CRYSError_t</b>: <br>
        CRYS_OK<br>
        CRYS_ECDSA_SIGN_INVALID_USER_CONTEXT_PTR_ERROR<br>
        CRYS_ECDSA_SIGN_USER_CONTEXT_VALIDATION_TAG_ERROR<br>
        CRYS_ECDSA_SIGN_INVALID_USER_PRIV_KEY_PTR_ERROR<br>
        CRYS_ECDSA_SIGN_USER_PRIV_KEY_VALIDATION_TAG_ERROR<br>
        CRYS_ECDSA_SIGN_ILLEGAL_HASH_OP_MODE_ERROR <br>
        CRYS_ECDSA_SIGN_INVALID_MESSAGE_DATA_IN_PTR_ERROR<br>
        CRYS_ECDSA_SIGN_INVALID_MESSAGE_DATA_IN_SIZE_ERROR<br>
        CRYS_ECDSA_SIGN_INVALID_SIGNATURE_OUT_PTR_ERROR<br>
        CRYS_ECDSA_SIGN_INVALID_SIGNATURE_OUT_SIZE_PTR_ERROR<br>
        CRYS_ECDSA_SIGN_INVALID_SIGNATURE_OUT_SIZE_ERROR<br>
        CRYS_ECDSA_SIGN_INVALID_DOMAIN_ID_ERROR <br>
**/
CEXPORT_C CRYSError_t CRYS_ECDSA_Sign(CRYS_ECDSA_SignUserContext_t *SignUserContext_ptr, /* in/out */
                                      CRYS_ECPKI_UserPrivKey_t *Signerprivate_key, /* in */
                                      CRYS_ECPKI_HASH_OpMode_t hash_mode, /* in */
                                      DxUint8_t *MessageDataIn_ptr, /* in */
                                      DxUint32_t Messagn_size_in_bytes, /* in */
                                      DxUint8_t *SignatureOut_ptr, /* out */
                                      DxUint32_t *SignatureOutSize_ptr /* in */)
{
    CRYSError_t error;

    error = CRYS_ECDSA_SignInit(SignUserContext_ptr, Signerprivate_key, hash_mode);
    if (error != CRYS_OK) {
        return error;
    }

    error = CRYS_ECDSA_SignUpdate(SignUserContext_ptr, MessageDataIn_ptr,
        Messagn_size_in_bytes);
    if (error != CRYS_OK) {
        return error;
    }

    error = CRYS_ECDSA_SignFinish(SignUserContext_ptr, SignatureOut_ptr,
                                  SignatureOutSize_ptr);
    return error;
} /* END OF CRYS_ECDSA_Sign */
