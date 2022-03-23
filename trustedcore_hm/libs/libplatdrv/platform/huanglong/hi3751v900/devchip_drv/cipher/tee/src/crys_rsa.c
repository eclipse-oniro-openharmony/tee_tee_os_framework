/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: rsa
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "hi_type_dev.h"
#include "drv_osal_lib.h"
#include "crys_aes.h"
#include "dx_pal_types.h"
#include "crys_rsa_error.h"
#include "crys_rsa_types.h"
#include "crys_rsa_local.h"
#include "crys_rsa_schemes.h"
#include "crys_cipher_common.h"
#include "crys_hash.h"

/************************ Public Functions ******************************/
#ifndef _INTERNAL_CRYS_NO_RSA_SIGN_SUPPORT

#define RSA_MAX_KEY_LEN 512
#define KEY_LEN_TIMES   2
#define BYTE_BIT_WIDTH  8
#ifndef WORD_WIDTH
#define WORD_WIDTH 4
#endif

static hi_s32 rsa_get_attr(CRYS_RSA_HASH_OpMode_t hash_func,
                           hi_u16 nlen,
                           hi_u32 *hash_len,
                           hi_u32 *key_len,
                           CRYS_HASH_OperationMode_t *hash_type,
                           hi_u8 *is_after_hash)
{
    if ((hash_len == HI_NULL) || (key_len == HI_NULL)
        || (hash_type == HI_NULL) || (is_after_hash == HI_NULL)) {
        hi_log_error("para is null.\n");
        return CRYS_FATAL_ERROR;
    }

    *hash_len = 0;
    *key_len = 0;
    *hash_type = HI_CIPHER_HASH_TYPE_MAX;

    if ((nlen >= RSA_MIN_KEY_LEN) || (nlen <= RSA_MAX_KEY_LEN)) {
        *key_len = nlen;
    } else {
        hi_log_error("nlen(0x%x) is invalid\n", nlen);
        return CRYS_FATAL_ERROR;
    }

    switch (hash_func) {
        case CRYS_RSA_HASH_SHA1_mode:
            *hash_len = SHA1_RESULT_SIZE;
            *is_after_hash = HI_FALSE;
            *hash_type = CRYS_HASH_SHA1_mode;
            break;
        case CRYS_RSA_After_SHA1_mode:
            *hash_len = SHA1_RESULT_SIZE;
            *is_after_hash = HI_TRUE;
            *hash_type = CRYS_HASH_SHA1_mode;
            break;
        case CRYS_RSA_HASH_SHA224_mode:
            *hash_len = SHA224_RESULT_SIZE;
            *is_after_hash = HI_FALSE;
            *hash_type = CRYS_HASH_SHA224_mode;
            break;
        case CRYS_RSA_After_SHA224_mode:
            *hash_len = SHA224_RESULT_SIZE;
            *is_after_hash = HI_TRUE;
            *hash_type = CRYS_HASH_SHA224_mode;
            break;
        case CRYS_RSA_HASH_SHA256_mode:
            *hash_len = SHA256_RESULT_SIZE;
            *is_after_hash = HI_FALSE;
            *hash_type = CRYS_HASH_SHA256_mode;
            break;
        case CRYS_RSA_After_SHA256_mode:
            *hash_len = SHA256_RESULT_SIZE;
            *is_after_hash = HI_TRUE;
            *hash_type = CRYS_HASH_SHA256_mode;
            break;
        case CRYS_RSA_HASH_SHA384_mode:
            *hash_len = SHA384_RESULT_SIZE;
            *is_after_hash = HI_FALSE;
            *hash_type = CRYS_HASH_SHA384_mode;
            break;
        case CRYS_RSA_After_SHA384_mode:
            *hash_len = SHA384_RESULT_SIZE;
            *is_after_hash = HI_TRUE;
            *hash_type = CRYS_HASH_SHA384_mode;
            break;
        case CRYS_RSA_HASH_SHA512_mode:
            *hash_len = SHA512_RESULT_SIZE;
            *is_after_hash = HI_FALSE;
            *hash_type = CRYS_HASH_SHA512_mode;
            break;
        case CRYS_RSA_After_SHA512_mode:
            *hash_len = SHA512_RESULT_SIZE;
            *is_after_hash = HI_TRUE;
            *hash_type = CRYS_HASH_SHA512_mode;
            break;
        case CRYS_RSA_HASH_NO_HASH_mode:
            *hash_len = 0;
            *is_after_hash = HI_TRUE;
            *hash_type = CRYS_HASH_NumOfModes;
            break;
        default:
            hi_log_error("hash_func (0x%x) is invalid.\n", hash_func);
            return CRYS_FATAL_ERROR;
    }

    return CRYS_OK;
}

CEXPORT_C CRYSError_t DX_RSA_Sign(CRYS_RSAPrivUserContext_t *UserContext_ptr,
                                  CRYS_RSAUserPrivKey_t *Userprivate_key,
                                  CRYS_RSA_HASH_OpMode_t hash_func,
                                  CRYS_PKCS1_MGF_t MGF,
                                  DxUint16_t SaltLen,
                                  DxUint8_t *DataIn_ptr,
                                  DxUint32_t DataInSize,
                                  DxUint8_t *Output_ptr,
                                  DxUint16_t *OutputSize_ptr,
                                  CRYS_PKCS1_version PKCS1_ver)
{
    hi_u32 key_len;
    hi_u32 hash_len;
    CRYS_HASH_Result_t hash_result;
    hi_s32 ret;
    CRYS_HASH_OperationMode_t hash_type;
    hi_u8 *hash_data = HI_NULL;
    hi_u8 is_after_hash;
    CRYSRSAPrivKey_t *private_key = HI_NULL;
    DxUint16_t modulus_size_bytes;
    hi_u32 out_len = 0;
    CRYSError_t err;
    cryp_rsa_key key;
    hi_cipher_rsa_sign_scheme en_scheme;

    /* if the users context ID pointer is DX_NULL return an error */
    if (UserContext_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the private key object is DX_NULL return an error */
    if (Userprivate_key == DX_NULL) {
        return CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;
    }

    /* if the point for in put is DX_NULL return an error */
    if (DataIn_ptr == DX_NULL) {
        return CRYS_RSA_DATA_POINTER_INVALID_ERROR;
    }

    /* if the point for out put is DX_NULL return an error */
    if (Output_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_OUTPUT_POINTER_ERROR;
    }

    /* if the point for out put size is DX_NULL return an error */
    if (OutputSize_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_OUTPUT_SIZE_POINTER_ERROR;
    }

    /* check if the hash operation mode is legal */
    if (hash_func >= CRYS_RSA_HASH_NumOfModes) {
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }

    /* check if the MGF operation mode is legal */
    if (MGF >= CRYS_RSA_NumOfMGFFunctions) {
        return CRYS_RSA_MGF_ILLEGAL_ARG_ERROR;
    }

    /* check that the PKCS1 version argument is legal */
    if (PKCS1_ver >= CRYS_RSA_NumOf_PKCS1_versions) {
        return CRYS_RSA_PKCS1_VER_ARG_ERROR;
    }

    /* According to the PKCS1 ver 2.1 standart it is not recommended to use MD5 hash
       therefore we do not support it */
    if (PKCS1_ver == CRYS_PKCS1_VER21 && hash_func == CRYS_RSA_HASH_MD5_mode) {
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }

    if (Userprivate_key->valid_tag != CRYS_RSA_PRIV_KEY_VALIDATION_TAG) {
        return CRYS_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;
    }

    /* Initializing the Modulus Size in Bytes needed for SaltLength parameter check */
    private_key = (CRYSRSAPrivKey_t *)Userprivate_key->PrivateKeyDbBuff;

    /* Note: the (-1) is due to the PKCS#1 Ver2.1 standard section 9.1.1 */
    modulus_size_bytes = (DxUint16_t)((private_key->nSizeInBits - 1) / BYTE_BIT_WIDTH);
    if ((private_key->nSizeInBits - 1) % BYTE_BIT_WIDTH) {
        modulus_size_bytes++;
    }

    if (private_key->OperationMode >= CRYS_RSADecryptionNumOfOptions) {
        hi_log_error("PrivKey operation_mode unsuport\n");
        return CRYS_RSA_INVALID_CRT_PARAMETR_SIZE_ERROR;
    }

    ret = rsa_get_attr(hash_func, modulus_size_bytes,
                       &hash_len, &key_len, &hash_type, &is_after_hash);
    if (ret != HI_SUCCESS) {
        hi_log_error("RSA attr config error\n");
        return ret;
    }

    if (!is_after_hash) {
        err = CRYS_HASH(hash_type, DataIn_ptr, DataInSize, hash_result);
        if (err != CRYS_OK) {
            hi_log_error("CRYS_HASH failed, err = 0x%x\n", err);
            return HI_FAILURE;
        }
        hash_data = (hi_u8 *)hash_result;
    } else {
        if (DataInSize != hash_len) {
            return CRYS_RSA_DATA_POINTER_INVALID_ERROR;
        }

        hash_data = DataIn_ptr;
    }

    if ((MGF == CRYS_PKCS1_MGF1) && (PKCS1_ver == CRYS_PKCS1_VER21)) {
        en_scheme = HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA1 + hash_type;
    } else if ((MGF == CRYS_PKCS1_NO_MGF) && (PKCS1_ver == CRYS_PKCS1_VER15)) {
        en_scheme = HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA1 + hash_type;
    } else {
        return CRYS_RSA_PKCS1_VER_ARG_ERROR;
    }

    ret = memset_s(&key, sizeof(key), 0, sizeof(key));
    if (ret != HI_SUCCESS) {
        return ret;
    }

    if (private_key->OperationMode == CRYS_RSA_NoCrt) {
        key.n = (hi_u8 *)UserContext_ptr;
        key.d = key.n + RSA_MAX_RSA_KEY_LEN;

        ret = crys_bn2bin((hi_u32 *)private_key->n, key.n, key_len);
        if (ret != CRYS_OK) {
            return ret;
        }

        ret = crys_bn2bin((hi_u32 *)private_key->PriveKeyDb.NonCrt.d, key.d, key_len);
        if (ret != CRYS_OK) {
            return ret;
        }
    } else if (private_key->OperationMode == CRYS_RSA_Crt) {
        key.n = (hi_u8 *)UserContext_ptr;
        key.d = HI_NULL;
        key.p = key.n + RSA_MAX_RSA_KEY_LEN;
        key.q = key.p + RSA_MAX_RSA_KEY_LEN / KEY_LEN_TIMES;
        key.dp = key.q + RSA_MAX_RSA_KEY_LEN / KEY_LEN_TIMES;
        key.dq = key.dp + RSA_MAX_RSA_KEY_LEN / KEY_LEN_TIMES;
        key.qp = key.dq + RSA_MAX_RSA_KEY_LEN / KEY_LEN_TIMES;

        ret = crys_bn2bin((hi_u32 *)private_key->n, key.n, key_len);
        if (ret != CRYS_OK) {
            return ret;
        }

        ret = crys_bn2bin((hi_u32 *)private_key->PriveKeyDb.Crt.P, key.p, key_len >> 1);
        if (ret != CRYS_OK) {
            return ret;
        }

        ret = crys_bn2bin((hi_u32 *)private_key->PriveKeyDb.Crt.Q, key.q, key_len >> 1);
        if (ret != CRYS_OK) {
            return ret;
        }

        ret = crys_bn2bin((hi_u32 *)private_key->PriveKeyDb.Crt.dP, key.dp, key_len >> 1);
        if (ret != CRYS_OK) {
            return ret;
        }

        ret = crys_bn2bin((hi_u32 *)private_key->PriveKeyDb.Crt.dQ, key.dq, key_len >> 1);
        if (ret != CRYS_OK) {
            return ret;
        }

        ret = crys_bn2bin((hi_u32 *)private_key->PriveKeyDb.Crt.qInv, key.qp, key_len >> 1);
        if (ret != CRYS_OK) {
            return ret;
        }
    } else {
        return CRYS_RSA_WRONG_PRIVATE_KEY_TYPE;
    }

    key.public = HI_FALSE;
    key.klen = key_len;

    err = kapi_rsa_sign_hash(&key, en_scheme, hash_data, hash_len, Output_ptr, &out_len);
    if (err == HI_SUCCESS) {
        *OutputSize_ptr = out_len;
    }

    return err;
} /* END OF _DX_RSA_Sign */

CEXPORT_C CRYSError_t _DX_RSA_Sign(CRYS_RSAPrivUserContext_t *UserContext_ptr,
                                   CRYS_RSAUserPrivKey_t *Userprivate_key,
                                   CRYS_RSA_HASH_OpMode_t hash_func,
                                   CRYS_PKCS1_MGF_t MGF,
                                   DxUint16_t SaltLen,
                                   DxUint8_t *DataIn_ptr,
                                   DxUint32_t DataInSize,
                                   DxUint8_t *Output_ptr,
                                   DxUint16_t *OutputSize_ptr,
                                   CRYS_PKCS1_version PKCS1_ver)
{
    CRYS_RSAPrivUserContext_t *user_context = HI_NULL;
    CRYS_RSAUserPrivKey_t *user_priv_key = HI_NULL;
    DxUint8_t *data = HI_NULL;
    DxUint16_t output_size;
    CRYSError_t error;

    if ((UserContext_ptr == HI_NULL) || (Userprivate_key == HI_NULL) || (DataIn_ptr == HI_NULL) ||
        (Output_ptr == HI_NULL) || (OutputSize_ptr == HI_NULL)) {
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    output_size = *OutputSize_ptr;

    data = (DxUint8_t *)crypto_malloc(DataInSize);
    if (data == HI_NULL) {
        hi_log_error("malloc for data falied\n");
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    error = memset_s(data, DataInSize, 0, DataInSize);
    if (error != 0) {
        hi_log_print_func_err(memset_s, error);
        goto err;
    }

    error = memcpy_s(data, DataInSize, DataIn_ptr, DataInSize);
    if (error != CRYS_OK) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    user_context = (CRYS_RSAPrivUserContext_t *)crypto_malloc(sizeof(CRYS_RSAPrivUserContext_t));
    if (user_context == HI_NULL) {
        hi_log_error("malloc for user_context falied\n");
        goto err;
    }
    error = memset_s(user_context, sizeof(CRYS_RSAPrivUserContext_t), 0, sizeof(CRYS_RSAPrivUserContext_t));
    if (error != 0) {
        hi_log_print_func_err(memset_s, error);
        goto err;
    }

    error = memcpy_s(user_context, sizeof(CRYS_RSAPrivUserContext_t), UserContext_ptr,
                     sizeof(CRYS_RSAPrivUserContext_t));
    if (error != CRYS_OK) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    user_priv_key = (CRYS_RSAUserPrivKey_t *)crypto_malloc(sizeof(CRYS_RSAUserPrivKey_t));
    if (user_priv_key == HI_NULL) {
        hi_log_error("malloc for user_priv_key falied\n");
        goto err;
    }
    error = memset_s(user_priv_key, sizeof(CRYS_RSAUserPrivKey_t), 0, sizeof(CRYS_RSAUserPrivKey_t));
    if (error != 0) {
        hi_log_print_func_err(memset_s, error);
        goto err;
    }

    error = memcpy_s(user_priv_key, sizeof(CRYS_RSAUserPrivKey_t), Userprivate_key, sizeof(CRYS_RSAUserPrivKey_t));
    if (error != CRYS_OK) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    error = DX_RSA_Sign(user_context, user_priv_key, hash_func, MGF, SaltLen,
                        data, DataInSize, Output_ptr, &output_size, PKCS1_ver);
    if (error == CRYS_OK) {
        *OutputSize_ptr = output_size;
    }
err:
    if (data != HI_NULL) {
        crypto_free(data);
        data = HI_NULL;
    }
    if (user_context != HI_NULL) {
        crypto_free(user_context);
        user_context = HI_NULL;
    }
    if (user_priv_key != HI_NULL) {
        crypto_free(user_priv_key);
        user_priv_key = HI_NULL;
    }

    return error;
}

CEXPORT_C CRYSError_t DX_RSA_Verify(CRYS_RSAPubUserContext_t *UserContext_ptr,
                                    CRYS_RSAUserPubKey_t *Userpub_key,
                                    CRYS_RSA_HASH_OpMode_t hash_func,
                                    CRYS_PKCS1_MGF_t MGF,
                                    DxUint16_t SaltLen,
                                    DxUint8_t *DataIn_ptr,
                                    DxUint32_t DataInSize,
                                    DxUint8_t *Sig_ptr,
                                    CRYS_PKCS1_version PKCS1_ver)
{
    hi_u32 key_len;
    hi_u32 hash_len;
    CRYS_HASH_Result_t hash_result;
    hi_s32 ret;
    CRYS_HASH_OperationMode_t hash_type;
    hi_u8 *hash_data = HI_NULL;
    hi_u8 is_after_hash;
    CRYSRSAPubKey_t *pub_key = HI_NULL;
    DxUint16_t modulus_size_bytes;
    hi_u32 em_bit = 0;
    CRYSError_t err;
    cryp_rsa_key key;
    hi_cipher_rsa_sign_scheme en_scheme;

    /* if the users context ID pointer is DX_NULL return an error */
    if (UserContext_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the private key object is DX_NULL return an error */
    if (Userpub_key == DX_NULL) {
        return CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;
    }

    /* check if the hash operation mode is legal */
    if (hash_func >= CRYS_RSA_HASH_NumOfModes) {
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }

    /* check if the MGF operation mode is legal */
    if (MGF >= CRYS_RSA_NumOfMGFFunctions) {
        return CRYS_RSA_MGF_ILLEGAL_ARG_ERROR;
    }

    /* check that the PKCS1 version argument is legal */
    if (PKCS1_ver >= CRYS_RSA_NumOf_PKCS1_versions) {
        return CRYS_RSA_PKCS1_VER_ARG_ERROR;
    }

    /* According to the PKCS1 ver 2.1 standart it is not recommended to use MD5 hash
       therefore we do not support it */
    if (PKCS1_ver == CRYS_PKCS1_VER21 && hash_func == CRYS_RSA_HASH_MD5_mode) {
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }

    if (Userpub_key->valid_tag != CRYS_RSA_PUB_KEY_VALIDATION_TAG) {
        return CRYS_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;
    }

    if (PKCS1_ver < CRYS_RSA_NumOf_PKCS1_versions) {
        /* Initializing the Modulus Size in Bytes needed for SaltLength parameter check */
        pub_key = (CRYSRSAPubKey_t *)Userpub_key->PublicKeyDbBuff;
        em_bit = pub_key->nSizeInBits;

        /* Note: the (-1) is due to the PKCS#1 Ver2.1 standard section 9.1.1 */
        modulus_size_bytes = (DxUint16_t)((em_bit - 1) / BYTE_BIT_WIDTH);
        if ((em_bit - 1) % BYTE_BIT_WIDTH) {
            modulus_size_bytes++;
        }
    }

    ret = rsa_get_attr(hash_func, modulus_size_bytes,
                       &hash_len, &key_len, &hash_type, &is_after_hash);
    if (ret != HI_SUCCESS) {
        hi_log_error("Crys RSA attr config error\n");
        return ret;
    }

    if (!is_after_hash) {
        err = CRYS_HASH(hash_type, DataIn_ptr, DataInSize, hash_result);
        if (err != CRYS_OK) {
            hi_log_error("CRYS_HASH failed, err = 0x%x\n", err);
            return HI_FAILURE;
        }
        hash_data = (hi_u8 *)hash_result;
        // hi_print_hex("M-HASH", hash_data, hash_len);
    } else {
        if (DataInSize != hash_len) {
            return CRYS_RSA_DATA_POINTER_INVALID_ERROR;
        }

        hash_data = DataIn_ptr;
        // hi_print_hex("I-HASH", hash_data, hash_len);
    }

    if ((MGF == CRYS_PKCS1_MGF1) && (PKCS1_ver == CRYS_PKCS1_VER21)) {
        en_scheme = HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA1 + hash_type;
    } else if ((MGF == CRYS_PKCS1_NO_MGF) && (PKCS1_ver == CRYS_PKCS1_VER15)) {
        en_scheme = HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA1 + hash_type;
    } else {
        return CRYS_RSA_PKCS1_VER_ARG_ERROR;
    }

    key.n = (hi_u8 *)UserContext_ptr;
    key.d = key.n + RSA_MAX_RSA_KEY_LEN;
    ret = crys_bn2bin(pub_key->n, key.n, key_len);
    if (ret != CRYS_OK) {
        return ret;
    }

    ret = crys_bn2bin(pub_key->e, (hi_u8 *)&key.e, 4); /* size is 4 */
    if (ret != CRYS_OK) {
        return ret;
    }

    key.public = HI_TRUE;
    key.klen = key_len;

    return kapi_rsa_verify_hash(&key, en_scheme, hash_data, hash_len, Sig_ptr, key_len);
} /* END OF _DX_RSA_Verify */

CEXPORT_C CRYSError_t _DX_RSA_Verify(CRYS_RSAPubUserContext_t *UserContext_ptr,
                                     CRYS_RSAUserPubKey_t *Userpub_key,
                                     CRYS_RSA_HASH_OpMode_t hash_func,
                                     CRYS_PKCS1_MGF_t MGF,
                                     DxUint16_t SaltLen,
                                     DxUint8_t *DataIn_ptr,
                                     DxUint32_t DataInSize,
                                     DxUint8_t *Sig_ptr,
                                     CRYS_PKCS1_version PKCS1_ver)
{
    CRYS_RSAPubUserContext_t *user_context = HI_NULL;
    CRYS_RSAUserPubKey_t *user_pub_key = HI_NULL;
    DxUint8_t *data = HI_NULL;
    CRYSError_t error;

    if ((UserContext_ptr == HI_NULL) || (Userpub_key == HI_NULL) || (DataIn_ptr == HI_NULL) ||
        (Sig_ptr == HI_NULL)) {
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    data = (DxUint8_t *)crypto_malloc(DataInSize);
    if (data == HI_NULL) {
        hi_log_error("malloc for data falied\n");
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    error = memset_s(data, DataInSize, 0, DataInSize);
    if (error != 0) {
        hi_log_print_func_err(memset_s, error);
        goto err;
    }
    error = memcpy_s(data, DataInSize, DataIn_ptr, DataInSize);
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    user_context = (CRYS_RSAPubUserContext_t *)crypto_malloc(sizeof(CRYS_RSAPubUserContext_t));
    if (user_context == HI_NULL) {
        hi_log_error("malloc for user_context falied\n");
        goto err;
    }
    error = memset_s(user_context, sizeof(CRYS_RSAPubUserContext_t), 0, sizeof(CRYS_RSAPubUserContext_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memset_s, error);
        goto err;
    }
    error = memcpy_s(user_context, sizeof(CRYS_RSAPubUserContext_t), UserContext_ptr,
                     sizeof(CRYS_RSAPubUserContext_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    user_pub_key = (CRYS_RSAUserPubKey_t *)crypto_malloc(sizeof(CRYS_RSAUserPubKey_t));
    if (user_pub_key == HI_NULL) {
        hi_log_error("malloc for user_pub_key falied\n");
        goto err;
    }
    error = memset_s(user_pub_key, sizeof(CRYS_RSAUserPubKey_t), 0, sizeof(CRYS_RSAUserPubKey_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memset_s, error);
        goto err;
    }
    error = memcpy_s(user_pub_key, sizeof(CRYS_RSAUserPubKey_t), Userpub_key, sizeof(CRYS_RSAUserPubKey_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    error = DX_RSA_Verify(user_context, user_pub_key, hash_func, MGF, SaltLen,
                          data, DataInSize, Sig_ptr, PKCS1_ver);
    if (error != CRYS_OK) {
        hi_log_print_func_err(DX_RSA_Verify, error);
        goto err;
    }

err:
    if (data != HI_NULL) {
        crypto_free(data);
        data = HI_NULL;
    }
    if (user_context != HI_NULL) {
        crypto_free(user_context);
        user_context = HI_NULL;
    }
    if (user_pub_key != HI_NULL) {
        crypto_free(user_pub_key);
        user_pub_key = HI_NULL;
    }

    return error;
}

CEXPORT_C CRYSError_t DX_RSA_SCHEMES_Encrypt(CRYS_RSAUserPubKey_t *Userpub_key,
                                             CRYS_RSAPrimeData_t *PrimeData_ptr,
                                             CRYS_RSA_HASH_OpMode_t hash_func,
                                             DxUint8_t *L,
                                             DxUint16_t Llen,
                                             CRYS_PKCS1_MGF_t MGF,
                                             DxUint8_t *DataIn_ptr,
                                             DxUint16_t DataInSize,
                                             DxUint8_t *Output_ptr,
                                             CRYS_PKCS1_version PKCS1_ver)
{
    DxUint16_t modulus_size_bytes;
    CRYSRSAPubKey_t *pub_key = HI_NULL;
    hi_s32 ret;
    hi_u32 hash_len;
    hi_u32 key_len;
    CRYS_HASH_OperationMode_t hash_type;
    hi_u8 is_after_hash;
    hi_u32 out_len = 0;
    hi_u8 *user_context = HI_NULL;
    cryp_rsa_key key = { 0 };
    hi_cipher_rsa_enc_scheme scheme;

    /* if the users context pointer is DX_NULL return an error */
    if (Userpub_key == DX_NULL) {
        return CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;
    }

    /* checking the Prime Data pointer */
    if (PrimeData_ptr == DX_NULL) {
        return CRYS_RSA_PRIM_DATA_STRUCT_POINTER_INVALID;
    }

    /* check if the hash operation mode is legal */
    if (hash_func >= CRYS_RSA_HASH_NumOfModes) {
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }

    /* check if the MGF operation mode is legal */
    if (CRYS_RSA_NumOfMGFFunctions <= MGF) {
        return CRYS_RSA_MGF_ILLEGAL_ARG_ERROR;
    }

    /* check that the PKCS1 version argument is legal */
    if (PKCS1_ver >= CRYS_RSA_NumOf_PKCS1_versions) {
        return CRYS_RSA_PKCS1_VER_ARG_ERROR;
    }

    /* if the users Data In pointer is illegal return an error */
    /* note - it is allowed to encrypt a message of size zero ; only on this case a NULL is allowed */
    if (DataIn_ptr == DX_NULL && DataInSize != 0) {
        return CRYS_RSA_DATA_POINTER_INVALID_ERROR;
    }

    /* If the output pointer is DX_NULL return Error */
    if (Output_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_OUTPUT_POINTER_ERROR;
    }

    if (Userpub_key->valid_tag != CRYS_RSA_PUB_KEY_VALIDATION_TAG) {
        return CRYS_RSA_PUB_KEY_VALIDATION_TAG_ERROR;
    }

    pub_key = (CRYSRSAPubKey_t *)Userpub_key->PublicKeyDbBuff;
    user_context = (hi_u8 *)PrimeData_ptr;

    /* Initialize K with the modulus size in Bytes */
    modulus_size_bytes = (DxUint16_t)(pub_key->nSizeInBits / 8); /* byte is 8 bits */
    if (pub_key->nSizeInBits % BITS_IN_BYTE) {
        modulus_size_bytes++;
    }

    ret = rsa_get_attr(hash_func, modulus_size_bytes,
                       &hash_len, &key_len, &hash_type, &is_after_hash);
    if (ret != HI_SUCCESS) {
        hi_log_error("RSA attr config error\n");
        return ret;
    }

    if ((MGF == CRYS_PKCS1_MGF1) && (PKCS1_ver == CRYS_PKCS1_VER21)) {
        scheme = HI_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA1 + hash_type;
    } else if ((MGF == CRYS_PKCS1_NO_MGF) && (PKCS1_ver == CRYS_PKCS1_VER15)) {
        scheme = HI_CIPHER_RSA_ENC_SCHEME_BLOCK_TYPE_2;
    } else {
        scheme = HI_CIPHER_RSA_ENC_SCHEME_NO_PADDING;
    }

    key.n = (hi_u8 *)user_context;
    key.d = key.n + RSA_MAX_RSA_KEY_LEN;
    ret = crys_bn2bin(pub_key->n, key.n, key_len);
    if (ret != CRYS_OK) {
        return ret;
    }

    ret = crys_bn2bin(pub_key->e, (hi_u8 *)&key.e, WORD_WIDTH);
    if (ret != CRYS_OK) {
        return ret;
    }

    key.public = HI_TRUE;
    key.klen = key_len;

    return kapi_rsa_encrypt(&key, scheme, DataIn_ptr, DataInSize, Output_ptr, &out_len);
} /* END OF _DX_RSA_SCHEMES_Encrypt */

CEXPORT_C CRYSError_t _DX_RSA_SCHEMES_Encrypt(CRYS_RSAUserPubKey_t *Userpub_key,
                                              CRYS_RSAPrimeData_t *PrimeData_ptr,
                                              CRYS_RSA_HASH_OpMode_t hash_func,
                                              DxUint8_t *L,
                                              DxUint16_t Llen,
                                              CRYS_PKCS1_MGF_t MGF,
                                              DxUint8_t *DataIn_ptr,
                                              DxUint16_t DataInSize,
                                              DxUint8_t *Output_ptr,
                                              CRYS_PKCS1_version PKCS1_ver)
{
    CRYS_RSAUserPubKey_t *user_pub_key = HI_NULL;
    CRYS_RSAPrimeData_t *prime_data = HI_NULL;
    DxUint8_t *salt = HI_NULL;
    DxUint8_t *data = HI_NULL;
    CRYSError_t error;

    if ((Userpub_key == HI_NULL) || (PrimeData_ptr == HI_NULL) || (DataIn_ptr == HI_NULL) ||
        (Output_ptr == HI_NULL) || ((L == HI_NULL) && (Llen > 0))) {
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    user_pub_key = (CRYS_RSAUserPubKey_t *)crypto_malloc(sizeof(CRYS_RSAUserPubKey_t));
    if (user_pub_key == HI_NULL) {
        hi_log_error("malloc for user_pub_key falied\n");
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    error = memset_s(user_pub_key, sizeof(CRYS_RSAUserPubKey_t), 0, sizeof(CRYS_RSAUserPubKey_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memset_s, error);
        goto err;
    }
    error = memcpy_s(user_pub_key, sizeof(CRYS_RSAUserPubKey_t), Userpub_key, sizeof(CRYS_RSAUserPubKey_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    prime_data = (CRYS_RSAPrimeData_t *)crypto_malloc(sizeof(CRYS_RSAPrimeData_t));
    if (prime_data == HI_NULL) {
        hi_log_error("malloc for prime_data falied\n");
        goto err;
    }
    error = memset_s(prime_data, sizeof(CRYS_RSAPrimeData_t), 0, sizeof(CRYS_RSAPrimeData_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memset_s, error);
        goto err;
    }
    error = memcpy_s(prime_data, sizeof(CRYS_RSAPrimeData_t), PrimeData_ptr, sizeof(CRYS_RSAPrimeData_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    if (Llen > 0) {
        salt = (DxUint8_t *)crypto_malloc(Llen);
        if (salt == HI_NULL) {
            hi_log_error("malloc for salt falied\n");
            goto err;
        }
        error = memset_s(salt, Llen, 0, Llen);
        if (error != HI_SUCCESS) {
            hi_log_print_func_err(memset_s, error);
            goto err;
        }
        error = memcpy_s(salt, Llen, L, Llen);
        if (error != HI_SUCCESS) {
            hi_log_print_func_err(memcpy_s, error);
            goto err;
        }
    }

    data = (DxUint8_t *)crypto_malloc(DataInSize);
    if (data == HI_NULL) {
        hi_log_error("malloc for data falied\n");
        goto err;
    }
    error = memcpy_s(data, DataInSize, DataIn_ptr, DataInSize);
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    error = DX_RSA_SCHEMES_Encrypt(user_pub_key, prime_data, hash_func, salt, Llen, MGF,
                                   data, DataInSize, Output_ptr, PKCS1_ver);
    if (error != CRYS_OK) {
        hi_log_print_func_err(DX_RSA_SCHEMES_Encrypt, error);
        goto err;
    }

err:
    if (user_pub_key != HI_NULL) {
        crypto_free(user_pub_key);
        user_pub_key = HI_NULL;
    }
    if (prime_data != HI_NULL) {
        crypto_free(prime_data);
        prime_data = HI_NULL;
    }
    if (salt != HI_NULL) {
        crypto_free(salt);
        salt = HI_NULL;
    }
    if (data != HI_NULL) {
        crypto_free(data);
        data = HI_NULL;
    }
    return error;
}

CEXPORT_C CRYSError_t DX_RSA_SCHEMES_Decrypt(CRYS_RSAUserPrivKey_t *Userprivate_key,
                                             CRYS_RSAPrimeData_t *PrimeData_ptr,
                                             CRYS_RSA_HASH_OpMode_t hash_func,
                                             DxUint8_t *L,
                                             DxUint16_t Llen,
                                             CRYS_PKCS1_MGF_t MGF,
                                             DxUint8_t *DataIn_ptr,
                                             DxUint16_t DataInSize,
                                             DxUint8_t *Output_ptr,
                                             DxUint16_t *OutputSize_ptr,
                                             CRYS_PKCS1_version PKCS1_ver)
{
    DxUint16_t modulus_size_bytes;
    CRYSRSAPrivKey_t *private_key = DX_NULL;
    hi_s32 ret;
    hi_u32 hash_len;
    hi_u32 key_len;
    CRYS_HASH_OperationMode_t hash_type;
    hi_u8 is_after_hash;
    hi_u8 *user_context = DX_NULL;
    cryp_rsa_key key;
    hi_u32 out_len = 0;
    hi_cipher_rsa_enc_scheme scheme;

    /* checking the User priver key pointer */
    if (Userprivate_key == DX_NULL) {
        return CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;
    }

    private_key = (CRYSRSAPrivKey_t *)Userprivate_key->PrivateKeyDbBuff;

    /* if the users context pointer is DX_NULL return an error */
    if (private_key == DX_NULL) {
        return CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;
    }

    /* checking the Prime Data pointer */
    if (PrimeData_ptr == DX_NULL) {
        return CRYS_RSA_PRIM_DATA_STRUCT_POINTER_INVALID;
    }

    /* check if the hash operation mode is legal */
    if (hash_func >= CRYS_RSA_HASH_NumOfModes) {
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }

    /* check if the MGF operation mode is legal */
    if (MGF >= CRYS_RSA_NumOfMGFFunctions) {
        return CRYS_RSA_MGF_ILLEGAL_ARG_ERROR;
    }

    /* check that the PKCS1 version argument is legal */
    if (PKCS1_ver >= CRYS_RSA_NumOf_PKCS1_versions) {
        return CRYS_RSA_PKCS1_VER_ARG_ERROR;
    }

    /* If the DataIn pointer is DX_NULL return Error */
    if (DataIn_ptr == DX_NULL) {
        return CRYS_RSA_DATA_POINTER_INVALID_ERROR;
    }

    /* If the output pointer is DX_NULL return Error */
    if (Output_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_OUTPUT_POINTER_ERROR;
    }

    /* If the output size pointer is DX_NULL return Error */
    if (OutputSize_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_OUTPUT_SIZE_POINTER_ERROR;
    }

    if (Userprivate_key->valid_tag != CRYS_RSA_PRIV_KEY_VALIDATION_TAG) {
        return CRYS_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;
    }

    if (Llen == 0) {
        L = DX_NULL;
    }

    user_context = (hi_u8 *)PrimeData_ptr;

    /* Initialize K with the modulus size in Bytes */
    modulus_size_bytes = (DxUint16_t)(private_key->nSizeInBits / BYTE_BIT_WIDTH);
    if (private_key->nSizeInBits % BYTE_BIT_WIDTH) {
        modulus_size_bytes++;
    }

    ret = rsa_get_attr(hash_func, modulus_size_bytes,
                       &hash_len, &key_len, &hash_type, &is_after_hash);
    if (ret != HI_SUCCESS) {
        hi_log_error("RSA attr config error\n");
        return ret;
    }

    if (DataInSize != key_len) {
        return CRYS_RSA_DATA_POINTER_INVALID_ERROR;
    }

    if ((MGF == CRYS_PKCS1_MGF1) && (PKCS1_ver == CRYS_PKCS1_VER21)) {
        scheme = HI_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA1 + hash_type;
    } else if ((MGF == CRYS_PKCS1_NO_MGF) && (PKCS1_ver == CRYS_PKCS1_VER15)) {
        scheme = HI_CIPHER_RSA_ENC_SCHEME_BLOCK_TYPE_2;
    } else {
        scheme = HI_CIPHER_RSA_ENC_SCHEME_NO_PADDING;
    }

    if (private_key->OperationMode == CRYS_RSA_NoCrt) {
        key.n = (hi_u8 *)user_context;
        key.d = key.n + RSA_MAX_RSA_KEY_LEN;

        ret = crys_bn2bin((hi_u32 *)private_key->n, key.n, key_len);
        if (ret != CRYS_OK) {
            return ret;
        }

        ret = crys_bn2bin((hi_u32 *)private_key->PriveKeyDb.NonCrt.d, key.d, key_len);
        if (ret != CRYS_OK) {
            return ret;
        }
    } else if (private_key->OperationMode == CRYS_RSA_Crt) {
        key.n = (hi_u8 *)user_context;
        key.d = HI_NULL;
        key.p = key.n + RSA_MAX_RSA_KEY_LEN / KEY_LEN_TIMES;
        key.q = key.p + RSA_MAX_RSA_KEY_LEN / KEY_LEN_TIMES;
        key.dp = key.q + RSA_MAX_RSA_KEY_LEN / KEY_LEN_TIMES;
        key.dq = key.dp + RSA_MAX_RSA_KEY_LEN / KEY_LEN_TIMES;
        key.qp = key.dq + RSA_MAX_RSA_KEY_LEN / KEY_LEN_TIMES;

        ret = crys_bn2bin((hi_u32 *)private_key->n, key.n, key_len);
        if (ret != HI_SUCCESS) {
            return ret;
        }

        ret = crys_bn2bin((hi_u32 *)private_key->PriveKeyDb.Crt.P, key.p, key_len >> 1);
        if (ret != HI_SUCCESS) {
            return ret;
        }

        ret = crys_bn2bin((hi_u32 *)private_key->PriveKeyDb.Crt.Q, key.q, key_len >> 1);
        if (ret != HI_SUCCESS) {
            return ret;
        }

        ret = crys_bn2bin((hi_u32 *)private_key->PriveKeyDb.Crt.dP, key.dp, key_len >> 1);
        if (ret != CRYS_OK) {
            return ret;
        }

        ret = crys_bn2bin((hi_u32 *)private_key->PriveKeyDb.Crt.dQ, key.dq, key_len >> 1);
        if (ret != CRYS_OK) {
            return ret;
        }

        ret = crys_bn2bin((hi_u32 *)private_key->PriveKeyDb.Crt.qInv, key.qp, key_len >> 1);
        if (ret != CRYS_OK) {
            return ret;
        }
    } else {
        return CRYS_RSA_WRONG_PRIVATE_KEY_TYPE;
    }

    key.public = HI_FALSE;
    key.klen = key_len;

    ret = kapi_rsa_decrypt(&key, scheme, DataIn_ptr, DataInSize, Output_ptr, &out_len);
    if (ret == HI_SUCCESS) {
        *OutputSize_ptr = out_len;
    }

    return ret;
}

CEXPORT_C CRYSError_t _DX_RSA_SCHEMES_Decrypt(CRYS_RSAUserPrivKey_t *Userprivate_key,
                                              CRYS_RSAPrimeData_t *PrimeData_ptr,
                                              CRYS_RSA_HASH_OpMode_t hash_func,
                                              DxUint8_t *L,
                                              DxUint16_t Llen,
                                              CRYS_PKCS1_MGF_t MGF,
                                              DxUint8_t *DataIn_ptr,
                                              DxUint16_t DataInSize,
                                              DxUint8_t *Output_ptr,
                                              DxUint16_t *OutputSize_ptr,
                                              CRYS_PKCS1_version PKCS1_ver)
{
    CRYS_RSAUserPrivKey_t *user_priv_key = HI_NULL;
    CRYS_RSAPrimeData_t *prime_data = HI_NULL;
    DxUint8_t *salt = HI_NULL;
    DxUint8_t *data = HI_NULL;
    DxUint16_t output_size;
    CRYSError_t error;

    if ((Userprivate_key == HI_NULL) || (PrimeData_ptr == HI_NULL) || (DataIn_ptr == HI_NULL) ||
        (Output_ptr == HI_NULL) || (OutputSize_ptr == HI_NULL)) {
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    output_size = *OutputSize_ptr;

    user_priv_key = (CRYS_RSAUserPrivKey_t *)crypto_malloc(sizeof(CRYS_RSAUserPrivKey_t));
    if (user_priv_key == HI_NULL) {
        hi_log_error("malloc for user_priv_key falied\n");
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    error = memset_s(user_priv_key, sizeof(CRYS_RSAUserPrivKey_t), 0, sizeof(CRYS_RSAUserPrivKey_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memset_s, error);
        goto err;
    }
    error = memcpy_s(user_priv_key, sizeof(CRYS_RSAUserPrivKey_t), Userprivate_key, sizeof(CRYS_RSAUserPrivKey_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    prime_data = (CRYS_RSAPrimeData_t *)crypto_malloc(sizeof(CRYS_RSAPrimeData_t));
    if (prime_data == HI_NULL) {
        hi_log_error("malloc for prime_data falied\n");
        goto err;
    }
    error = memset_s(prime_data, sizeof(CRYS_RSAPrimeData_t), 0, sizeof(CRYS_RSAPrimeData_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memset_s, error);
        goto err;
    }
    error = memcpy_s(prime_data, sizeof(CRYS_RSAPrimeData_t), PrimeData_ptr, sizeof(CRYS_RSAPrimeData_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    if (Llen > 0) {
        salt = (DxUint8_t *)crypto_malloc(Llen);
        if (salt == HI_NULL) {
            hi_log_error("malloc for salt falied\n");
            goto err;
        }
        error = memset_s(salt, Llen, 0, Llen);
        if (error != HI_SUCCESS) {
            hi_log_print_func_err(memset_s, error);
            goto err;
        }
        error = memcpy_s(salt, Llen, L, Llen);
        if (error != CRYS_OK) {
            hi_log_print_func_err(memcpy_s, error);
            goto err;
        }
    }

    data = (DxUint8_t *)crypto_malloc(DataInSize);
    if (data == HI_NULL) {
        hi_log_error("malloc for data falied\n");
        goto err;
    }
    error = memset_s(data, DataInSize, 0, DataInSize);
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memset_s, error);
        goto err;
    }
    error = memcpy_s(data, DataInSize, DataIn_ptr, DataInSize);
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    error = DX_RSA_SCHEMES_Decrypt(user_priv_key, prime_data, hash_func, salt, Llen, MGF,
                                   data, DataInSize, Output_ptr, &output_size, PKCS1_ver);
    if (error == CRYS_OK) {
        *OutputSize_ptr = output_size;
    }
err:
    if (user_priv_key != HI_NULL) {
        crypto_free(user_priv_key);
        user_priv_key = HI_NULL;
    }
    if (prime_data != HI_NULL) {
        crypto_free(prime_data);
        prime_data = HI_NULL;
    }
    if (salt != HI_NULL) {
        crypto_free(salt);
        salt = HI_NULL;
    }
    if (data != HI_NULL) {
        crypto_free(data);
        data = HI_NULL;
    }
    return error;
}

#endif /* _INTERNAL_CRYS_NO_RSA_SIGN_SUPPORT */
