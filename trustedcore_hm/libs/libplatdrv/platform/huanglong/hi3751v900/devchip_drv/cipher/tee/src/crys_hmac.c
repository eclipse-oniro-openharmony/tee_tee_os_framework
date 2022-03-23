/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hmac
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "hi_type_dev.h"
#include "crys_aes.h"
#include "dx_pal_types.h"
#include "crys_hash.h"
#include "crys_hmac.h"
#include "crys_hmac_error.h"
#include "crys_cipher_common.h"
#include "crys_kdf.h"
#include "dx_util.h"
#include "drv_osal_lib.h"
#include "cipher_drv_hash.h"
#include "tee_common.h"
#ifdef CHIP_SYMC_VER_V200
#include "hi_tee_keyladder.h"
#include "tee_drv_klad_ext.h"
#endif
#include "hi_tee_chip_task.h"

/************************ Defines ******************************/
#define HMAC_MMZ_BUFF_SIZE         0x2000
#define HASH_BLOCK_SIZE            64
#define HASH_PAD_MAX_LEN           64
#define HASH1_SIGNATURE_SIZE       20
#define HASH256_SIGNATURE_SIZE     32
#define PBKDF_HARD_KEY_MAX_LEN     64
#define PBKDF_HARD_DATAIN_LEN_WORD 16
#define PBKDF_HARD_KEY_LEN         32
#define PBKDF_HARD_KEY_LEN_WORD    8
#define CRYS_BUFF_SIZE 16
#define CRYS_COUNT_BUFF_SIZE 4
#define OFFSET_3 3

typedef struct hi_hmac_user_context {
    hi_handle hash;
} hmac_user_context;

#define SECURE_STORAGE_KEY_LEN 16

/* NOTE: If modify this string, the old KEY may never be used. */
static char *g_mask_str = "Swe1@#8$!~s^vd(&8Df$&<.s/u'Ed_=@3";
static hi_u16 g_mask_res[SECURE_STORAGE_KEY_LEN];
static int g_hmac_rootkey_init = 0;
static TEE_UUID g_rootkey_uuids[] = {
    TEE_SERVICE_SSA,
    TEE_SERVICE_RPMB,
    TEE_SERVICE_KEYMASTER,
    TEE_SERVICE_GATEKEEPER,
	TEE_SERVICE_HUK,
};

CRYSError_t crys_pkcs5_pbkdf2_hmac256(hi_cipher_pbkdf2 *pstInfo, DxUint8_t *output);

/* !
 * Converts Symmetric Adaptor return code to CRYS error code.
 *
 * \param error_code Symmetric Adaptor return error.
 * \param error_info Ignored.
 *
 * \return CRYSError_t one of CRYS_* error codes defined in crys_error.h
 */
static CRYSError_t adaptor_to_crys_hmac_err(int error_code, DxUint32_t error_info)
{
    CRYSError_t err;

    switch (error_code) {
        case HI_ERR_CIPHER_UNSUPPORTED:
            err = CRYS_HMAC_IS_NOT_SUPPORTED;
            break;
        case HI_ERR_CIPHER_FAILED_INIT:
            err = CRYS_HMAC_IS_NOT_SUPPORTED;
            break;
        case HI_ERR_CIPHER_INVALID_POINT:
            err = CRYS_HMAC_DATA_IN_POINTER_INVALID_ERROR;
            break;
        case HI_ERR_CIPHER_INVALID_PARA:
            err = CRYS_HMAC_ILLEGAL_PARAMS_ERROR;
            break;
        case HI_ERR_CIPHER_BUSY:
        case HI_ERR_CIPHER_NO_AVAILABLE_RNG:
            err = CRYS_HMAC_IS_NOT_SUPPORTED;
            break;
        case HI_SUCCESS:
            err = CRYS_OK;
            break;
        default:
            err = CRYS_FATAL_ERROR;
            break;
    }

    return err | error_info;
}

/* This function initializes the HMAC machine on the CRYS level.
 *
 * The function allocates and initializes the HMAC Context .
 * The function receives as input a pointer to store the context handle to HMAC Context.
 *
 * The function executes a HASH_init session and processes a HASH update
 * on the Key XOR ipad and stores it in the context.
 *
 * @param[in] ContextID_ptr - A pointer to the HMAC context buffer allocated by the user
 *                       that is used for the HMAC machine operation.
 *
 * @param[in] operation_mode - The operation mode: MD5 or SHA1.
 *
 * @param[in] key_ptr - The pointer to the user's key buffer,
 *            or its digest (if larger than the hash block size).
 *
 * @param[in] keySize - The size of the received key. Must not exceed the associated
 *                      hash block size. For larger keys the caller must provide
 *                      a hash digest of the key as the actual key.
 *
 * @return CRYSError_t - On success the function returns the value CRYS_OK,
 *            and on failure a non-ZERO error.
 *
 */
CIMPORT_C CRYSError_t CRYS_HMAC_Init(CRYS_HMACUserContext_t *ContextID_ptr,
                                     CRYS_HASH_OperationMode_t operation_mode,
                                     DxUint8_t *key_ptr,
                                     DxUint16_t keySize)
{
    hi_s32 ret;
    hmac_user_context *hamc_user_context = HI_NULL;
    hi_cipher_hash_type hash_type = HI_CIPHER_HASH_TYPE_SHA1;

    /* if the users context ID pointer is DX_NULL return an error */
    if (ContextID_ptr == DX_NULL) {
        return CRYS_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    if (sizeof(CRYS_HMACUserContext_t) < sizeof(hmac_user_context)) {
        return CRYS_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* check if the key pointer is valid */
    if (key_ptr == DX_NULL) {
        return CRYS_HMAC_INVALID_KEY_POINTER_ERROR;
    }

    hamc_user_context = (hmac_user_context *)ContextID_ptr;
    ret = memset_s(hamc_user_context, sizeof(hmac_user_context), 0, sizeof(hmac_user_context));
    if (ret != 0) {
        hi_log_print_func_err(memset_s, ret);
        return ret;
    }

    /* check if the key size is valid */
    if (keySize == 0) {
        return CRYS_HMAC_UNVALID_KEY_SIZE_ERROR;
    }

    switch (operation_mode) {
        case CRYS_HASH_SHA1_mode:
            hash_type = HI_CIPHER_HASH_TYPE_HMAC_SHA1;
            break;
        case CRYS_HASH_SHA224_mode:
            hash_type = HI_CIPHER_HASH_TYPE_HMAC_SHA224;
            break;
        case CRYS_HASH_SHA256_mode:
            hash_type = HI_CIPHER_HASH_TYPE_HMAC_SHA256;
            break;
        case CRYS_HASH_SHA384_mode:
            hash_type = HI_CIPHER_HASH_TYPE_HMAC_SHA384;
            break;
        case CRYS_HASH_SHA512_mode:
            hash_type = HI_CIPHER_HASH_TYPE_HMAC_SHA512;
            break;
        default:
            return CRYS_HMAC_ILLEGAL_OPERATION_MODE_ERROR;
    }

    /* hash i_key_pad and message start */
    ret = kapi_hash_start(&hamc_user_context->hash, hash_type, key_ptr, keySize);
    if (ret != HI_SUCCESS) {
        hi_log_error("hash i_key_pad and message start failed!\n");
        return adaptor_to_crys_hmac_err(ret, 0);
    }

    return DX_CRYS_RETURN_ERROR(ret, 0, adaptor_to_crys_hmac_err);
}

/* This function processes a HMAC block of data via the HASH hardware/software.
 * The function receives as input a handle to the HMAC Context,
 * and performs a HASH update on the data described below.
 *
 * @param[in] ContextID_ptr - A pointer to the HMAC context buffer allocated by the user
 *                       that is used for the HMAC machine operation.
 *
 * @param DataIn_ptr - A pointer to the buffer that stores the data to be hashed.
 *
 * @param DataInSize - The size of the data to be hashed, in bytes.
 *
 * @return CRYSError_t - On success the function returns CRYS_OK,
 *            and on failure a non-ZERO error.
 */
CIMPORT_C CRYSError_t CRYS_HMAC_Update(CRYS_HMACUserContext_t *ContextID_ptr,
                                       DxUint8_t *DataIn_ptr,
                                       DxUint32_t DataInSize)
{
    hi_s32 ret;
    hmac_user_context *hamc_user_context = HI_NULL;
    /* if the users context ID pointer is DX_NULL return an error */
    if (ContextID_ptr == DX_NULL) {
        return CRYS_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the users Data In pointer is illegal and the size is not 0 return an error */
    if ((DataIn_ptr == DX_NULL) && DataInSize) {
        return CRYS_HMAC_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* if the data size is zero no need to execute an update , return CRYS_OK */
    if (DataInSize == 0) {
        return CRYS_OK;
    }

    hamc_user_context = (hmac_user_context *)ContextID_ptr;
    ret = kapi_hash_update(hamc_user_context->hash,
                           DataIn_ptr, DataInSize, HASH_CHUNCK_SRC_LOCAL);
    if (ret != HI_SUCCESS) {
        hi_log_error("hmac message update failed!\n");
        return adaptor_to_crys_hmac_err(ret, 0);
    }

    return CRYS_OK;
}

/**
 * This function finalizes the HMAC processing of a data block.
 * The function receives as input a handle to the HMAC Context that was previously initialized
 * by a CRYS_HMAC_Init function or by a CRYS_HMAC_Update function.
 * This function finishes the HASH operation on the ipad and text, and then
 * executes a new HASH operation with the key XOR opad and the previous HASH operation result.
 *
 *  @param[in] ContextID_ptr - A pointer to the HMAC context buffer allocated by the user
 *                       that is used for the HMAC machine operation.
 *
 *  @retval HmacResultBuff - A pointer to the target buffer where the
 *                       HMAC result stored in the context is loaded to.
 *
 * @return CRYSError_t - On success the function returns CRYS_OK,
 *            and on failure a non-ZERO error.
 */
CIMPORT_C CRYSError_t CRYS_HMAC_Finish(CRYS_HMACUserContext_t *ContextID_ptr,
                                       CRYS_HASH_Result_t HmacResultBuff)
{
    hi_s32 ret;
    hmac_user_context *hamc_user_context = HI_NULL;
    hi_u32 hlen = 0;

    /* if the users context ID pointer is DX_NULL return an error */
    if (ContextID_ptr == DX_NULL) {
        return CRYS_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    if (HmacResultBuff == DX_NULL) {
        return CRYS_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }
    hamc_user_context = (hmac_user_context *)ContextID_ptr;

    ret = kapi_hash_finish(hamc_user_context->hash, (hi_u8 *)HmacResultBuff, sizeof(CRYS_HASH_Result_t), &hlen);
    if (ret != HI_SUCCESS) {
        hi_log_error("Hash Final i_key_pad+message failure, ret=%d\n", ret);
        return adaptor_to_crys_hmac_err(ret, 0);
    }

    hamc_user_context->hash = HASH_HANDLE_CLOSED_STATUS;

    return CRYS_OK;
}

/**
 * @brief This function clears the hash context
 *
 * @param[in] ContextID_ptr - a pointer to the HMAC context
 *                       buffer allocated by the user that is
 *                       used for the HMAC machine operation.
 *                       This should be the same context that
 *                       was used on the previous call of this
 *                       session.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* crys_error.h
 */
CEXPORT_C CRYSError_t CRYS_HMAC_Free(CRYS_HMACUserContext_t *ContextID_ptr)
{
    hmac_user_context *hamc_user_context = HI_NULL;
    hi_u8 hash_result[CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES] = { 0 };
    hi_u32 hlen = 0;
    hi_s32 ret;

    hamc_user_context = (hmac_user_context *)ContextID_ptr;

    if (ContextID_ptr == DX_NULL) {
        return CRYS_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* release handle if not release */
    if (hamc_user_context->hash != HASH_HANDLE_CLOSED_STATUS) {
        ret = kapi_hash_finish(hamc_user_context->hash, hash_result, sizeof(hash_result), &hlen);
        if (ret != HI_SUCCESS) {
            return CRYS_FATAL_ERROR;
        }
    }

    ret = memset_s(ContextID_ptr, sizeof(CRYS_HMACUserContext_t), 0, sizeof(CRYS_HMACUserContext_t));
    if (ret != 0) {
        hi_log_print_func_err(memset_s, ret);
        return ret;
    }

    return CRYS_OK;
}

/**
 * This function provide HASH function to process one buffer of data.
 * The function allocates an internal HASH Context , it initializes the
 * HASH Context with the cryptographic attributes that are needed for
 * the HASH block operation (initialize H's value for the HASH algorithm).
 * Then the function loads the Hardware with the initializing values and after
 * that process the data block using the hardware to do hash .
 * At the end the function return the message digest of the data buffer .
 *
 *
 * @param[in] operation_mode - The operation mode : MD5 or SHA1.
 *
 * @param[in] key_ptr - The pointer to the users key buffer.
 *
 * @oaram[in] keySize - The size of the received key.
 *
 * @param[in] ContextID_ptr - a pointer to the HMAC context buffer allocated by the user that
 *                       is used for the HMAC machine operation.
 *
 * @param[in] DataIn_ptr - The pointer to the buffer of the input data to the HMAC. The pointer does
 *                         not need to be aligned. On CSI input mode the pointer must be equal to
 *                         value (0xFFFFFFFC | DataInAlignment).
 *
 * @param[in] DataInSize - The size of the data to be hashed in bytes. On CSI data transfer mode the size must
 *                         multiple of HASH_BLOCK_SIZE for used HASH mode.
 *
 * param[out] hash_resultBuff - a pointer to the target buffer where the
 *                      HMAC result stored in the context is loaded to.
 *
 * @return CRYSError_t on success the function returns CRYS_OK else non ZERO error.
 *
 */
CIMPORT_C CRYSError_t CRYS_HMAC(CRYS_HASH_OperationMode_t operation_mode,
                                DxUint8_t *key_ptr,
                                DxUint16_t keySize,
                                DxUint8_t *DataIn_ptr,
                                DxUint32_t DataSize,
                                CRYS_HASH_Result_t HmacResultBuff)
{
    CRYS_HMACUserContext_t *user_context = HI_NULL;
    CRYSError_t error;

    user_context = (CRYS_HMACUserContext_t *)malloc(sizeof(CRYS_HMACUserContext_t));
    if (user_context == HI_NULL) {
        hi_log_error("CRYS_HMAC malloc failed\n");
        return CRYS_FATAL_ERROR;
    }

    error = CRYS_HMAC_Init(user_context, operation_mode, key_ptr, keySize);
    if (error != CRYS_OK) {
        goto end;
    }

    error = CRYS_HMAC_Update(user_context, DataIn_ptr, DataSize);
    if (error != CRYS_OK) {
        goto end;
    }
    error = CRYS_HMAC_Finish(user_context, HmacResultBuff);

end:
    error = CRYS_HMAC_Free(user_context);
    free(user_context);
    user_context = HI_NULL;

    return error;
}

#ifdef CHIP_SYMC_VER_V200

#ifdef CFG_HI_TEE_KLAD_SUPPORT
extern hi_s32 hi_tee_drv_klad_create(hi_handle *klad);
extern hi_s32 hi_tee_drv_klad_set_attr(const hi_handle klad, const tee_klad_attr *attr);
extern hi_s32 hi_tee_drv_klad_attach(const hi_handle klad, const hi_handle target);
extern hi_s32 hi_tee_drv_klad_set_content_key(const hi_handle klad, const tee_klad_content_key *key);
extern hi_s32 hi_tee_drv_klad_destroy(const hi_handle klad);
#endif

static CRYSError_t crys_load_securestore_rootkey(unsigned char hmac_key[16], unsigned int k_len) /* 16 k_len */
{
#ifdef CFG_HI_TEE_KLAD_SUPPORT
    CRYSError_t error;
    hi_handle cipher;
    hi_handle klad;
    CRYS_AESUserContext_t context_id;
    tee_klad_content_key content_key = { 0, { 0x82, 0xEA, 0x8D, 0xC4, 0x3E, 0x1E,
        0x5B, 0xA4, 0xAB, 0xED, 0x78, 0x5B, 0x03, 0x0C, 0xAC, 0xF3 } };  /* random as klad content key */
    hi_u8 *data_in = (hi_u8 *)g_mask_str; /* cipher data in */
    tee_klad_attr attr = { 0 };

    error = hi_tee_drv_klad_create(&klad);
    if (error != CRYS_OK) {
        hi_log_error("drv_tee_klad_create failed, err= 0x%x k_len:0x%x \n", error, k_len);
        goto __EXIT__;
    }

    /* each chip's OTP secstorge key is unique */
    attr.klad_type = HI_TEE_KLAD_TYPE_SECSTORGE;
    attr.alg = HI_TEE_KLAD_ALG_TYPE_AES;
    attr.engine = 0;
    error = hi_tee_drv_klad_set_attr(klad, &attr);
    if (error != CRYS_OK) {
        hi_log_error("hi_tee_drv_klad_set_attr failed, err= 0x%x\n", error);
        goto __EXIT__;
    }

    error = CRYS_AES_Init(&context_id, HI_NULL, data_in, CRYS_AES_Key128BitSize, CRYS_AES_Encrypt,
                          CRYS_AES_ECB_KLAD_mode);
    if (error != CRYS_OK) {
        hi_log_error("CRYS_AES_Init failed, err= 0x%x\n", error);
        goto __EXIT__;
    }

    /* cipher handle saved in the buffer first word */
    cipher = context_id.buff[0];

    error = hi_tee_drv_klad_attach(klad, cipher);
    if (error != CRYS_OK) {
        hi_log_error("hi_tee_drv_klad_attach failed, err= 0x%x\n", error);
        goto __EXIT__;
    }

    error = hi_tee_drv_klad_set_content_key(klad, &content_key);
    if (error != CRYS_OK) {
        hi_log_error("hi_tee_drv_klad_set_content_key failed, err= 0x%x\n", error);
        goto __EXIT__;
    }

    error = CRYS_AES_Finish(&context_id, data_in, 16, hmac_key); /* key length is 16 */
    if (error != CRYS_OK) {
        hi_log_error("CRYS_AES_Finish failed, err= 0x%x\n", error);
        goto __EXIT__;
    }

__EXIT__:
    (hi_void) hi_tee_drv_klad_destroy(klad);

    return error;
#else
    return CRYS_FATAL_ERROR;
#endif
}

CRYSError_t crys_pkcs5_pbkdf2_hmac256_hard_key(hi_cipher_pbkdf2 *pstInfo, DxUint8_t *output)
{
    CRYSError_t error;
    hi_u8 hmac_key[16] = { 0 }; /* key length is 16 */

    error = crys_load_securestore_rootkey(hmac_key, sizeof(hmac_key));
    if (error != CRYS_OK) {
        hi_log_error("crys_load_securestore_rootkey failed, err= 0x%x\n", error);
        return CRYS_FATAL_ERROR;
    }

    pstInfo->hmac_key = hmac_key;
    pstInfo->hmac_key_len = 16; /* key length is 16 */

    return crys_pkcs5_pbkdf2_hmac256(pstInfo, output);
}
#else
CRYSError_t crys_pkcs5_pbkdf2_hmac256_hard_key(hi_cipher_pbkdf2 *pstInfo, DxUint8_t *output)
{
    CRYSError_t error = CRYS_ERROR_BASE;
    hi_u8 hmac_key[16] = { 0 }; /* key length is 16 */

    pstInfo->hmac_key = hmac_key;
    pstInfo->hmac_key_len = 16; /* key length is 16 */

    return crys_pkcs5_pbkdf2_hmac256(pstInfo, output);
}
#endif
CRYSError_t crys_pkcs5_pbkdf2_hmac256(hi_cipher_pbkdf2 *pstInfo, DxUint8_t *output)
{
    hi_u32 i, j;
    CRYS_HASH_Result_t md1;
    CRYS_HASH_Result_t work;
    hi_u32 use_len;
    hi_u8 *out_p = output;
    hi_u8 counter[4] = { 0 }; /* size is 4 */
    hi_u32 md_size = 32; /* SHA256 output 32 bytes */
    hi_s32 ret;
    hi_u32 handle = 0;
#ifndef MHASH_NONSUPPORT
    hi_u32 local = 0;
#endif

    if ((pstInfo == HI_NULL)
        || (pstInfo->hmac_key == HI_NULL)
        || (pstInfo->salt == HI_NULL)
        || (output == HI_NULL)) {
        hi_log_error("Error, invalid pointer\n");
        return CRYS_FATAL_ERROR;
    }

    ret = memset_s(counter, sizeof(counter), 0, 4); /* size is 4 */
    if (ret != 0) {
        hi_log_print_func_err(memset_s, ret);
        return ret;
    }

    counter[3] = 1; /* set pos 3 to 1 */

#ifndef MHASH_NONSUPPORT
    ret = kapi_hash_start(&local, HI_CIPHER_HASH_TYPE_HMAC_SHA256, pstInfo->hmac_key, pstInfo->hmac_key_len);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(kapi_hash_start, ret);
        return ret;
    }
#endif

    while (pstInfo->key_length) {
#ifdef MHASH_NONSUPPORT
        ret = kapi_hash_start(&handle, CRYP_CIPHER_HASH_TYPE_HMAC_SHA256, pstInfo->hmac_key, pstInfo->hmac_key_len);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(kapi_hash_start, ret);
            return ret;
        }
#else
        ret = kapi_hash_clone(&handle, local);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(kapi_hash_clone, ret);
            goto exit__;
        }
#endif
        ret = kapi_hash_update(handle, pstInfo->salt, pstInfo->slen, HASH_CHUNCK_SRC_LOCAL);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(kapi_hash_update, ret);
            goto exit__;
        }
        ret = kapi_hash_update(handle, counter, 4, HASH_CHUNCK_SRC_LOCAL); /* size is 4 */
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(kapi_hash_update, ret);
            goto exit__;
        }
        ret = kapi_hash_finish(handle, (hi_u8 *)work, sizeof(CRYS_HASH_Result_t), &md_size);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(kapi_hash_finish, ret);
            goto exit__;
        }

        ret = memcpy_s(md1, sizeof(md1), work, md_size);
        if (ret != CRYS_OK) {
            hi_log_print_func_err(memcpy_s, ret);
            goto exit__;
        }

        for (i = 1; i < pstInfo->iteration_count; i++) {
#ifdef MHASH_NONSUPPORT
            ret = kapi_hash_start(&handle, CRYP_CIPHER_HASH_TYPE_HMAC_SHA256, pstInfo->hmac_key, pstInfo->hmac_key_len);
            if (ret != HI_SUCCESS) {
                return HI_FAILURE;
            }
#else
            ret = kapi_hash_clone(&handle, local);
            if (ret != HI_SUCCESS) {
                goto exit__;
            }
#endif
            ret = kapi_hash_update(handle, (hi_u8 *)md1, md_size, HASH_CHUNCK_SRC_LOCAL)
                  || kapi_hash_finish(handle, (hi_u8 *)md1, sizeof(md1), &md_size);
            if (ret != HI_SUCCESS) {
                goto exit__;
            }
            for (j = 0; j < md_size; j++) {
                ((DxUint8_t *)work)[j] ^= ((DxUint8_t *)md1)[j];
            }
        }

        use_len = (pstInfo->key_length < md_size) ? pstInfo->key_length : md_size;
        ret = memcpy_s(out_p, pstInfo->key_length, work, use_len);
        if (ret != CRYS_OK) {
            hi_log_print_func_err(memcpy_s, ret);
            goto exit__;
        }

        pstInfo->key_length -= (uint32_t)use_len;
        out_p += use_len;

        for (i = 4; i > 0; i--) /* initial value is 4 */
            if (++counter[i - 1] != 0) {
                break;
            }
    }
exit__:
#ifndef MHASH_NONSUPPORT
    kapi_hash_finish(local, (hi_u8 *)work, sizeof(work), &md_size);
#endif
    return (ret);
}

static CRYSError_t crys_hmac_gen_rootkey(void)
{
    hi_cipher_pbkdf2 info;
    CRYSError_t err;

    if (g_hmac_rootkey_init) {
        return CRYS_OK;
    }

    (void)memset_s(&info, sizeof(info), 0, sizeof(hi_cipher_pbkdf2));
    info.iteration_count = 1;
    info.key_length = SECURE_STORAGE_KEY_LEN;
    info.hmac_key = HI_NULL; /* use SECURE_STORE_ROOTKEY */
    info.hmac_key_len = 0;
    info.salt = (hi_u8 *)g_mask_str;
    info.slen = strlen(g_mask_str);

    err = crys_pkcs5_pbkdf2_hmac256_hard_key(&info, g_mask_res);
    if (err != CRYS_OK) {
        hi_log_error("crys_pkcs5_pbkdf2_hmac256_hard_key failed, err= 0x%x\n", err);
        return CRYS_FATAL_ERROR;
    }

    g_hmac_rootkey_init = 1;
    return CRYS_OK;
}

static CRYSError_t crys_check_rootkey_uuid(void)
{
    TEE_UUID ta_uuid = { 0 };
    unsigned int i;
    unsigned int num = sizeof(g_rootkey_uuids) / sizeof(TEE_UUID);
    (void)memset_s(&ta_uuid, sizeof(TEE_UUID), 0, sizeof(TEE_UUID));

    if (crypto_get_owner(&ta_uuid)) {
        hi_log_error("Get current TA uuid failed.\n");
        return CRYS_FATAL_ERROR;
    }
    for (i = 0; i < num; i++) {
        if (!memcmp(&g_rootkey_uuids[i], &ta_uuid, sizeof(TEE_UUID))) {
            return CRYS_OK;
        }
    }
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_KDF_KeyDerivFunc(DxUint8_t *ZZSecret_ptr,
                                            DxUint32_t ZZSecretSize,
                                            CRYS_KDF_OtherInfo_t *OtherInfo_ptr,
                                            CRYS_KDF_HASH_OpMode_t KDFhashMode,
                                            CRYS_KDF_DerivFuncMode_t derivation_mode,
                                            DxUint8_t *KeyingData_ptr,
                                            DxUint32_t KeyingDataSizeBytes)
{
    hi_cipher_pbkdf2 info;
    CRYSError_t err;

    err = crys_check_rootkey_uuid();
    if (err != CRYS_OK) {
        hi_log_error("Check rootkey uuid failed\n");
        return CRYS_FATAL_ERROR;
    }

    if (ZZSecret_ptr == HI_NULL) {
        hi_log_error("Invalid input\n");
        return CRYS_FATAL_ERROR;
    }

    if (crys_hmac_gen_rootkey() != CRYS_OK) {
        return CRYS_FATAL_ERROR;
    }

    /* PBKDF2 */
    (void)memset_s(&info, sizeof(info), 0, sizeof(hi_cipher_pbkdf2));
    info.iteration_count = 2; /* set diff from DX_UTIL_CmacDeriveKey to 2 */
    info.key_length = KeyingDataSizeBytes;
    info.hmac_key = (hi_u8 *)&g_mask_res;
    info.hmac_key_len = sizeof(g_mask_res);
    info.salt = ZZSecret_ptr;
    info.slen = ZZSecretSize;

    err = crys_pkcs5_pbkdf2_hmac256(&info, KeyingData_ptr);
    if (err != CRYS_OK) {
        hi_log_error("crys_pkcs5_pbkdf2_hmac256 failed, err= 0x%x\n", err);
        return CRYS_FATAL_ERROR;
    }

    return err;
}

/*
 * CRYS_DeriveKey
 * @pDataIn input
 * @dataInSize size of input
 * @pCmacResult result buffer
 *
 * Hardware HMAC to derivekey for secure stroage
 */
CRYSError_t CRYS_DeriveKey(DxUint8_t *pDataIn,
                           DxUint32_t dataInSize, DxUint8_t *pCmacResult)
{
    hi_cipher_pbkdf2 info;
    CRYSError_t err;
    s32 ret;
    if (pDataIn == HI_NULL) {
        hi_log_error("Invalid pDataIn\n");
        return CRYS_FATAL_ERROR;
    }

    if (crys_hmac_gen_rootkey() != CRYS_OK) {
        return CRYS_FATAL_ERROR;
    }

    ret = memset_s(&info, sizeof(info), 0, sizeof(hi_cipher_pbkdf2));
    if (ret != HI_SUCCESS) {
        return ret;
    }

    info.iteration_count = 1;
    info.key_length = DX_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES;
    info.hmac_key = (hi_u8 *)&g_mask_res;
    info.hmac_key_len = DX_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES;
    info.salt = pDataIn;
    info.slen = dataInSize;

    err = crys_pkcs5_pbkdf2_hmac256(&info, pCmacResult);
    if (err != CRYS_OK) {
        hi_log_error("crys_pkcs5_pbkdf2_hmac256 failed, err= 0x%x\n", err);
        return CRYS_FATAL_ERROR;
    }

    return CRYS_OK;
}
/**
 * DX_UTIL_CmacDeriveKey
 * @aesKeyType aes key type
 * @pDataIn input
 * @dataInSize input size
 * @pCmacResult result buffer
 *
 * HMAC with current TA uuid to make sure other TA can not create a same key.
 */
CRYSError_t DX_UTIL_CmacDeriveKey(DX_UTIL_KeyType_t aesKeyType,
                                  DxUint8_t *pDataIn,
                                  DxUint32_t dataInSize,
                                  DX_UTIL_AES_CmacResult_t pCmacResult)
{
    hi_log_error("DX_UTIL_CmacDeriveKey enter\n");
#ifndef HI_CIPHER_TEST
    CRYSError_t err;

    err = crys_check_rootkey_uuid();
    if (err != CRYS_OK) {
        hi_log_error("Check rootkey uuid failed\n");
        return CRYS_FATAL_ERROR;
    }
#endif

    if (aesKeyType != DX_UTIL_KDR_KEY) {
        hi_log_error("Not support aesKeyType[%d]\n", aesKeyType);
        return CRYS_FATAL_ERROR;
    }

    return CRYS_DeriveKey(pDataIn, dataInSize, pCmacResult);
}
