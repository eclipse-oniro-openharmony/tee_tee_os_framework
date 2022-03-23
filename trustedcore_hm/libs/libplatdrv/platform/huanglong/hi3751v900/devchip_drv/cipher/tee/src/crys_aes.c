/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: for aes
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "crys_aes.h"
#include "dx_pal_types.h"
#include "crys_aes.h"
#include "crys_aes_error.h"
#include "drv_osal_lib.h"
#include "ext_alg.h"

#define CIPHER_MMZ_BUFF_SIZE      (0x2000 - 16)
#define CRYS_AES_DATA_IN_MIN_SIZE (2 * CRYS_AES_BLOCK_SIZE_IN_BYTES)

typedef struct hiaes_user_context {
    hi_handle cipher;
    hi_bool is_decrypt;
    CRYS_AES_OperationMode_t operation_mode;
    hi_u8 last_block[CRYS_AES_BLOCK_SIZE_IN_BYTES];
} aes_user_context;

/* !
 * Converts Symmetric Adaptor return code to CRYS error code.
 *
 * \param error_code Symmetric Adaptor return error.
 * \param error_info Ignored.
 *
 * \return CRYSError_t one of CRYS_* error codes defined in crys_error.h
 */
static CRYSError_t sym_adaptor_to_crys_aes_err(int error_code, DxUint32_t error_info)
{
    CRYSError_t err;

    switch (error_code) {
        case HI_ERR_CIPHER_UNSUPPORTED:
            err = CRYS_AES_IS_NOT_SUPPORTED;
            break;
        case HI_ERR_CIPHER_FAILED_INIT:
            err = CRYS_AES_IS_NOT_SUPPORTED;
            break;
        case HI_ERR_CIPHER_INVALID_POINT:
            err = CRYS_AES_WRAP_ILLEGAL_DATA_PTR_ERROR;
            break;
        case HI_ERR_CIPHER_INVALID_PARA:
            err = CRYS_AES_ILLEGAL_PARAMS_ERROR;
            break;
        case HI_ERR_CIPHER_FAILED_CONFIGAES:
            err = CRYS_AES_ILLEGAL_PARAMS_ERROR;
            break;
        case HI_ERR_CIPHER_FAILED_CONFIGDES:
            err = CRYS_AES_ILLEGAL_PARAMS_ERROR;
            break;
        case HI_ERR_CIPHER_BUSY:
        case HI_ERR_CIPHER_NO_AVAILABLE_RNG:
            err = CRYS_AES_IS_NOT_SUPPORTED;
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

static hi_cipher_work_mode make_sep_aes_mode(CRYS_AES_OperationMode_t operation_mode)
{
    hi_cipher_work_mode result;

    switch (operation_mode) {
        case CRYS_AES_ECB_mode:
            result = HI_CIPHER_WORK_MODE_ECB;
            break;
        case CRYS_AES_CBC_mode:
            result = HI_CIPHER_WORK_MODE_CBC;
            break;
        case CRYS_AES_CTR_mode:
            result = HI_CIPHER_WORK_MODE_CTR;
            break;
        case CRYS_AES_CMAC_mode:
            result = HI_CIPHER_WORK_MODE_CBC;
            break;
        case CRYS_AES_OFB_mode:
            result = HI_CIPHER_WORK_MODE_OFB;
            break;
        case CRYS_AES_CBC_CTS_mode:
            result = HI_CIPHER_WORK_MODE_CBC_CTS;
            break;
        default:
            result = HI_CIPHER_WORK_MODE_MAX;
    }

    return result;
}

/****************************************************************************************************/
/**
 * @brief This function is used to initialize the AES machine or SW structures.
 *        To perform the AES operations this should be the first function called.
 *
 *        The actual macros, that will be used by the user for calling this function, are described
 *        in crys_aes.h file.
 *
 * @param[in] ContextID_ptr - A pointer to the AES context buffer that is allocated by the user
 *                            and is used for the AES machine operation.
 * @param[in] IVCounter_ptr - A buffer containing an initial value: IV, Counter or Tweak according
 *                            to operation mode:
 *                            - on ECB, XCBC, CMAC mode this parameter is not used and may be NULL,
 *                            - on CBC and MAC modes it contains the IV value,
 *                            - on CTR and OFB modes it contains the init counter,
 *                            - on XTS mode it contains the initial tweak value - 128-bit consecutive number
 *                              of data unit (in little endian).
 * @param[in] Key_ptr  -  A pointer to the user's key buffer.
 * @param[in] KeySize  -  An enum parameter, defines size of used key (128, 192, 256, 512 bits):
 *                        On XCBC mode allowed 128 bit size only, on XTS - 256 or 512 bit, on other modes <= 256 bit.
 * @param[in] EncryptDecryptFlag - A flag specifying whether the AES should perform an Encrypt operation (0)
 *                                 or a Decrypt operation (1). In XCBC, MAC and CMAC modes it must be Encrypt.
 * @param[in] operation_mode - The operation mode: ECB, CBC, MAC, CTR, OFB, XCBC (PRF and 96), CMAC.
 *
 * @return CRYSError_t - On success the value CRYS_OK is returned, and on failure - a value from crys_aes_error.h
 */
static CIMPORT_C CRYSError_t CheckMode(CRYS_AES_OperationMode_t operation_mode,
                                       CRYS_AES_EncryptMode_t EncryptDecryptFlag, CRYS_AES_IvCounter_t IVCounter_ptr)
{
    /* check if the operation mode is legal */
    if ((operation_mode >= CRYS_AES_NumOfModes) || (operation_mode == CRYS_AES_CCM_mode)) {
        return CRYS_AES_ILLEGAL_OPERATION_MODE_ERROR;
    }

    /* check if the mode is supported */
    if ((operation_mode != CRYS_AES_ECB_mode) && (operation_mode != CRYS_AES_CBC_mode) &&
        (operation_mode != CRYS_AES_OFB_mode) && (operation_mode != CRYS_AES_CTR_mode) &&
        (operation_mode != CRYS_AES_CBC_CTS_mode) && (operation_mode != CRYS_AES_CMAC_mode)) {
        return CRYS_AES_ILLEGAL_OPERATION_MODE_ERROR;
    }

    /* if the operation mode selected is CBC,CTS, MAC, CTR, XTS or OFB then check the validity of
    the IV counter pointer (note: on XTS mode it is the Tweak pointer) */
    if (((operation_mode == CRYS_AES_CBC_mode) || (operation_mode == CRYS_AES_CTR_mode) ||
         (operation_mode == CRYS_AES_MAC_mode) || (operation_mode == CRYS_AES_XTS_mode) ||
         (operation_mode == CRYS_AES_CBC_CTS_mode) || (operation_mode == CRYS_AES_OFB_mode)) &&
        (IVCounter_ptr == DX_NULL)) {
        return CRYS_AES_INVALID_IV_OR_TWEAK_PTR_ERROR;
    }

    /* check the Encrypt / Decrypt flag validity */
    if (EncryptDecryptFlag >= CRYS_AES_EncryptNumOfOptions) {
        return CRYS_AES_INVALID_ENCRYPT_MODE_ERROR;
    }
    /* in MAC,XCBC,CMAC modes enable only encrypt mode */
    if (((operation_mode == CRYS_AES_XCBC_MAC_mode) || (operation_mode == CRYS_AES_CMAC_mode) ||
         (operation_mode == CRYS_AES_MAC_mode)) &&
        (EncryptDecryptFlag != CRYS_AES_Encrypt)) {
        return CRYS_AES_DECRYPTION_NOT_ALLOWED_ON_THIS_MODE;
    }

    return CRYS_OK;
}

static CIMPORT_C CRYSError_t crys_get_key_len(CRYS_AES_KeySize_t key_size_id,
                                              hi_cipher_key_length *cipher_key_len,
                                              hi_u32 *klen)
{
    /* check the max key size for all modes besides XTS */
    if (key_size_id > CRYS_AES_Key256BitSize) {
        return CRYS_AES_ILLEGAL_KEY_SIZE_ERROR;
    }

    /* get AES_Key size in bytes */
    switch (key_size_id) {
        case CRYS_AES_Key128BitSize:
            *cipher_key_len = HI_CIPHER_KEY_AES_128BIT;
            *klen = 16; /* 16: 128bit */
            break;

        case CRYS_AES_Key192BitSize:
            *cipher_key_len = HI_CIPHER_KEY_AES_192BIT;
            *klen = 24; /* 24: 192bit */
            break;

        case CRYS_AES_Key256BitSize:
            *cipher_key_len = HI_CIPHER_KEY_AES_256BIT;
            *klen = 32; /* 32: 256bit */
            break;
        default:
            return CRYS_AES_ILLEGAL_KEY_SIZE_ERROR; /* for preventing compiler warnings */
    }

    return HI_SUCCESS;
}

CIMPORT_C CRYSError_t CRYS_AES_Init(CRYS_AESUserContext_t *ContextID_ptr,
                                    CRYS_AES_IvCounter_t IVCounter_ptr,
                                    CRYS_AES_Key_t Key_ptr,
                                    CRYS_AES_KeySize_t key_size_id,
                                    CRYS_AES_EncryptMode_t EncryptDecryptFlag,
                                    CRYS_AES_OperationMode_t operation_mode)
{
    hi_s32 ret;
    aes_user_context *user_context = DX_NULL;
    hi_cipher_work_mode work_mode;
    hi_cipher_key_length cipher_key_len = HI_CIPHER_KEY_DEFAULT;
    hi_u32 klen = 0;

    /* if the users context ID pointer is DX_NULL return an error */
    if (ContextID_ptr == DX_NULL) {
        return CRYS_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    user_context = (aes_user_context *)ContextID_ptr;
    ret = memset_s(user_context, sizeof(aes_user_context), 0, sizeof(aes_user_context));
    if (ret != 0) {
        return ret;
    }

    ret = CheckMode(operation_mode, EncryptDecryptFlag, IVCounter_ptr);
    if (ret != CRYS_OK) {
        return ret;
    }

    /* check the validity of the key pointer */
    if (Key_ptr == DX_NULL) {
        return CRYS_AES_INVALID_KEY_POINTER_ERROR;
    }

    work_mode = make_sep_aes_mode(operation_mode);
    if (work_mode >= HI_CIPHER_WORK_MODE_MAX) {
        return CRYS_AES_ILLEGAL_OPERATION_MODE_ERROR;
    }

    ret = crys_get_key_len(key_size_id, &cipher_key_len, &klen);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(crys_get_key_len, ret);
        return CRYS_FATAL_ERROR;
    }

    user_context->operation_mode = operation_mode;
    user_context->is_decrypt = (EncryptDecryptFlag == CRYS_AES_Decrypt) ? 1 : 0;

    ret = kapi_symc_create(&user_context->cipher, HI_CIPHER_TYPE_NORMAL);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(kapi_symc_create, ret);
        return CRYS_FATAL_ERROR;
    }

    ret = crys_aes_set_clear_key(user_context->cipher, Key_ptr, klen);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(crys_aes_set_clear_key, ret);
        ret = kapi_symc_destroy(user_context->cipher);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(kapi_symc_destroy, ret);
        }
        return CRYS_FATAL_ERROR;
    }

    if (CRYS_AES_CMAC_mode == operation_mode) {
        ret = ext_aes_cmac_init(user_context->cipher, HI_FALSE, Key_ptr, klen);
    } else {
        ret = kapi_symc_config(user_context->cipher, HI_CIPHER_ALG_AES,
                               work_mode, HI_CIPHER_BIT_WIDTH_128BIT, cipher_key_len,
                               IVCounter_ptr, CRYS_AES_IV_COUNTER_SIZE_IN_BYTES, CIPHER_IV_CHANGE_ONE_PKG,
                               ADDR_NULL, 0, 0);
    }

    if (ret != HI_SUCCESS) {
        ret = kapi_symc_destroy(user_context->cipher);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(kapi_symc_destroy, ret);
        }
        return CRYS_FATAL_ERROR;
    }

    return DX_CRYS_RETURN_ERROR(ret, 0, sym_adaptor_to_crys_aes_err);
}

/****************************************************************************************************/
/**
 * @brief This function is used to operate a block of data on the SW or on AES machine.
 *        This function should be called after the appropriate CRYS AES init function
 *        (according to used AES operation mode).
 *
 * @param[in] ContextID_ptr - A pointer to the AES context buffer allocated by the user that
 *                            is used for the AES machine operation. This should be the same context that was
 *                            used on the previous call of this session.
 *
 * @param[in] DataIn_ptr - A pointer to the buffer of the input data to the AES. The pointer does
 *                         not need to be aligned. On CSI input mode the pointer must be equal to
 *                         value (0xFFFFFFFC | DataInAlignment).
 *
 * @param[in] DataInSize - A size of the input data must be multiple of 16 bytes and not 0,
 *                         on all modes. Note last chunk (block) of data must be processed by
 *                         CRYS_AES_Finish function but not by CRYS_AES_Block function;
 *
 * @param[out] DataOut_ptr - A pointer to the buffer of the output data from the AES. The pointer  does not
 *                             need to be aligned. On CSI output mode the pointer must be equal to
 *                             value (0xFFFFFFFC | DataOutAlignment). On all MAC modes (MAC,XCBC, CMAC) CSI
 *                             output is not allowed.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                       value MODULE_* CRYS_DES_error.h
 *
 *     NOTES: 1. Temporarily it is not allowed, that both the Input and the Output simultaneously
 *               were on CSI mode.
 *            2. Temporarily the CSI input or output are not allowed on XCBC, CMAC and XTS modes.
 */
CIMPORT_C CRYSError_t CRYS_AES_Block(CRYS_AESUserContext_t *ContextID_ptr,
                                     DxUint8_t *DataIn_ptr,
                                     DxUint32_t DataInSize,
                                     DxUint8_t *DataOut_ptr)
{
    hi_s32 ret;
    hi_u32 copy_size = 0;
    hi_u32 real_size = 0;
    hi_u32 total = 0;
    aes_user_context user_context;
    compat_addr input;
    compat_addr output;
    crypto_mem src_mmz_in;
    crypto_mem src_mmz_out;

    /* if the users context ID pointer is DX_NULL return an error */
    if (ContextID_ptr == DX_NULL) {
        return CRYS_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    ret = memset_s(&user_context, sizeof(user_context), 0, sizeof(aes_user_context));
    if (ret != 0) {
        return ret;
    }

    ret = memset_s(&input, sizeof(input), 0, sizeof(input));
    if (ret != 0) {
        return ret;
    }

    ret = memset_s(&output, sizeof(output), 0, sizeof(output));
    if (ret != 0) {
        return ret;
    }

    ret = memset_s(&src_mmz_in, sizeof(src_mmz_in), 0, sizeof(src_mmz_in));
    if (ret != 0) {
        return ret;
    }

    ret = memset_s(&src_mmz_out, sizeof(src_mmz_out), 0, sizeof(src_mmz_out));
    if (ret != 0) {
        return ret;
    }

    ret = memcpy_s(&user_context, sizeof(user_context), ContextID_ptr, sizeof(aes_user_context));
    if (ret != CRYS_OK) {
        return ret;
    }

    /* if the users Data In pointer is illegal return an error */
    if ((DataIn_ptr == DX_NULL)) {
        ret = kapi_symc_destroy(user_context.cipher);
        if (ret != HI_SUCCESS) {
            return CRYS_FATAL_ERROR;
        }
        return CRYS_AES_DATA_IN_POINTER_INVALID_ERROR;
    }

    if (((user_context.operation_mode == CRYS_AES_ECB_mode) ||
         (user_context.operation_mode == CRYS_AES_CBC_mode))
        && (DataInSize % CRYS_AES_BLOCK_SIZE_IN_BYTES != 0)) {
        ret = kapi_symc_destroy(user_context.cipher);
        if (ret != HI_SUCCESS) {
            return CRYS_FATAL_ERROR;
        }
        return CRYS_AES_DATA_IN_SIZE_ILLEGAL;
    }

    ret = crypto_mem_create(&src_mmz_in, SEC_MMZ, "AES_IN",
                            CIPHER_MMZ_BUFF_SIZE + CRYS_AES_BLOCK_SIZE_IN_BYTES);
    if (ret != HI_SUCCESS) {
        ret = kapi_symc_destroy(user_context.cipher);
        if (ret != HI_SUCCESS) {
            return CRYS_FATAL_ERROR;
        }
        return CRYS_FATAL_ERROR;
    }
    (hi_void) crypto_mem_phys(&src_mmz_in, &input);

    ret = crypto_mem_create(&src_mmz_out, SEC_MMZ, "AES_OUT",
                            CIPHER_MMZ_BUFF_SIZE + CRYS_AES_BLOCK_SIZE_IN_BYTES);
    if (ret != HI_SUCCESS) {
        (hi_void) crypto_mem_destory(&src_mmz_in);
        ret = kapi_symc_destroy(user_context.cipher);
        if (ret != HI_SUCCESS) {
            return CRYS_FATAL_ERROR;
        }
        return CRYS_FATAL_ERROR;
    }
    (hi_void) crypto_mem_phys(&src_mmz_out, &output);

    while (total < DataInSize) {
        if ((DataInSize - total) > CIPHER_MMZ_BUFF_SIZE) {
            copy_size = CIPHER_MMZ_BUFF_SIZE;
            real_size = copy_size;
        } else {
            copy_size = DataInSize - total;
            real_size = copy_size;
            if (CRYS_AES_CBC_CTS_mode != user_context.operation_mode) {
                copy_size = (copy_size + AES_BLOCK_SIZE_IN_BYTE - 1) & (~0x0F);
            }
        }

        (hi_void) crypto_mem_attach(&src_mmz_in, DataIn_ptr + total);

        ret = crypto_mem_flush(&src_mmz_in, HI_FALSE, 0, real_size);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(crypto_mem_flush, ret);
            (hi_void) crypto_mem_destory(&src_mmz_in);
            (hi_void) crypto_mem_destory(&src_mmz_out);
            ret = kapi_symc_destroy(user_context.cipher);
            if (ret != HI_SUCCESS) {
                hi_log_error("Cipher destory failed.\n");
                return CRYS_FATAL_ERROR;
            }
            return CRYS_FATAL_ERROR;
        }

        ret = kapi_symc_crypto(user_context.cipher, input,
                               output, copy_size, user_context.is_decrypt, HI_FALSE, HI_CIPHER_DATA_DIR_TEE2TEE);
        if (ret != HI_SUCCESS) {
            hi_log_error("Cipher encrypt failed.\n");
            (hi_void) crypto_mem_destory(&src_mmz_in);
            (hi_void) crypto_mem_destory(&src_mmz_out);
            ret = kapi_symc_destroy(user_context.cipher);
            if (ret != HI_SUCCESS) {
                hi_log_error("Cipher destory failed.\n");
                return CRYS_FATAL_ERROR;
            }
            return CRYS_FATAL_ERROR;
        }

        if ((user_context.operation_mode != CRYS_AES_CMAC_mode) && (DataOut_ptr != DX_NULL)) {
            if ((DataOut_ptr != DX_NULL)) {
                (hi_void) crypto_mem_attach(&src_mmz_out, DataOut_ptr + total);
                ret = crypto_mem_flush(&src_mmz_out, HI_TRUE, 0, real_size);
                if (ret != HI_SUCCESS) {
                    hi_log_print_func_err(crypto_mem_flush, ret);
                    (hi_void) crypto_mem_destory(&src_mmz_in);
                    (hi_void) crypto_mem_destory(&src_mmz_out);
                    ret = kapi_symc_destroy(user_context.cipher);
                    if (ret != HI_SUCCESS) {
                        hi_log_error("Cipher destory failed.\n");
                        return CRYS_FATAL_ERROR;
                    }
                    return CRYS_FATAL_ERROR;
                }
            }
        }
        total += real_size;
    }

    (hi_void) crypto_mem_destory(&src_mmz_in);
    (hi_void) crypto_mem_destory(&src_mmz_out);

    ret = memcpy_s(ContextID_ptr, sizeof(CRYS_AESUserContext_t), &user_context, sizeof(user_context));
    if (ret != CRYS_OK) {
        return ret;
    }

    return DX_CRYS_RETURN_ERROR(ret, 0, sym_adaptor_to_crys_aes_err);
}

/****************************************************************************************************/
/**
 * @brief This function is used as finish operation on all AES modes.
 *
 *        The function must be called after AES_Block operations (or instead) for last chunck
 *        of data with size > 0.
 *
 *        The function performs all operations, including specific operations for last blocks of
 *        data on some modes (XCBC, CMAC, MAC) and puts out the result. After all operations
 *        the function cleans the secure sensitive data from context.
 *
 *        1. Checks the validation of all of the inputs of the function.
 *           If one of the received parameters is not valid it shall return an error.
 *        2. Decrypts the received context to the working context  by calling the
 *           CRYS_CCM_GetContext function.
 *        3. Calls the LLF_AES_Finish function.
 *        4. Outputs the result and cleans working context.
 *        5. Exits
 *
 *
 * @param[in] ContextID_ptr - A pointer to the AES context buffer allocated by the user that
 *                            should be the same context that was used on the previous call
 *                            of this session.
 * @param[in] DataIn_ptr    - A pointer to the buffer of the input data to the AES. The pointer does
 *                            not need to be aligned. On CSI input mode the pointer must be equal to
 *                            value (0xFFFFFFFC | DataInAlignment).
 * @param[in] DataInSize    - A size of the input data must be:  DataInSize >= minimalSize, where:
 *                            minimalSize =
 *                                  -  1 byte for CTR, OFB, XCBC, CMAC mode;
 *                                  - 16 bytes for other modes.
 * @param[out] DataOut_ptr  - A pointer to the output buffer. The pointer  does not need to be aligned.
 *                            On CSI output mode the pointer must be equal to value
 *                            (0xFFFFFFFC | DataOutAlignment). On some modes (MAC,XCBC,CMAC,XTS)
 *                            CSI output is not allowed. Temporarily is not allowed, that both the
 *                            Input and the output are on CSI mode simultaneously.
 *                            The size of the output buffer must be not less than:
 *                                - 16 bytes for MAC, XCBC, CMAC modes;
 *                                - DataInSize for ECB,CBC,CTR,XTS,OFB modes.
 *
 * @return CRYSError_t    - On success CRYS_OK is returned, on failure - a value defined in crys_aes_error.h.
 *
 */
CIMPORT_C CRYSError_t CRYS_AES_Finish(CRYS_AESUserContext_t *ContextID_ptr,
                                      DxUint8_t *DataIn_ptr,
                                      DxUint32_t DataInSize,
                                      DxUint8_t *DataOut_ptr)
{
    hi_s32 ret;
    CRYSError_t err;
    aes_user_context user_context;

    /* if the users context ID pointer is DX_NULL return an error */
    if (ContextID_ptr == DX_NULL) {
        return CRYS_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    ret = memset_s(&user_context, sizeof(user_context), 0, sizeof(aes_user_context));
    if (ret != CRYS_OK) {
        return ret;
    }

    ret = memcpy_s(&user_context, sizeof(user_context), ContextID_ptr, sizeof(aes_user_context));
    if (ret != CRYS_OK) {
        return ret;
    }

    /* if the users Data In pointer is illegal return an error */
    if ((DataIn_ptr == DX_NULL) && (DataInSize != 0)) {
        ret = kapi_symc_destroy(user_context.cipher);
        if (ret != HI_SUCCESS) {
            return CRYS_FATAL_ERROR;
        }
        return CRYS_AES_DATA_IN_POINTER_INVALID_ERROR;
    }

    if ((DataInSize % CRYS_AES_BLOCK_SIZE_IN_BYTES != 0) &&
        ((user_context.operation_mode == CRYS_AES_ECB_mode) ||
         (user_context.operation_mode == CRYS_AES_CBC_mode))) {
        ret = kapi_symc_destroy(user_context.cipher);
        if (ret != HI_SUCCESS) {
            return CRYS_FATAL_ERROR;
        }
        return CRYS_AES_DATA_IN_SIZE_ILLEGAL;
    }

    /* Check, that in case of CTS mode data size is not less than CRYS_AES_BLOCK_SIZE_IN_BYTES */
    if ((DataInSize < CRYS_AES_BLOCK_SIZE_IN_BYTES) &&
        (user_context.operation_mode == CRYS_AES_CBC_CTS_mode)) {
        ret = kapi_symc_destroy(user_context.cipher);
        if (ret != HI_SUCCESS) {
            return CRYS_FATAL_ERROR;
        }
        return CRYS_AES_DATA_IN_SIZE_ILLEGAL;
    }

    if (CRYS_AES_CMAC_mode == user_context.operation_mode) {
        err = ext_aes_cmac_finish(user_context.cipher, DataIn_ptr, DataInSize, HI_FALSE, DataOut_ptr);
        if (err != CRYS_OK) {
            hi_log_error("ext_aes_cmac_finish error.\n");
            ret = kapi_symc_destroy(user_context.cipher);
            if (ret != HI_SUCCESS) {
                return CRYS_FATAL_ERROR;
            }
            return err;
        }
    } else if (DataInSize > 0) {
        err = CRYS_AES_Block(ContextID_ptr, DataIn_ptr, DataInSize, DataOut_ptr);
        if (err != CRYS_OK) {
            hi_log_error("CRYS_AES_Block error.\n");
            ret = kapi_symc_destroy(user_context.cipher);
            if (ret != HI_SUCCESS) {
                return CRYS_FATAL_ERROR;
            }
            return err;
        }
    }

    ret = kapi_symc_destroy(user_context.cipher);
    if (ret != HI_SUCCESS) {
        hi_log_error("Cipher encrypt failed.\n");
    }

    return DX_CRYS_RETURN_ERROR(ret, 0, sym_adaptor_to_crys_aes_err);
}

/****************************************************************************************************/
/**
 * @brief This function is used to perform the AES operation in one integrated process.
 *
 *        The input-output parameters of the function are the following:
 *
 * @param[in] IVCounter_ptr - A buffer containing an initial value: IV, Counter or Tweak according
 *                            to operation mode:
 *                            - on ECB, XCBC, CMAC mode this parameter is not used and may be NULL,
 *                            - on CBC and MAC modes it contains the IV value,
 *                            - on CTR and OFB modes it contains the init counter,
 *                            - on XTS mode it contains the initial tweak value - 128-bit consecutive number
 *                              of data unit (in little endian).
 * @param[in] Key_ptr  -  A pointer to the user's key buffer.
 * @param[in] KeySize  -  An enum parameter, defines size of used key (128, 192, 256 bits).
 * @param[in] EncryptDecryptFlag - A flag specifying whether the AES should perform an Encrypt operation (0)
 *                                 or a Decrypt operation (1). In XCBC and CMAC modes it must be 0.
 * @param[in] operation_mode - The operation mode: ECB, CBC, MAC, CTR, XCBC (PRF and 96), CMAC, XTS, OFB.
 * @param[in] DataIn_ptr - A pointer to the buffer of the input data to the AES.
 *
 * @param[in] DataInSize - The size of the input data, it must be:
 *                         - on ECB,CBC,MAC modes must be a multiple of 16 bytes
 *                         - on CTR, XCBC, CMAC and OFB modes any value
 *                 - on XTS mode: If input or output pointers are in the D-Cache range,
 *                   only the following data sizes are supported: 64B, 512B, 520B, 521B. Otherwise,
 *                   1024B and 4096B are also supported.
 * @param[out] DataOut_ptr - A pointer to the buffer of the output data from the AES
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a value defined in crys_aes_error.h
 *
 */
CIMPORT_C CRYSError_t CRYS_AES(CRYS_AES_IvCounter_t IVCounter_ptr,
                               CRYS_AES_Key_t Key_ptr,
                               CRYS_AES_KeySize_t KeySize,
                               CRYS_AES_EncryptMode_t EncryptDecryptFlag,
                               CRYS_AES_OperationMode_t operation_mode,
                               DxUint8_t *DataIn_ptr,
                               DxUint32_t DataInSize,
                               DxUint8_t *DataOut_ptr)
{
    CRYS_AESUserContext_t user_context;
    CRYSError_t error;

    /* check, that data size is multiple of 16 bytes on relevant modes */
    if (((DataInSize % CRYS_AES_BLOCK_SIZE_IN_BYTES) != 0) && ((operation_mode == CRYS_AES_ECB_mode) ||
                                                               (operation_mode == CRYS_AES_CBC_mode) ||
                                                               (operation_mode == CRYS_AES_MAC_mode))) {
        return CRYS_AES_DATA_IN_SIZE_ILLEGAL;
    }

    /* check the minimum data size according to mode */
    if ((operation_mode == CRYS_AES_XTS_mode) && (DataInSize < CRYS_AES_DATA_IN_MIN_SIZE)) {
        return CRYS_AES_DATA_IN_SIZE_ILLEGAL;
    }

    error = memset_s(&user_context, sizeof(user_context), 0, sizeof(CRYS_AESUserContext_t));
    if (error != 0) {
        return error;
    }

    error = CRYS_AES_Init(&user_context, IVCounter_ptr, Key_ptr, KeySize, EncryptDecryptFlag, operation_mode);
    if (error != CRYS_OK) {
        goto end;
    }

    error = CRYS_AES_Finish(&user_context, DataIn_ptr, DataInSize, DataOut_ptr);

end:
    return error;
}
