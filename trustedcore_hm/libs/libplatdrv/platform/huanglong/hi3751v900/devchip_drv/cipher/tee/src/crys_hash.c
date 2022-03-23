/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hash
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "hi_type_dev.h"
#include "crys_aes.h"
#include "dx_pal_types.h"
#include "crys_hash.h"
#include "crys_hash_error.h"
#include "crys_cipher_common.h"
#include "drv_osal_lib.h"

/************************ Defines ******************************/
#define HMAC_MMZ_BUFF_SIZE     0x2000
#define HASH_BLOCK_SIZE        64
#define HASH_PAD_MAX_LEN       64
#define HASH1_SIGNATURE_SIZE   20
#define HASH256_SIGNATURE_SIZE 32

typedef struct hi_cipher_hash_info {
    hi_handle hash;
    hi_cipher_hash_type hash_type;
} cipher_hash_info;

typedef struct hi_hash_user_context {
    CRYS_HASH_OperationMode_t operation_mode;
    union {
        hi_handle hash;
    } ctx;
} hash_user_context;


/*
 * Converts Symmetric Adaptor return code to CRYS error code.
 *
 * \param error_code Symmetric Adaptor return error.
 * \param error_info Ignored.
 *
 * \return CRYSError_t one of CRYS_* error codes defined in crys_error.h
 */
static CRYSError_t adaptor_to_crys_hash_err(int error_code, DxUint32_t error_info)
{
    CRYSError_t err;

    switch (error_code) {
        case HI_ERR_CIPHER_UNSUPPORTED:
            err = CRYS_HASH_IS_NOT_SUPPORTED;
            break;
        case HI_ERR_CIPHER_FAILED_INIT:
            err = CRYS_HASH_IS_NOT_SUPPORTED;
            break;
        case HI_ERR_CIPHER_INVALID_POINT:
            err = CRYS_HASH_DATA_IN_POINTER_INVALID_ERROR;
            break;
        case HI_ERR_CIPHER_INVALID_PARA:
            err = CRYS_HASH_DATA_SIZE_ILLEGAL;
            break;
        case HI_ERR_CIPHER_BUSY:
        case HI_ERR_CIPHER_NO_AVAILABLE_RNG:
            err = CRYS_HASH_IS_NOT_SUPPORTED;
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

/**
 * This function initializes the HASH machine on the CRYS level.
 *
 * This function allocates and initializes the HASH Context .
 * The function receives as input a pointer to store the context handle to HASH Context ,
 * it initializes the
 * HASH Context with the cryptographic attributes that are needed for
 * the HASH block operation (initialize H's value for the HASH algorithm).
 *
 * The function flow:
 *
 * 1) checking the validity of the arguments - returnes an error on an illegal argument case.
 * 2) Aquiring the working context from the CCM manager.
 * 3) Initializing the context with the parameters passed by the user and with the init values
 *    of the HASH.
 * 4) loading the user tag to the context.
 * 5) release the CCM context.
 *
 * @param[in] ContextID_ptr - a pointer to the HASH context buffer allocated by the user that
 *                       is used for the HASH machine operation.
 *
 * @param[in] operation_mode - The operation mode : MD5 or SHA1.
 *
 * @return CRYSError_t on success the function returns CRYS_OK else non ZERO error.
 *
 */
CEXPORT_C CRYSError_t CRYS_HASH_Init(CRYS_HASHUserContext_t *ContextID_ptr,
                                     CRYS_HASH_OperationMode_t operation_mode)
{
    hi_s32 ret;
    hash_user_context *hash_context = HI_NULL;

    if (ContextID_ptr == DX_NULL) {
        return CRYS_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    if (operation_mode >= CRYS_HASH_NumOfModes) {
        return CRYS_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }

    hash_context = (hash_user_context *)ContextID_ptr;
    ret = memset_s(hash_context, sizeof(hash_user_context), 0, sizeof(hash_user_context));
    if (ret != 0) {
        hi_log_print_func_err(memset_s, ret);
        return ret;
    }

    switch (operation_mode) {
        case CRYS_HASH_SHA1_mode:
            ret = kapi_hash_start(&hash_context->ctx.hash, HI_CIPHER_HASH_TYPE_SHA1, HI_NULL, 0);
            break;
        case CRYS_HASH_SHA224_mode:
            ret = kapi_hash_start(&hash_context->ctx.hash, HI_CIPHER_HASH_TYPE_SHA224, HI_NULL, 0);
            break;
        case CRYS_HASH_SHA256_mode:
            ret = kapi_hash_start(&hash_context->ctx.hash, HI_CIPHER_HASH_TYPE_SHA256, HI_NULL, 0);
            break;
        case CRYS_HASH_SHA384_mode:
            ret = kapi_hash_start(&hash_context->ctx.hash, HI_CIPHER_HASH_TYPE_SHA384, HI_NULL, 0);
            break;
        case CRYS_HASH_SHA512_mode:
            ret = kapi_hash_start(&hash_context->ctx.hash, HI_CIPHER_HASH_TYPE_SHA512, HI_NULL, 0);
            break;
        default:
            return CRYS_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }
    hash_context->operation_mode = operation_mode;

    return DX_CRYS_RETURN_ERROR(ret, 0, adaptor_to_crys_hash_err);
}

/**
 * This function process a block of data via the HASH Hardware.
 * The function receives as input an handle to the  HASH Context , that was initialized before
 * by an CRYS_HASH_Init function or by other CRYS_HASH_Update
 * function. The function Sets the hardware with the last H's
 * value that where stored in the CRYS HASH context and then
 * process the data block using the hardware and in the end of
 * the process stores in the HASH context the H's value HASH
 * Context with the cryptographic attributes that are needed for
 * the HASH block operation (initialize H's value for the HASH
 * algorithm). This function is used in cases not all the data
 * is arrange in one continues buffer.
 *
 * The function flow:
 *
 * 1) checking the parameters validty if there is an error the function shall exit with an error code.
 * 2) Aquiring the working context from the CCM manager.
 * 3) If there isnt enouth data in the previous update data buff in the context plus the received data
 *    load it to the context buffer and exit the function.
 * 4) fill the previous update data buffer to contain an entire block.
 * 5) Calling the hardware low level function to execute the update.
 * 6) fill the previous update data buffer with the data not processed at the end of the received data.
 * 7) release the CCM context.
 *
 * @param[in] ContextID_ptr - a pointer to the HASH context buffer allocated by the user that
 *                       is used for the HASH machine operation.
 *
 * @param DataIn_ptr a pointer to the buffer that stores the data to be
 *                       hashed .
 *
 * @param DataInSize  The size of the data to be hashed in bytes.
 *
 * @return CRYSError_t on success the function returns CRYS_OK else non ZERO error.
 *
 */
CEXPORT_C CRYSError_t CRYS_HASH_Update(CRYS_HASHUserContext_t *ContextID_ptr,
                                       DxUint8_t *DataIn_ptr,
                                       DxUint32_t DataInSize)
{
    hi_s32 ret;
    hash_user_context *hash_context = NULL;

    /* if the users context ID pointer is DX_NULL return an error */
    if (ContextID_ptr == DX_NULL) {
        return CRYS_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the users Data In pointer is illegal and the size is not 0 return an error */
    if ((DataIn_ptr == DX_NULL) && DataInSize) {
        return CRYS_HASH_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* if the data size is zero no need to execute an update , return CRYS_OK */
    if (DataInSize == 0) {
        return CRYS_OK;
    }

    hash_context = (hash_user_context *)ContextID_ptr;
    if (CRYS_HASH_SHA512_mode < hash_context->operation_mode) {
        hi_log_print_err_code(CRYS_HASH_ILLEGAL_OPERATION_MODE_ERROR);
        return CRYS_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }
    ret = kapi_hash_update(hash_context->ctx.hash,
                           DataIn_ptr, DataInSize, HASH_CHUNCK_SRC_LOCAL);

    return DX_CRYS_RETURN_ERROR(ret, 0, adaptor_to_crys_hash_err);
}

/*
 * This function finalize the hashing process of data block.
 * The function receives as input an handle to the HASH Context , that was initialized before
 * by an CRYS_HASH_Init function or by CRYS_HASH_Update function.
 * The function "adds" an header to the data block as the specific hash standard
 * specifics , then it loads the hardware and reads the final message digest.
 *
 *  the function flow:
 *
 * 1) checking the parameters validty if there is an error the function shall exit with an error code.
 * 2) Calling the hardware low level function to execute the
 *    finish.
 *
 *  @param[in] ContextID_ptr - a pointer to the HASH context buffer allocated by the user that
 *                       is used for the HASH machine operation.
 *
 *  @retval hash_resultBuff a pointer to the target buffer where the
 *                       HASE result stored in the context is loaded to.
 *
 *  @return CRYSError_t on success the function returns CRYS_OK else non ZERO error.
 */
CEXPORT_C CRYSError_t CRYS_HASH_Finish(CRYS_HASHUserContext_t *ContextID_ptr,
                                       CRYS_HASH_Result_t hash_resultBuff)
{
    hi_s32 ret;
    hash_user_context *hash_context = HI_NULL;
    hi_u32 hlen = 0;

    /* if the users context ID pointer is DX_NULL return an error */
    if (ContextID_ptr == DX_NULL) {
        hi_log_error("ContextID_ptr is null\n");;
        return CRYS_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if output hash_resultBuff In pointer is illegal return an error */
    if (hash_resultBuff == DX_NULL) {
        hi_log_error("hash_resultBuff is null\n");;
        return CRYS_HASH_DATA_IN_POINTER_INVALID_ERROR;
    }
    hash_context = (hash_user_context *)ContextID_ptr;
    if (CRYS_HASH_SHA512_mode < hash_context->operation_mode) {
        hi_log_print_err_code(CRYS_HASH_ILLEGAL_OPERATION_MODE_ERROR);
        return CRYS_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }
    ret = kapi_hash_finish(hash_context->ctx.hash,
                           (hi_u8 *)hash_resultBuff, sizeof(CRYS_HASH_Result_t), &hlen);

    hash_context->ctx.hash = HASH_HANDLE_CLOSED_STATUS;

    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(kapi_hash_finish, ret);
        return DX_CRYS_RETURN_ERROR(ret, 0, adaptor_to_crys_hash_err);
    }

    return HI_SUCCESS;
}

/**
 * @brief This function clears the hash context
 *
 * @param[in] ContextID_ptr - a pointer to the HASH context
 *                       buffer allocated by the user that is
 *                       used for the HASH machine operation.
 *                       This should be the same context that
 *                       was used on the previous call of this
 *                       session.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* crys_error.h
 */
CEXPORT_C CRYSError_t CRYS_HASH_Free(CRYS_HASHUserContext_t *ContextID_ptr)
{
    hash_user_context *hash_context = HI_NULL;
    hi_u8 hash_result[CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES];
    hi_u32 hlen = 0;
    hi_s32 ret = HI_FAILURE;

    if (ContextID_ptr == DX_NULL) {
        return CRYS_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* release handle if not release */
    hash_context = (hash_user_context *)ContextID_ptr;

    if (hash_context->ctx.hash != HASH_HANDLE_CLOSED_STATUS) {
        ret = kapi_hash_finish(hash_context->ctx.hash, hash_result, sizeof(hash_result), &hlen);
        if (ret != HI_SUCCESS) {
            return CRYS_FATAL_ERROR;
        }
    }

    ret = memset_s(ContextID_ptr, sizeof(CRYS_HASHUserContext_t), 0, sizeof(CRYS_HASHUserContext_t));
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
 * @param[in] operation_mode - The operation mode : MD5 or SHA1.
 *
 * @param DataIn_ptr a pointer to the buffer that stores the data to be
 *                       hashed .
 *
 * @param DataInSize  The size of the data to be hashed in bytes.
 *
 * @retval hash_resultBuff a pointer to the target buffer where the
 *                      HASE result stored in the context is loaded to.
 *
 * @return CRYSError_t on success the function returns CRYS_OK else non ZERO error.
 *
 */
CEXPORT_C CRYSError_t CRYS_HASH(CRYS_HASH_OperationMode_t operation_mode,
                                DxUint8_t *DataIn_ptr,
                                DxUint32_t DataSize,
                                CRYS_HASH_Result_t hash_resultBuff)
{
    CRYSError_t error;
    CRYS_HASHUserContext_t *user_context = HI_NULL;

    user_context = (CRYS_HASHUserContext_t *)crypto_malloc(sizeof(CRYS_HASHUserContext_t));
    if (user_context == HI_NULL) {
        hi_log_error("CRYS_HMAC hi_tee_drv_hal_malloc failed\n");
        return HI_FAILURE;
    }

    error = CRYS_HASH_Init(user_context, operation_mode);
    if (error != CRYS_OK) {
        goto end;
    }

    error = CRYS_HASH_Update(user_context, DataIn_ptr, DataSize);
    if (error != CRYS_OK) {
        goto end;
    }

    error = CRYS_HASH_Finish(user_context, hash_resultBuff);

end:
    error = CRYS_HASH_Free(user_context);

    crypto_free(user_context);
    user_context = HI_NULL;

    return error;
}
