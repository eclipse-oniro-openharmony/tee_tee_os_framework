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

#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_CRYS_API

#include "dx_pal_types.h"
#include "dx_pal_mem.h"
#include "sym_adaptor_driver.h"
#include "crys_rc4_error.h"
#include "crys_rc4.h"
#include "cc_acl.h"
#include "rc4.h"
#include "dx_error.h"
#include "crys_context_relocation.h"

/* !
 * Converts Symmetric Adaptor return code to CRYS error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return CRYSError_t one of CRYS_* error codes defined in crys_error.h
 */
static CRYSError_t SymAdaptor2CrysRc4Err(int symRetCode, uint32_t errorInfo)
{
    switch (symRetCode) {
    case DX_RET_UNSUPP_ALG:
        return CRYS_RC4_IS_NOT_SUPPORTED;
    case DX_RET_UNSUPP_ALG_MODE:
    case DX_RET_UNSUPP_OPERATION:
    case DX_RET_INVARG:
    case DX_RET_INVARG_QID:
        return CRYS_RC4_ILLEGAL_PARAMS_ERROR;
    case DX_RET_INVARG_KEY_SIZE:
        return CRYS_RC4_ILLEGAL_KEY_SIZE_ERROR;
    case DX_RET_INVARG_CTX_IDX:
        return CRYS_RC4_INVALID_USER_CONTEXT_POINTER_ERROR;
    case DX_RET_INVARG_CTX:
        return CRYS_RC4_USER_CONTEXT_CORRUPTED_ERROR;
    case DX_RET_INVARG_BAD_ADDR:
        return CRYS_RC4_DATA_IN_POINTER_INVALID_ERROR;
    case DX_RET_NOMEM:
        return CRYS_OUT_OF_RESOURCE_ERROR;
    case DX_RET_INVARG_INCONSIST_DMA_TYPE:
        return CRYS_ILLEGAL_RESOURCE_VAL_ERROR;
    case DX_RET_PERM:
    case DX_RET_NOEXEC:
    case DX_RET_BUSY:
    case DX_RET_OSFAULT:
    default:
        return CRYS_FATAL_ERROR;
    }
}

/*
 * @brief This function is used to initialize the RC4 machine.
 *        To operate the RC4 machine, this should be the first function called.
 *
 * @param[in] ContextID_ptr - A pointer to the RC4 context buffer that is allocated by the user
 *                       and is used for the RC4 machine operation.
 * @param[in] Key_ptr -  A pointer to the user's key buffer.
 * @param[in] KeySize - The size of the KEY in bytes. Requirements:
 *             - for SW implementation    0 < KeySize < CRYS_RC4_MAX_KEY_SIZE_IN_BYTES,
 *             - for HW implementation    LLF_RC4_MIN_KEY_SIZE_IN_BYTES  < KeySize < LLF_RC4_MAX_KEY_SIZE_IN_BYTES,
 *
 * @return CRYSError_t - CRYS_OK,
 *                       CRYS_RC4_INVALID_USER_CONTEXT_POINTER_ERROR,
 *                       CRYS_RC4_ILLEGAL_KEY_SIZE_ERROR,
 *                       CRYS_RC4_INVALID_KEY_POINTER_ERROR
 */
CIMPORT_C CRYSError_t CRYS_RC4_Init(CRYS_RC4UserContext_t *ContextID_ptr, uint8_t *Key_ptr, uint32_t KeySizeInBytes)
{
    int symRc = DX_RET_OK;

    /* pointer on SEP RC4 context struct */
    struct sep_ctx_rc4 *pRc4Context;
    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context ID pointer is DX_NULL return an error */
    if (ContextID_ptr == DX_NULL) {
        return CRYS_RC4_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* If the Keys size is invalid return an error */
    if ((KeySizeInBytes == 0) || (KeySizeInBytes > CRYS_RC4_MAX_KEY_SIZE_IN_BYTES)) {
        return CRYS_RC4_ILLEGAL_KEY_SIZE_ERROR;
    }

    /* If the the key pointer is not validity */
    if (Key_ptr == DX_NULL) {
        return CRYS_RC4_INVALID_KEY_POINTER_ERROR;
    }

    /* check validity for priv */
    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ, Key_ptr, KeySizeInBytes) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, ContextID_ptr, sizeof(CRYS_RC4UserContext_t))) {
        return CRYS_RC4_ILLEGAL_PARAMS_ERROR;
    }

    /* Get pointer within the buffer that can accomodate context without
       crossing a page */
    pRc4Context = (struct sep_ctx_rc4 *)DX_InitUserCtxLocation(ContextID_ptr->buff, sizeof(CRYS_RC4UserContext_t),
                                                               sizeof(struct sep_ctx_rc4));

    if (pRc4Context == DX_NULL) {
        return CRYS_RC4_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    pRc4Context->alg      = SEP_CRYPTO_ALG_RC4;
    pRc4Context->key_size = KeySizeInBytes;

    DX_PAL_MemCopy(pRc4Context->key, Key_ptr, KeySizeInBytes);

    /* ................. calling the low level init function ................. */
    /* ----------------------------------------------------------------------- */

    symRc = SymDriverAdaptorInit((struct sep_ctx_generic *)pRc4Context);
    return DX_CRYS_RETURN_ERROR(symRc, 0, SymAdaptor2CrysRc4Err);
}

/*
 * @brief This function is used to process a stream on the RC4 machine.
 *        This function should be called after the CRYS_RS4_Init.
 *
 *
 * @param[in] ContextID_ptr - A pointer to the RC4 context buffer allocated by the user
 *                       that is used for the RC4 machine operation. This should be the
 *                       same context as was used for the previous call of this session.
 *
 * @param[in] DataIn_ptr - The pointer to the buffer of the input data to the RC4.
 *                   The pointer's value does not need to be word-aligned.
 *
 * @param[in] DataInSize - The size of the input data.
 *
 * @param[in,out] DataOut_ptr - The pointer to the buffer of the output data from the RC4.
 *                        The pointer's value does not need to be word-aligned.
 *
 * @return CRYSError_t - CRYS_OK,
 *                       CRYS_RC4_INVALID_USER_CONTEXT_POINTER_ERROR,
 *                       CRYS_RC4_ILLEGAL_KEY_SIZE_ERROR,
 *                       CRYS_RC4_INVALID_KEY_POINTER_ERROR
 */
CIMPORT_C CRYSError_t CRYS_RC4_Stream(CRYS_RC4UserContext_t *ContextID_ptr, uint8_t *DataIn_ptr, uint32_t DataInSize,
                                      uint8_t *DataOut_ptr)
{
    int symRc = DX_RET_OK;

    /* pointer on SEP RC4 context struct */
    struct sep_ctx_rc4 *pRc4Context;
    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if no data to process -we're done */
    if (DataInSize == 0) {
        return CRYS_OK;
    }

    /* if the users context ID pointer is DX_NULL return an error */
    if (ContextID_ptr == DX_NULL) {
        return CRYS_RC4_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the users Data In pointer is illegal return an error */
    if (DataIn_ptr == DX_NULL) {
        return CRYS_RC4_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* if the users Data Out pointer is illegal return an error */
    if (DataOut_ptr == DX_NULL) {
        return CRYS_RC4_DATA_OUT_POINTER_INVALID_ERROR;
    }

    /* data size must be a positive number */
    if (DataInSize == 0) {
        return CRYS_RC4_DATA_SIZE_ILLEGAL;
    }

    /* check validity for priv */
    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, ContextID_ptr, sizeof(CRYS_RC4UserContext_t))) {
        return CRYS_RC4_ILLEGAL_PARAMS_ERROR;
    }

    pRc4Context = (struct sep_ctx_rc4 *)DX_GetUserCtxLocation(ContextID_ptr->buff, sizeof(CRYS_RC4UserContext_t));
    if (pRc4Context == NULL)
        return CRYS_RC4_ILLEGAL_PARAMS_ERROR;

    symRc = SymDriverAdaptorProcess((struct sep_ctx_generic *)pRc4Context, DataIn_ptr, DataOut_ptr, DataInSize);

    return DX_CRYS_RETURN_ERROR(symRc, 0, SymAdaptor2CrysRc4Err);
}

/* ********************************************************************************************* */
/*
 * @brief This function is used to end the RC4 processing session.
 *        It is the last function called for the RC4 process.
 *
 *
 * @param[in] ContextID_ptr - A pointer to the RC4 context buffer allocated by the user that
 *                       is used for the RC4 machine operation. This should be the
 *                       same context as was used for the previous call of this session.
 *
 *
 * @return CRYSError_t - CRYS_OK,
 *                       CRYS_RC4_INVALID_USER_CONTEXT_POINTER_ERROR,
 */
CIMPORT_C CRYSError_t CRYS_RC4_Free(CRYS_RC4UserContext_t *ContextID_ptr)
{
    /* The return error identifiers */
    CRYSError_t Error = CRYS_OK;

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context ID pointer is DX_NULL return an error */
    if (ContextID_ptr == DX_NULL) {
        return CRYS_RC4_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* check validity for priv */
    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, ContextID_ptr, sizeof(CRYS_RC4UserContext_t))) {
        return CRYS_RC4_ILLEGAL_PARAMS_ERROR;
    }

    /* .............. clearing the users context .......................... */
    /* -------------------------------------------------------------------- */

    DX_PAL_MemSetZero(ContextID_ptr, sizeof(CRYS_RC4UserContext_t));

    return Error;
}

/*
 * @brief This function provides a RC4 function for processing
 *        data.
 *
 * The function allocates an internal RC4 Context, and initializes the RC4 Context with the
 * cryptographic attributes that are needed for the RC4 cryptographic operation. Next the
 * function loads the engine with the initializing values, and then processes the data,
 * returning the processed data in the output buffer. Finally, the function frees the
 * internally allocated context.
 *
 * @param[in] Key_ptr -  A pointer to the user's key buffer.
 *
 * @param[in] KeySize - The size of the KEY in bytes.
 *
 * @param[in] DataIn_ptr - The pointer to the buffer of the input data to the RC4.
 *                   The pointer's value does not need to be word-aligned.
 *
 * @param[in] DataInSize - The size of the input data.
 *
 * @param[in,out] The pointer to the buffer of the output data from the RC4.
 *                The pointer's value does not need to be word-aligned. The size of this buffer
 *                must be the same as the DataIn buffer.
 *
 * @return CRYSError_t -  CRYS_OK,
 *                        CRYS_RC4_INVALID_USER_CONTEXT_POINTER_ERROR,
 *                        CRYS_RC4_USER_CONTEXT_CORRUPTED_ERROR
 *
 */
CIMPORT_C CRYSError_t CRYS_RC4(uint8_t *Key_ptr, uint32_t KeySizeInBytes, uint8_t *DataIn_ptr, uint32_t DataInSize,
                               uint8_t *DataOut_ptr)
{
    /* a users context used to pass to all of the CRYS functions */
    CRYS_RC4UserContext_t ContextID;

    /* The return error identifier */
    CRYSError_t Error = CRYS_OK;

    /* if no data to process -we're done */
    if (DataInSize == 0) {
        return CRYS_OK;
    }

    /* ............... calling the CRYS init function ...................... */
    /* --------------------------------------------------------------------- */
    Error = CRYS_RC4_Init(&ContextID, Key_ptr, KeySizeInBytes);

    if (Error != CRYS_OK) {
        return Error;
    }

    /* ............... calling the CRYS Stream function .................... */
    /* --------------------------------------------------------------------- */

    Error = CRYS_RC4_Stream(&ContextID, DataIn_ptr, DataInSize, DataOut_ptr);

    if (Error != CRYS_OK) {
        return Error;
    }

    /* ................. end of function ..................................... */
    /* ----------------------------------------------------------------------- */

    /* call the free function - release the users context */
    Error = CRYS_RC4_Free(&ContextID);

    return Error;
}
