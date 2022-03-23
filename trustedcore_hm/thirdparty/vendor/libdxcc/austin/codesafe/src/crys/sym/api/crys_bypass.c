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
#include "crys_bypass_api.h"
#include "sym_adaptor_driver.h"
#include "dma_buffer.h"
#include "bypass.h"
#include "dx_macros.h"
#include "dx_error.h"
#include "validate_crys_bypass.h"
#include "crys_context_relocation.h"

#ifdef DX_CC_TEE
#define CRYS_BYPASS_BUFF_OF_WORDS (sizeof(struct sep_ctx_generic) / 2 + 3)
#else
#define CRYS_BYPASS_BUFF_OF_WORDS sizeof(struct sep_ctx_generic) / sizeof(uint32_t)
#endif

#define CRYS_BYPASS_BUFF_OF_WORDS_IN_BYTES (CRYS_BYPASS_BUFF_OF_WORDS * sizeof(uint32_t))

/* !
 * Converts Symmetric Adaptor return code to CRYS error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return CRYSError_t one of CRYS_* error codes defined in crys_error.h
 */
static CRYSError_t SymAdaptor2CrysBypassErr(int symRetCode, uint32_t errorInfo)
{
    errorInfo = errorInfo;
    switch (symRetCode) {
    case DX_RET_UNSUPP_ALG:
    case DX_RET_UNSUPP_ALG_MODE:
        return CRYS_BYPASS_IS_NOT_SUPPORTED;
    case DX_RET_INVARG:
    case DX_RET_INVARG_QID:
    case DX_RET_INVARG_KEY_SIZE:
    case DX_RET_INVARG_CTX_IDX:
    case DX_RET_INVARG_CTX:
        return CRYS_BYPASS_ILLEGAL_PARAMS_ERROR;
    case DX_RET_INVARG_BAD_ADDR:
        return CRYS_BYPASS_INVALID_INPUT_POINTER_ERROR;
    case DX_RET_NOMEM:
        return CRYS_OUT_OF_RESOURCE_ERROR;
    case DX_RET_INVARG_INCONSIST_DMA_TYPE:
        return CRYS_BYPASS_ILLEGAL_MEMORY_AREA_ERROR;
    case DX_RET_UNSUPP_OPERATION:
    case DX_RET_PERM:
    case DX_RET_NOEXEC:
    case DX_RET_BUSY:
    case DX_RET_OSFAULT:
    default:
        return CRYS_FATAL_ERROR;
    }
}

/* !
 * Memory copy using HW engines.
 * The table below describes the supported copy modes that
 * reference by the data input/output buffers:
 *
 *  ----------------------------------------------
 *  |  DataIn_ptr  |         DataOut_ptr         |
 *  |--------------------------------------------|
 *  | SRAM         | DCACHE/SRAM/DLLI/MLLI       |
 *  | ICACHE       | DCACHE/SRAM/DLLI/MLLI       |
 *  | DCACHE       | DCACHE/SRAM/DLLI/MLLI       |
 *  | DLLI         | DCACHE/SRAM/DLLI            |
 *  | MLLI         | DCACHE/SRAM/MLLI            |
 *  ----------------------------------------------
 *
 * \param DataIn_ptr This is the source buffer which need to copy from.
 *          It may be a SeP local address or a DMA Object handle as described
 *          in the table above.
 * \param DataSize In bytes
 * \param DataOut_ptr This is the destination buffer which need to copy to.
 *          It may be a SeP local address or a DMA Object handle as described
 *          in the table above.
 *
 * Restriction: MLLI refers to DMA oject in System memory space.
 *
 * \return CRYSError_t On success CRYS_OK is returned, on failure an error according to
 *                       CRYS_Bypass_error.h
 */
CIMPORT_C CRYSError_t CRYS_Bypass(uint8_t *DataIn_ptr, uint32_t DataSize, uint8_t *DataOut_ptr)
{
    /* The return error identifiers */
    CRYSError_t Error = CRYS_OK;
    int symRc         = DX_RET_OK;

    uint32_t ctxBuff[CRYS_BYPASS_BUFF_OF_WORDS] = { 0x0 };
    /* pointer on SEP AES context struct */
    struct sep_ctx_generic *pSepContext =
        (struct sep_ctx_generic *)DX_InitUserCtxLocation(ctxBuff, sizeof(ctxBuff), sizeof(struct sep_ctx_generic));
    if (pSepContext == DX_NULL) {
        return CRYS_BYPASS_ILLEGAL_PARAMS_ERROR;
    }

    /* data size must be a positive number and a block size mult */
    if (DataSize == 0)
        return DX_SUCCESS;

    /* if the users Data In pointer is illegal return an error */
    if (DataIn_ptr == DX_NULL)
        return CRYS_BYPASS_INVALID_INPUT_POINTER_ERROR;

    /* if the users Data Out pointer is illegal return an error */
    if (DataOut_ptr == DX_NULL)
        return CRYS_BYPASS_INVALID_OUTPUT_POINTER_ERROR;

    Error = validateParams(DataIn_ptr, DataSize);
    if (Error != CRYS_OK) {
        return Error;
    }

    Error = validateParams(DataOut_ptr, DataSize);
    if (Error != CRYS_OK) {
        return Error;
    }

    pSepContext->alg = SEP_CRYPTO_ALG_BYPASS;
    symRc            = SymDriverAdaptorProcess(pSepContext, DataIn_ptr, DataOut_ptr, DataSize);

    return DX_CRYS_RETURN_ERROR(symRc, 0, SymAdaptor2CrysBypassErr);
}
