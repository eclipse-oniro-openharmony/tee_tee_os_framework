/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SEP_SYM_ADAPTOR_DRIVER_H
#define SEP_SYM_ADAPTOR_DRIVER_H

#include "mlli.h"
#include "ssi_crypto_ctx.h"
#include "dma_buffer.h"

/* *****************************************************************************
 *                MACROS
 * *************************************************************************** */
#define SPAD_GET_MAX_BLOCKS(size) ((size) / SASI_DRV_ALG_MAX_BLOCK_SIZE)
#define SPAD_BLOCKS2BYTES(blocks) ((blocks)*SASI_DRV_ALG_MAX_BLOCK_SIZE)
#define SPAD_BYTES2BLOCKS(bytes)  ((bytes) / SASI_DRV_ALG_MAX_BLOCK_SIZE)

/* *****************************************************************************
 *                TYPE DEFINITIONS
 * *************************************************************************** */

typedef enum SepRangeType {
    SEP_NULL,
    SEP_SRAM,
    SEP_ICACHE,
    SEP_DCACHE,
} SepRangeType_e;

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */

/* !
 * Allocate sym adaptor driver resources
 *
 * \param None
 *
 * \return 0 for success, otherwise failure
 */
int SymDriverAdaptorModuleInit(void);

/* !
 * Release sym adaptor driver resources
 *
 * \param None
 *
 * \return always success
 */
int SymDriverAdaptorModuleTerminate(void);

/* !
 * Initializes the caller context by invoking the symmetric dispatcher driver.
 * The caller context may resides in SRAM or DCACHE SEP areas.
 * This function flow is synchronouse.
 *
 * \param pCtx
 *
 * \return int One of DX_SYM_* error codes defined in ssi_error.h.
 */
int SymDriverAdaptorInit(struct drv_ctx_generic *pCtx);

/* !
 * Process a cryptographic data by invoking the symmetric dispatcher driver.
 * The invoker may request any amount of data aligned to the given algorithm
 * block size. It uses a scratch pad to copy (in cpu mode) the user
 * data from DCACHE/ICACHE to SRAM for processing. This function flow is
 * synchronouse.
 *
 * \param pCtx may resides in SRAM or DCACHE SeP areas
 * \param pDataIn The input data buffer. It may reside in SRAM, DCACHE or ICACHE SeP address range
 * \param pDataOut The output data buffer. It may reside in SRAM or DCACHE SeP address range
 * \param DataSize The data input size in octets
 *
 * \return int One of DX_SYM_* error codes defined in ssi_error.h.
 */
int SymDriverAdaptorProcess(struct drv_ctx_generic *pCtx, void *pDataIn, void *pDataOut, uint32_t DataSize);
/* !
 * Finalizing the cryptographic data by invoking the symmetric dispatcher driver.
 * It calls the `SymDriverDcacheAdaptorFinalize` function for processing by leaving
 * any reminder for the finalize operation.
 *
 * \param pCtx may resides in SRAM or DCACHE SeP areas
 * \param pDataIn The input data buffer. It may reside in SRAM, DCACHE or ICACHE SeP address range
 * \param pDataOut The output data buffer. It may reside in SRAM or DCACHE SeP address range
 * \param DataSize The data input size in octets
 *
 * \return int One of DX_SYM_* error codes defined in ssi_error.h.
 */
int SymDriverAdaptorFinalize(struct drv_ctx_generic *pCtx, void *pDataIn, void *pDataOut, uint32_t DataSize);

#endif /* SEP_SYM_ADAPTOR_DRIVER_H */
