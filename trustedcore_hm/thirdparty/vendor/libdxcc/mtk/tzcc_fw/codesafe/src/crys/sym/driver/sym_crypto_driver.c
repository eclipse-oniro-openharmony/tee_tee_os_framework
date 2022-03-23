/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_SaSi_SYM_DRIVER
#define ZERO_BLOCK_DEFINED

#include "ssi_pal_types.h"
#include "cc_plat.h"
#include "sym_crypto_driver.h"
#include "ssi_error.h"
#include "hw_queue.h"
#include "ssi_crypto_ctx.h"
#include "cipher.h"
#include "aead.h"
#include "hash.h"
#include "hmac.h"
#include "bypass.h"
#include "inttypes.h"

SASI_PAL_COMPILER_ASSERT(sizeof(enum drv_engine_type) == sizeof(uint32_t), "drv_engine_type is not 32bit!");
SASI_PAL_COMPILER_ASSERT(sizeof(enum ssi_drv_crypto_alg) == sizeof(uint32_t), "ssi_drv_crypto_alg is not 32bit!");
SASI_PAL_COMPILER_ASSERT(sizeof(enum sep_crypto_direction) == sizeof(uint32_t), "sep_crypto_direction is not 32bit!");
SASI_PAL_COMPILER_ASSERT(sizeof(enum drv_crypto_key_type) == sizeof(uint32_t), "drv_crypto_key_type is not 32bit!");

/* A buffer with 0s for algorithms which require using 0 valued block */
const uint32_t ZeroBlock[SEP_AES_BLOCK_SIZE_WORDS] SASI_SRAM_CONST;

/* *****************************************************************************
 *                FUNCTIONS
 * *************************************************************************** */

typedef int (*InitFunc_t)(DxSramAddr_t ctxAddr);
typedef int (*ProcessFunc_t)(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);
typedef int (*FinalizeFunc_t)(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

typedef struct FunctionDispatch_t {
    InitFunc_t initFunc;
    ProcessFunc_t processFunc;
    FinalizeFunc_t finalizeFunc;
} FunctionDispatch;

#define ALG_FUNCS(init, process, finalize) { (InitFunc_t)init, (ProcessFunc_t)process, (FinalizeFunc_t)finalize },

const FunctionDispatch gFuncDispatchList[DRV_CRYPTO_ALG_NUM] SASI_SRAM_CONST = {
#if ENABLE_AES_DRIVER
    ALG_FUNCS(InitCipher, ProcessCipher, FinalizeCipher)
#else
    { NULL, NULL, NULL },
#endif
#if ENABLE_DES_DRIVER
        ALG_FUNCS(InitCipher, ProcessCipher, FinalizeCipher)
#else
    { NULL, NULL, NULL },
#endif
#if ENABLE_HASH_DRIVER
            ALG_FUNCS(InitHash, ProcessHash, FinalizeHash)
#else
    { NULL, NULL, NULL },
#endif
#if ENABLE_C2_DRIVER
                ALG_FUNCS(InitC2, ProcessC2, FinalizeC2)
#else
    { NULL, NULL, NULL },
#endif
#if ENABLE_HMAC_DRIVER
                    ALG_FUNCS(InitHmac, ProcessHash, FinalizeHmac)
#else
    { NULL, NULL, NULL },
#endif
#if ENABLE_AEAD_DRIVER
                        ALG_FUNCS(InitAead, ProcessAead, FinalizeAead)
#else
    { NULL, NULL, NULL },
#endif
#if ENABLE_BYPASS_DRIVER
                            ALG_FUNCS(NULL, ProcessBypass, NULL)
#else
    { NULL, NULL, NULL },
#endif
};

/* !
 * Initializes sym. driver resources.
 *
 * \return int One of DX_SYM_* error codes defined in head of file.
 */
int SymDriverInit(void)
{
    return SASI_RET_OK;
}

/* !
 * Delete sym. driver resources.
 *
 * \return int One of DX_SYM_* error codes defined in head of file.
 */
int SymDriverFini(void)
{
    return SASI_RET_OK;
}

/* !
 * This function is called from the SW queue manager which passes the
 * related context. The function casts the context buffer and diverts
 * to the specific SaSi Init API according to the cipher algorithm that
 * associated in the given context. It is also prepare the necessary
 * firmware private context parameters that are require for the crypto
 * operation, for example, computation of the AES-MAC k1, k2, k3 values.
 * The API has no affect on the user data buffers.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 *
 * \return int One of DX_SYM_* error codes defined in head of file.
 */
int SymDriverDispatchInit(DxSramAddr_t ctxAddr)
{
    const DxSramAddr_t algAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_generic, alg);
    int retcode;
    uint32_t alg;

    SASI_PAL_LOG_INFO("qid=%d pCtx=%08X\n", CURR_QUEUE_ID(), ctxAddr);

    alg = ReadContextWord(algAddr);
    if (gFuncDispatchList[alg].initFunc == NULL) {
        SASI_PAL_LOG_ERR("Unsupported alg %d\n", alg);
        return SASI_RET_UNSUPP_ALG;
    }

    HW_QUEUE_LOCK();

    retcode = (gFuncDispatchList[alg].initFunc)(ctxAddr);

    HW_QUEUE_UNLOCK();

    return retcode;
}

/* !
 * This function is called from the SW queue manager in order to process
 * a symmetric crypto operation on the user data buffers.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in head of file.
 */
int SymDriverDispatchProcess(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer)
{
    const DxSramAddr_t algAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_generic, alg);
    int retcode;
    uint32_t alg;

    SASI_PAL_LOG_INFO("qid=%d pCtx=%08X\n", CURR_QUEUE_ID(), ctxAddr);

    SASI_PAL_LOG_INFO("pDmaInputBuffer: pData=%" PRIx64 " DataSize=%08X DmaMode=%08X \n", pDmaInputBuffer->pData,
                      pDmaInputBuffer->size, pDmaInputBuffer->dmaBufType);

    SASI_PAL_LOG_INFO("pDmaOutputBuffer: pData=%" PRIx64 " DataSize=%08X DmaMode=%08X\n", pDmaOutputBuffer->pData,
                      pDmaOutputBuffer->size, pDmaOutputBuffer->dmaBufType);

    alg = ReadContextWord(algAddr);
    if (gFuncDispatchList[alg].processFunc == NULL) {
        SASI_PAL_LOG_ERR("Unsupported alg %d\n", alg);
        return SASI_RET_UNSUPP_ALG;
    }

    HW_QUEUE_LOCK();

    retcode = (gFuncDispatchList[alg].processFunc)(ctxAddr, pDmaInputBuffer, pDmaOutputBuffer);

    HW_QUEUE_UNLOCK();

    return retcode;
}

/* !
 * This function is called from the SW queue manager in order to complete
 * a crypto operation. The SW queue manager calls this API when the
 * "Process" bit "0x2" is set in the SW descriptor header. This function
 * may be invoked after "DispatchDriverProcess" or "DispatchDriverInit" with any
 * number of IN/OUT MLLI tables.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in head of file.
 */
int SymDriverDispatchFinalize(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer)
{
    const DxSramAddr_t algAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_generic, alg);
    int retcode;
    uint32_t alg;

    SASI_PAL_LOG_INFO("qid=%d pCtx=%08X\n", CURR_QUEUE_ID(), ctxAddr);

    SASI_PAL_LOG_INFO("pDmaInputBuffer: pData=%" PRIx64 " DataSize=%08X DmaMode=%08X\n", pDmaInputBuffer->pData,
                      pDmaInputBuffer->size, pDmaInputBuffer->dmaBufType);

    SASI_PAL_LOG_INFO("pDmaOutputBuffer: pData=%" PRIx64 " DataSize=%08X DmaMode=%08X\n", pDmaOutputBuffer->pData,
                      pDmaOutputBuffer->size, pDmaOutputBuffer->dmaBufType);

    alg = ReadContextWord(algAddr);
    if (gFuncDispatchList[alg].finalizeFunc == NULL) {
        SASI_PAL_LOG_ERR("Unsupported alg %d\n", alg);
        return SASI_RET_UNSUPP_ALG;
    }

    HW_QUEUE_LOCK();

    retcode = (gFuncDispatchList[alg].finalizeFunc)(ctxAddr, pDmaInputBuffer, pDmaOutputBuffer);

    HW_QUEUE_UNLOCK();

    return retcode;
}
