/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */

#include "dx_sasi_kernel.h"
#include "ssi_hal_plat.h"
#include "ssi_pal_types.h"
#include "dx_reg_base_host.h"
#include "ssi_regs.h"
#include "dx_host.h"
#include "sasi_rnd.h"
#include "sasi_rnd_local.h"
#include "ssi_rng_plat.h"
#include "ssi_pal_mutex.h"
#include "cc_plat.h"
#include "hw_queue.h"
#include "ssi_pal_dma.h"
#include "ssi_pal_mem.h"
#include "ssi_pal_abort.h"
#include "ssi_general_defs.h"

#include "llf_rnd_trng.h"

extern SaSi_PalMutex sasiSymCryptoMutex;

/* ***************  Defines  ****************** */

/* ************************************************************************************* */
/*
 *
 * @brief The function retrievess the TRNG parameters, provided by the User trough NVM,
 *        and sets them into structures given by pointers rndContext_ptr and trngParams_ptr.
 *
 * @author reuvenl (6/26/2012)
 *
 * @param[out] pRndState - The pointer to structure, containing PRNG data and
 *                            parameters.
 * @param[out] pTrngParams - The pointer to structure, containing parameters
 *                            of HW TRNG.
 *
 * @return SaSiError_t - no return value
 */
SaSiError_t RNG_PLAT_SetUserRngParameters(SaSi_RND_State_t *pRndState, SaSi_RND_Params_t *pTrngParams)
{
    SaSiError_t error = SaSi_OK;

    /* FUNCTION LOGIC */

    /* Set the AES key size as max. supported size */
    /* --------------------------------------------- */
    pRndState->KeySizeWords = SASI_AES_KDR_MAX_SIZE_WORDS; /* SUPPORT_256_192_KEY */

    /* Set TRNG parameters         */
    /* ----------------------------- */
#if (SSI_CONFIG_TRNG_MODE == 0 || SSI_CONFIG_TRNG_MODE == 1)
    pTrngParams->TrngMode = SaSi_RND_FE;

    pTrngParams->SubSamplingRatio1 = SSI_CONFIG_SAMPLE_CNT_ROSC_1;
    pTrngParams->SubSamplingRatio2 = SSI_CONFIG_SAMPLE_CNT_ROSC_2;
    pTrngParams->SubSamplingRatio3 = SSI_CONFIG_SAMPLE_CNT_ROSC_3;
    pTrngParams->SubSamplingRatio4 = SSI_CONFIG_SAMPLE_CNT_ROSC_4;

    /* Allowed ROSCs lengths b'0-3. If bit value 1 - appropriate ROSC is allowed. */
    pTrngParams->RoscsAllowed =
        (((pTrngParams->SubSamplingRatio1 > 0) ? 0x1 : 0x0) | ((pTrngParams->SubSamplingRatio2 > 0) ? 0x2 : 0x0) |
         ((pTrngParams->SubSamplingRatio3 > 0) ? 0x4 : 0x0) | ((pTrngParams->SubSamplingRatio4 > 0) ? 0x8 : 0x0));
    pTrngParams->SubSamplingRatio = 0;
#else
    pTrngParams->TrngMode = SaSi_RND_SWEE;

    pTrngParams->SubSamplingRatio1 = SASI_RNG_DEFAULT_SAMPL_RATIO_ON_SWEE_MODE;
    pTrngParams->SubSamplingRatio2 = SASI_RNG_DEFAULT_SAMPL_RATIO_ON_SWEE_MODE;
    pTrngParams->SubSamplingRatio3 = SASI_RNG_DEFAULT_SAMPL_RATIO_ON_SWEE_MODE;
    pTrngParams->SubSamplingRatio4 = SASI_RNG_DEFAULT_SAMPL_RATIO_ON_SWEE_MODE;

    pTrngParams->RoscsAllowed     = SASI_RNG_DEFAULT_ROSCS_ALLOWED_FLAG;
    pTrngParams->SubSamplingRatio = SASI_RNG_DEFAULT_SAMPL_RATIO_ON_SWEE_MODE;
#endif

    return error;

} /* End of RNG_PLAT_SetUserRngParameters */

/* ******************************************************************* */
/* !
 * Copy TRNG source from SRAM to RAM using CC HW descriptors.
 *
 * \param inSramAddr - Input SRAM address of the source buffer, must be word
 * aligned.
 * \param inSize - Size in octets of the source buffer, must be multiple of
 * word.
 * \param outRamAddr - Output RAM address of the destination buffer, must be
 * word aligned.
 *
 * \return 0 if success, else 1.
 *
 *  Note: The AXI bus secure mode for in/out buffers is used: AxiNs = 0.
 */
uint32_t LLF_RND_DescBypass(DxSramAddr_t inSramAddr, uint32_t inSize, uint32_t *outAddr_ptr)
{
    uint32_t error = 0;

    HwDesc_s desc;
    /* Virtual and physical address of allocated temp buffer */
    uint8_t *tmpVirtAddr_ptr;
    SaSi_PalDmaBlockInfo_t tmpBlockInfo;
    uint32_t numOfBlocks = 1;
    SaSi_PalDmaBufferHandle dmaH;

    error = SaSi_PalMutexLock(&sasiSymCryptoMutex, SASI_INFINITE);
    if (error != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }
    /* Allocate contigious buffer for DMA transfer */
    error = SaSi_PalDmaContigBufferAllocate(inSize, &tmpVirtAddr_ptr);
    if (error != 0) {
        goto End;
    }

    numOfBlocks = 1;
    error =
        SaSi_PalDmaBufferMap(tmpVirtAddr_ptr, inSize, SASI_PAL_DMA_DIR_FROM_DEVICE, &numOfBlocks, &tmpBlockInfo, &dmaH);
    if ((error != 0) || (numOfBlocks != 1)) {
        goto End;
    }

    /* Execute BYPASS operation */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_SRAM(&desc, inSramAddr, inSize);
    HW_DESC_SET_DOUT_TYPE(&desc, DMA_DLLI /* outType */, tmpBlockInfo.blockPhysAddr, inSize,
                          QID_TO_AXI_ID(NO_OS_QUEUE_ID), DEFALUT_AXI_SECURITY_MODE /* outAxiNs */);
    HW_DESC_SET_FLOW_MODE(&desc, BYPASS);
    AddHWDescSequence(NO_OS_QUEUE_ID, &desc);

    /* Wait */
    WaitForSequenceCompletionPlat();
    SaSi_PalDmaBufferUnmap(tmpVirtAddr_ptr, inSize, SASI_PAL_DMA_DIR_FROM_DEVICE, numOfBlocks, &tmpBlockInfo, dmaH);

    /* Copy data from temp buffer into RAM output, usung virt. addresses */
    SaSi_PalMemCopy((uint8_t *)outAddr_ptr, tmpVirtAddr_ptr, inSize);

    /* Release the temp buffer */
    error = SaSi_PalDmaContigBufferFree(inSize, tmpVirtAddr_ptr);

End:
    if (SaSi_PalMutexUnlock(&sasiSymCryptoMutex) != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to release mutex\n");
    }

    return error;
}
