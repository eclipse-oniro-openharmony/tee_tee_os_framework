/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/




/************* Include Files ****************/

#include "dx_crys_kernel.h"
#include "cc_hal_plat.h"
#include "cc_pal_types.h"
#include "dx_reg_base_host.h"
#include "cc_regs.h"
#include "dx_host.h"
#include "cc_rnd.h"
#include "cc_rnd_local.h"
#include "cc_rng_plat.h"
#include "cc_pal_mutex.h"
#include "cc_plat.h"
#include "hw_queue.h"
#include "cc_pal_dma.h"
#include "cc_pal_mem.h"
#include "cc_pal_abort.h"
#include "cc_general_defs.h"

#include "llf_rnd_trng.h"

extern CC_PalMutex CCSymCryptoMutex;

/****************  Defines  ********************/


/****************************************************************************************/
/**
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
 * @return CCError_t - no return value
 */
CCError_t RNG_PLAT_SetUserRngParameters(
        CCRndState_t *pRndState,
        CCRndParams_t  *pTrngParams)
{
        CCError_t  error = CC_OK;

        /* FUNCTION LOGIC */

        /* Set the AES key size as max. supported size */
        /*---------------------------------------------*/
        pRndState->KeySizeWords = CC_AES_KDR_MAX_SIZE_WORDS; /*SUPPORT_256_192_KEY*/

        /* Set TRNG parameters         */
        /*-----------------------------*/
#if (CC_CONFIG_TRNG_MODE==0 || CC_CONFIG_TRNG_MODE==1)
        pTrngParams->TrngMode = CC_RND_FE;

        pTrngParams->SubSamplingRatio1 = CC_CONFIG_SAMPLE_CNT_ROSC_1;
        pTrngParams->SubSamplingRatio2 = CC_CONFIG_SAMPLE_CNT_ROSC_2;
        pTrngParams->SubSamplingRatio3 = CC_CONFIG_SAMPLE_CNT_ROSC_3;
        pTrngParams->SubSamplingRatio4 = CC_CONFIG_SAMPLE_CNT_ROSC_4;

        /* Allowed ROSCs lengths b'0-3. If bit value 1 - appropriate ROSC is allowed. */
        pTrngParams->RoscsAllowed = (((pTrngParams->SubSamplingRatio1 > 0) ? 0x1 : 0x0) |
                ((pTrngParams->SubSamplingRatio2 > 0) ? 0x2 : 0x0) |
                ((pTrngParams->SubSamplingRatio3 > 0) ? 0x4 : 0x0) |
                ((pTrngParams->SubSamplingRatio4 > 0) ? 0x8 : 0x0));
        pTrngParams->SubSamplingRatio = 0;
#else
        pTrngParams->TrngMode = CC_RND_SWEE;

        pTrngParams->SubSamplingRatio1 = CC_RNG_DEFAULT_SAMPL_RATIO_ON_SWEE_MODE;
        pTrngParams->SubSamplingRatio2 = CC_RNG_DEFAULT_SAMPL_RATIO_ON_SWEE_MODE;
        pTrngParams->SubSamplingRatio3 = CC_RNG_DEFAULT_SAMPL_RATIO_ON_SWEE_MODE;
        pTrngParams->SubSamplingRatio4 = CC_RNG_DEFAULT_SAMPL_RATIO_ON_SWEE_MODE;

        pTrngParams->RoscsAllowed = CC_RNG_DEFAULT_ROSCS_ALLOWED_FLAG;
        pTrngParams->SubSamplingRatio = CC_RNG_DEFAULT_SAMPL_RATIO_ON_SWEE_MODE;
#endif

        return error;

} /* End of RNG_PLAT_SetUserRngParameters */

/**********************************************************************/
/*!
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
uint32_t LLF_RND_DescBypass(CCSramAddr_t  inSramAddr, uint32_t inSize, uint32_t *outAddr_ptr)
{
        uint32_t error = 0;

        HwDesc_s desc;
        /* Virtual and physical address of allocated temp buffer */
        uint8_t *tmpVirtAddr_ptr;
        CCPalDmaBlockInfo_t  tmpBlockInfo;
        uint32_t  numOfBlocks = 1;
        CC_PalDmaBufferHandle dmaH;

        error = CC_PalMutexLock(&CCSymCryptoMutex, CC_INFINITE);
        if (error != CC_SUCCESS) {
                CC_PalAbort("Fail to acquire mutex\n");
        }
        /* Allocate contigious buffer for DMA transfer */
        error = CC_PalDmaContigBufferAllocate(inSize,
                                               &tmpVirtAddr_ptr);
        if (error != 0) {
                goto End;
        }

        numOfBlocks = 1;
        error = CC_PalDmaBufferMap(tmpVirtAddr_ptr,
                                    inSize,
                                    CC_PAL_DMA_DIR_FROM_DEVICE,
                                    &numOfBlocks,
                                    &tmpBlockInfo,
                                    &dmaH);
        if ((error != 0) || (numOfBlocks != 1)) {
                goto End;
        }

        /* Execute BYPASS operation */
        HW_DESC_INIT(&desc);
        HW_DESC_SET_DIN_SRAM(&desc, inSramAddr, inSize);
        HW_DESC_SET_DOUT_TYPE(&desc, DMA_DLLI/*outType*/, tmpBlockInfo.blockPhysAddr,
                              inSize, DEFALUT_AXI_SECURITY_MODE/*outAxiNs*/);
        HW_DESC_SET_FLOW_MODE(&desc, BYPASS);
        AddHWDescSequence(&desc);

        /* Wait */
        WaitForSequenceCompletionPlat();
        CC_PalDmaBufferUnmap(tmpVirtAddr_ptr,
                              inSize,
                              CC_PAL_DMA_DIR_FROM_DEVICE,
                              numOfBlocks,
                              &tmpBlockInfo,
                              dmaH);

        /* Copy data from temp buffer into RAM output, usung virt. addresses */
        CC_PalMemCopy((uint8_t*)outAddr_ptr, tmpVirtAddr_ptr, inSize);

        /* Release the temp buffer */
        error = CC_PalDmaContigBufferFree(inSize,
                                           tmpVirtAddr_ptr);

        End:
        if (CC_PalMutexUnlock(&CCSymCryptoMutex) != CC_SUCCESS) {
                CC_PalAbort("Fail to release mutex\n");
        }

        return error;
}



