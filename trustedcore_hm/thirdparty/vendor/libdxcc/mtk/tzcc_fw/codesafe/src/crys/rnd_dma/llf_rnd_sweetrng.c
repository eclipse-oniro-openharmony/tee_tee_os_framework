/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include "dx_rng.h"
#include "ssi_pal_mem.h"
#include "ssi_rng_plat.h"
#include "dx_sasi_kernel.h"
#include "ssi_hal.h"
#include "ssi_regs.h"
#include "dx_host.h"
#include "sasi_rnd_local.h"
#include "sasi_rnd_error.h"
#include "llf_rnd_hwdefs.h"
#include "llf_rnd.h"
#include "llf_rnd_error.h"
#include "ssi_sram_map.h"
#include "cc_plat.h"
#include "llf_rnd_trng.h"
#include "mtk_trng_dx.h"

/* macro for calculation max. allowed time for */
#define LLF_RND_CalcMaxTrngTime(ehrSamples, SubSamplingRatio)                                                        \
    (((ehrSamples)*LLF_RND_TRNG_MAX_TIME_COEFF * LLF_RND_TRNG_VON_NEUMAN_COEFF * LLF_RND_HW_TRNG_EHR_WIDTH_IN_BITS * \
      (SubSamplingRatio)) >>                                                                                         \
     LLF_RND_TRNG_MAX_TIME_SCALE)
#define ROSC_INIT_START_BIT 0x80000000

/* ********************************** Enums **************************** */
/* ********************************Typedefs **************************** */

/* *************** Global Data to be read by RNG function ************** */

/* test variables */
#ifdef RND_TEST_TRNG_WITH_ESTIMATOR
uint32_t gEntrSize[4];
#endif

extern uint32_t LLF_RND_DescBypass(DxSramAddr_t inSramAddr, uint32_t inSize, uint32_t *outAddr_ptr);

/* ********************************************************************************* */
/*
 * The function checks that parameters, loaded in the TRNG HW
 * are match to parameters, required by trngParams_ptr structures.
 *
 * @author reuvenl (6/25/2012)
 *
 * @param trngParams_ptr
 *
 * @return SaSiError_t
 */
static SaSiError_t LLF_RND_TRNG_CheckHwParams(SaSi_RND_Params_t *trngParams_ptr)
{
    uint32_t temp;
    SaSiBool_t isTrue = SASI_TRUE;

    /* check Debug control - masked TRNG tests according to mode */
    temp = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(RNG, TRNG_DEBUG_CONTROL));
    isTrue &= (temp == LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_SWEE_MODE);
    /* check samplesCount */
    temp = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(RNG, SAMPLE_CNT1));
    isTrue &= (temp == trngParams_ptr->SubSamplingRatio);

    /* if any parameters are not match return an Error */
    if (isTrue == SASI_FALSE)
        return LLF_RND_TRNG_PREVIOUS_PARAMS_NOT_MATCH_ERROR;
    else
        return SaSi_OK;
}

/* ************************************************************************************* */
/* ****************************       Public Functions      **************************** */
/* ************************************************************************************* */

SaSiError_t LLF_RND_StartTrngHW(SaSi_RND_State_t *rndState_ptr, SaSi_RND_Params_t *trngParams_ptr, SaSiBool_t isRestart,
                                uint32_t *roscsToStart_ptr, DxSramAddr_t sramAddr)
{
    /* LOCAL DECLARATIONS */

    SaSiError_t error = SaSi_OK;
    uint32_t temp, ehrSamples, tmpSamplCnt = 0;

    /* FUNCTION LOGIC */

    /* Check pointers */
    if ((rndState_ptr == NULL) || (trngParams_ptr == NULL) || (roscsToStart_ptr == NULL))
        return LLF_RND_TRNG_ILLEGAL_PTR_ERROR;

    /* -------------------------------------------------------------- */
    /* 1. If full restart, get semaphore and set initial ROSCs      */
    /* -------------------------------------------------------------- */
    if (isRestart) {
        /* SWEE mode - start all allowed ROSCs */
        *roscsToStart_ptr = 0x0f & trngParams_ptr->RoscsAllowed;

        /* init rndState flags to zero */
        rndState_ptr->TrngProcesState = 0;
    }

    if (*roscsToStart_ptr == 0)
        return LLF_RND_TRNG_REQUIRED_ROSCS_NOT_ALLOWED_ERROR;

    /* -------------------------------------------------------------- */
    /* 2. Restart the TRNG and set  parameters              */
    /* -------------------------------------------------------------- */

    /* enable the HW RND clock   */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_CLK_ENABLE), LLF_RND_HW_RND_CLK_ENABLE_VAL);

    /* do software reset */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_SW_RESET), 0x1);
    /* in order to verify that the reset has completed the sample count need to be verified */
    do {
        /* enable the HW RND clock   */
        SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_CLK_ENABLE), LLF_RND_HW_RND_CLK_ENABLE_VAL);

        /* set sampling ratio (rng_clocks) between consequtive bits */
        SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, SAMPLE_CNT1), trngParams_ptr->SubSamplingRatio);

        /* read the sampling ratio  */
        tmpSamplCnt = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(RNG, SAMPLE_CNT1));

    } while (tmpSamplCnt != trngParams_ptr->SubSamplingRatio);

    /* disable the RND source for setting new parameters in HW */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RND_SOURCE_ENABLE), LLF_RND_HW_RND_SRC_DISABLE_VAL);

    /* set TRNG_CONFIG to choose SOP_SEL = 1 - i.e. EHR output */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, TRNG_CONFIG), LLF_RND_HW_TRNG_WITH_DMA_CONFIG_VAL);

    /* SWEE mode */
    /* Debug Control register: NC_BYPASS + TRNG_CRNGT_BYPASS + AUTO_CORRELATE_BYPASS set to 1   */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, TRNG_DEBUG_CONTROL), LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_SWEE_MODE);

    /* set interrupt mask */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_IMR), LLF_RNG_INT_MASK_ON_SWEETRNG_MODE);
    ehrSamples = LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_SWEE_MODE;

    /* set ROSCS to start and EHR samples from each ROSC to DMA transfer */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_DMA_SRC_MASK), *roscsToStart_ptr);
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_DMA_SAMPLES_NUM), ehrSamples);

    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_DMA_SRAM_ADDR), (uint32_t)sramAddr);

    /* clear RNG interrupts !!TBD */
    temp = 0;
    SASI_REG_FLD_SET(HOST_RGF, HOST_ICR, RNG_INT_CLEAR, temp, 1);
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_ICR), temp);
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_ICR), 0xFFFFFFFF);

    /* enable DMA (automatically enables RNG source) */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_DMA_ENABLE), LLF_RND_HW_RND_DMA_ENABLE_VAL);

    /* set indication about current started ROSCs:  */
    /* new started */
    rndState_ptr->TrngProcesState = (rndState_ptr->TrngProcesState & 0x00ffffff) | (*roscsToStart_ptr << 24);
    /* total started */
    rndState_ptr->TrngProcesState |= (*roscsToStart_ptr << 8);

    /* end  of function */
    return error;
}

SaSiError_t LLF_RND_GetTrngSource(SaSi_RND_State_t *rndState_ptr,    /* in/out */
                                  SaSi_RND_Params_t *trngParams_ptr, /* in/out */
                                  SaSiBool_t isContinued,            /* in */
                                  uint32_t *entropySize_ptr,         /* in/out */
                                  uint32_t **sourceOut_ptr_ptr,      /* out */
                                  uint32_t *sourceOutSize_ptr,       /* in/out */
                                  uint32_t *rndWorkBuff_ptr,         /* in */
                                  bool isFipsSupported)              /* in */
{
    /* LOCAL DECLARATIONS */

    /* The return error identifier */
    SaSiError_t error = 0;

    uint32_t isr;
    uint32_t tmp;
    uint32_t roscToStart, sizeToProcessBytes, prefRoscIndex;
    DxSramAddr_t sramAddr;
    uint32_t *ramAddr;

    SASI_UNUSED_PARAM(isFipsSupported);

    /* FUNCTION LOGIC */

    /* ............... local initializations .............................. */
    /* -------------------------------------------------------------------- */
    /* Set initial value to entropy flag and collectionIndex */
    int32_t entropyFlag        = LLF_RNG_ENTROPY_FLAG_LOW;
    int32_t collectionIndex    = 0;
    uint32_t totalEntropyValue = 0;
    uint32_t totalSourceSize   = 0;
    uint32_t requirEntropy     = 0;

    /* initializing the Error to O.K */
    error = SaSi_OK;

    /* Set source RAM address with offset 8 bytes from sourceOut address in
      order to remain empty bytes for SaSi operations */
    *sourceOut_ptr_ptr = rndWorkBuff_ptr + SaSi_RND_SRC_BUFF_OFFSET_WORDS;
    ramAddr            = *sourceOut_ptr_ptr + SaSi_RND_TRNG_SRC_INNER_OFFSET_WORDS;
    sramAddr           = SASI_SRAM_RND_HW_DMA_ADDRESS;
    /* init to 0 for FE mode */
    *sourceOutSize_ptr = 0;

    /* Case of RND KAT or TRNG KAT testing  */
    if ((rndState_ptr->StateFlag & SaSi_RND_KAT_DRBG_mode) || (rndState_ptr->StateFlag & SaSi_RND_KAT_TRNG_mode)) {
        /* set source sizes given by the user in KAT test and placed
           in the rndWorkBuff with offset SaSi_RND_SRC_BUFF_OFFSET_WORDS */
        *sourceOutSize_ptr = (*sourceOut_ptr_ptr)[0];
        if (*sourceOutSize_ptr == 0) {
            return SaSi_RND_KAT_DATA_PARAMS_ERROR;
        }

        /* Go to Estimator */
        if (rndState_ptr->StateFlag & SaSi_RND_KAT_TRNG_mode) {
            /* Assumed, that KAT data is set in the rnd Work      *
               buffer as follows:                     *
               - full source size set in buffr[0],            *
               - count blocks set in buffr[1],                *
            *  - KAT source begins from buffer[2].            */
            tmp = (*sourceOut_ptr_ptr)[1]; /* count blocks for estimation */
            if (tmp == 0) {
                return SaSi_RND_KAT_DATA_PARAMS_ERROR;
            }
            sizeToProcessBytes = (*sourceOut_ptr_ptr)[0] / tmp; /* one block size */
            goto Estimator;
        } else
            goto End;
    }
    /* If not continued mode, set TRNG parameters and restart TRNG     */
    /* -------------------------------------------------------------- */
    if (isContinued == SASI_FALSE) {
        /* Set instantiation, TRNG errors and time   *
         * exceeding bits of State to 0           */
        rndState_ptr->StateFlag &= ~(SaSi_RND_Instantiated | SaSi_RND_InstantReseedAutocorrErrors |
                                     SaSi_RND_InstantReseedTimeExceed | SaSi_RND_InstantReseedLessEntropy);

        /* Full restart TRNG */
        error = LLF_RND_StartTrngHW(rndState_ptr, trngParams_ptr, SASI_TRUE /* isRestart */, &roscToStart, sramAddr);

        /* Note: in case of error the TRNG HW is still not started */
        if (error)
            goto End;
    }

    /* On continued mode check HW TRNG */
    else {
        /* check TRNG parameters */
        error = LLF_RND_TRNG_CheckHwParams(trngParams_ptr);
        if (error != SaSi_OK)
            goto End;

        /* previously started ROSCs */
        roscToStart = (rndState_ptr->TrngProcesState & 0xff000000) >> 24;
    }

    /* ==================================================== */
    /* ==================================================== */
    /*         Processing after previous start            */
    /* ==================================================== */
    /* ==================================================== */

    /* ========================================================= */
    /* SWEE mode processing (yet started all 4 ROSCs):
       wait interrupt, estimate entropy and output the source  */
    /* ========================================================= */
    /* save entropy */
    requirEntropy = *entropySize_ptr;

    /* Perform collection of bits until required entropy is reached or max number of iteration exceeded */
    while ((entropyFlag == LLF_RNG_ENTROPY_FLAG_LOW) && (collectionIndex < LLF_RNG_MAX_COLLECTION_ITERATION_SIZE)) {
        /* wait and output irr = RNG_ISR */
        LLF_RND_WaitRngInterrupt(&isr);

        /* source size from one rosc and from all started rosc's */
        sizeToProcessBytes = LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_SWEE_MODE * LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES;

        /* calculate count of rosc's started */
        tmp = LLF_RND_GetCountRoscs(trngParams_ptr->RoscsAllowed, roscToStart);

        /* Calculate size of current and total source size */
        *sourceOutSize_ptr = tmp * sizeToProcessBytes;
        totalSourceSize += *sourceOutSize_ptr;

        error = (SaSiError_t)mtk_get_trng((uint8_t *)ramAddr, (uint32_t)(*sourceOutSize_ptr));
        if (error != 0)
            goto End;

#ifdef BIG__ENDIAN
        /* set endianness */
        for (i = 0; i < (*sourceOutSize_ptr) / 4; ++i) {
            ramAddr[i] = SaSi_COMMON_REVERSE32(ramAddr[i]);
        }
#endif

    Estimator:
        if (requirEntropy != 1) { /* the condition need for performance test */

            error = LLF_RND_EntropyEstimateFull(ramAddr,                 /* in */
                                                sizeToProcessBytes >> 2, /* 1 block size, words */
                                                tmp /* count blocks */,    /* in */
                                                entropySize_ptr,         /* out */
                                                rndWorkBuff_ptr);        /* in */
            if (error)
                goto End;
        }
        /* save entropy size for testing */
        totalEntropyValue += *entropySize_ptr;
        rndState_ptr->EntropySizeBits = totalEntropyValue;

        /* if not KAT mode check entropy */
        if (!(rndState_ptr->StateFlag & (SaSi_RND_KAT_DRBG_mode | SaSi_RND_KAT_TRNG_mode))) {
            if (totalEntropyValue == 0) {
                error       = LLF_RND_TRNG_NULL_ENTROPY_ERROR;
                entropyFlag = LLF_RNG_ENTROPY_FLAG_NULL;

            } else if (totalEntropyValue < requirEntropy) {
                entropyFlag = LLF_RNG_ENTROPY_FLAG_LOW;
                /* If enropy was collected from alowed ROSCs(first time) */
                if (collectionIndex == 0) {
                    /* Get index of rosc with best entropy value */
                    prefRoscIndex = LLF_RND_GetPreferableRosc(rndWorkBuff_ptr);

                    /* Update ROSC for next entropy collection */
                    if (prefRoscIndex != 0xf) {
                        roscToStart = 1 << prefRoscIndex;
                    } else {
                        error = LLF_RND_TRNG_GENERATION_NOT_COMPLETED_ERROR; // add relevant error
                        goto End;
                    }
                    /* Update RAM address for next entropy source */
                    ramAddr += (sizeToProcessBytes >> 2) * tmp;
                } else { /* If entropy was collected from chosen ROSC */
                    /* Update RAM address for next entropy source */
                    ramAddr += (LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_SWEE_MODE * LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS);
                }

                /* Start TRNG with updated ROSC */
                error =
                    LLF_RND_StartTrngHW(rndState_ptr, trngParams_ptr, SASI_FALSE /* isRestart */, &roscToStart, sramAddr);
                if (error)
                    goto End;

                /* In case this is the last collection iteration, save the low entropy error for return */
                error = LLF_RND_TRNG_LOW_ENTROPY_ERROR;

            } else if (totalEntropyValue >= requirEntropy) {
                entropyFlag = LLF_RNG_ENTROPY_FLAG_REQUIRED;
                /* Update output source size and entropy */
                *sourceOutSize_ptr = totalSourceSize;
                *entropySize_ptr   = totalEntropyValue;
                error              = 0;
            }

        } else { /* KAT mode */

            entropyFlag = LLF_RNG_ENTROPY_FLAG_KAT_MODE;
        }
        collectionIndex++;
    }
    if (entropyFlag == LLF_RNG_ENTROPY_FLAG_KAT_MODE) {
        /* update processed ROSCs */
        rndState_ptr->TrngProcesState |= ((rndState_ptr->TrngProcesState >> 8) & 0x00FF0000);
        /* clean started & not processed */
        rndState_ptr->TrngProcesState &= 0x00FFFFFF;
    } else {
        goto End;
    }
/* end SWEE mode */

/* ................. end of function ..................................... */
/* ----------------------------------------------------------------------- */
End:

    CLEAR_TRNG_SRC();
    /* turn the RNG off    */
    if ((rndState_ptr->StateFlag & SaSi_RND_KAT_TRNG_mode) == 0) {
        LLF_RND_TurnOffTrng();
    }

    return error;

} /* END of LLF_RND_GetTrngSource */

SaSiError_t LLF_RND_RunTrngStartupTest(SaSi_RND_State_t *rndState_ptr, SaSi_RND_Params_t *trngParams_ptr,
                                       uint32_t *rndWorkBuff_ptr)

{
    SaSiError_t error = SaSi_OK;
    SASI_UNUSED_PARAM(rndState_ptr);
    SASI_UNUSED_PARAM(trngParams_ptr);
    SASI_UNUSED_PARAM(rndWorkBuff_ptr);

    return error;
}
