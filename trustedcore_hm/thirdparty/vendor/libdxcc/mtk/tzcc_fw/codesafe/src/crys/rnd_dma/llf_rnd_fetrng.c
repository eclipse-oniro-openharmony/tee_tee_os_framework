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
    isTrue &= (temp == LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_FE_MODE);
    /* check samplesCount */
    temp = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(RNG, SAMPLE_CNT1));
    isTrue &= (temp == trngParams_ptr->SubSamplingRatio);

    /* if any parameters are not match return an Error */
    if (isTrue == SASI_FALSE) {
        return LLF_RND_TRNG_PREVIOUS_PARAMS_NOT_MATCH_ERROR;
    } else {
        return SaSi_OK;
    }
}

static uint32_t LLF_RND_TRNG_RoscMaskToNum(uint32_t mask)
{
    return (mask == LLF_RND_HW_TRNG_ROSC3_BIT) ?
               LLF_RND_HW_TRNG_ROSC3_NUM :
               (mask == LLF_RND_HW_TRNG_ROSC2_BIT) ?
               LLF_RND_HW_TRNG_ROSC2_NUM :
               (mask == LLF_RND_HW_TRNG_ROSC1_BIT) ? LLF_RND_HW_TRNG_ROSC1_NUM : LLF_RND_HW_TRNG_ROSC0_NUM;
}

static void LLF_RND_TRNG_EnableRngSourceAndWatchdog(SaSi_RND_Params_t *trngParams_ptr)
{
    uint32_t maxCycles;
    uint32_t ehrSamples;

    /* set EHR samples = 2 /384 bit/ for both AES128 and AES256 */
    ehrSamples = LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_FE_MODE;

    /* Set watchdog threshold to maximal allowed time (in CPU cycles) */
    maxCycles = LLF_RND_CalcMaxTrngTime(ehrSamples, trngParams_ptr->SubSamplingRatio);
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_WATCHDOG_VAL), maxCycles);

    /* enable the RND source */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RND_SOURCE_ENABLE), LLF_RND_HW_RND_SRC_ENABLE_VAL);
}

static SaSiError_t LLF_RND_TRNG_ReadEhrData(uint32_t *pSourceOut, bool isFipsSupported)
{
    SaSiError_t error = SaSi_OK;
    uint32_t isr      = 0;
    uint32_t i;

    error = LLF_RND_TRNG_REQUIRED_ROSCS_NOT_ALLOWED_ERROR;

    /* wait RNG interrupt: isr signals error bits */
    LLF_RND_WaitRngInterrupt(&isr);

    if (SASI_REG_FLD_GET(0, RNG_ISR, EHR_VALID, isr)) {
        error = SaSi_OK;
    }
    if (SASI_REG_FLD_GET(0, RNG_ISR, CRNGT_ERR, isr) && isFipsSupported) {
        /* CRNGT requirements for FIPS 140-2. Should not try the next ROSC in FIPS mode. */
        error = LLF_RND_CTRNG_TEST_FAIL_ERROR;
    }

    /* in case of AUTOCORR_ERR or RNG_WATCHDOG, keep the default error value. will try the next ROSC. */

    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_ICR), 0xFFFFFFFF);

    if (error == SaSi_OK) {
        for (i = 0; i < LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS; i++) {
            /* load the current random data to the output buffer */
            *(pSourceOut++) = SASI_HAL_READ_REGISTER(DX_EHR_DATA_0_REG_OFFSET + (i * sizeof(uint32_t)));
        }
        SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(RNG, RNG_ISR));
    }

    return error;
}

/* ************************************************************************************* */
/* ****************************       Public Functions      **************************** */
/* ************************************************************************************* */

SaSiError_t LLF_RND_StartTrngHW(SaSi_RND_State_t *rndState_ptr, SaSi_RND_Params_t *trngParams_ptr, SaSiBool_t isRestart,
                                uint32_t *roscsToStart_ptr, DxSramAddr_t sramAddr)
{
    /* LOCAL DECLARATIONS */

    SaSiError_t error    = SaSi_OK;
    uint32_t tmpSamplCnt = 0;
    uint32_t roscNum     = 0;

    SASI_UNUSED_PARAM(sramAddr);

    /* FUNCTION LOGIC */

    /* Check pointers */
    if ((rndState_ptr == NULL) || (trngParams_ptr == NULL) || (roscsToStart_ptr == NULL))
        return LLF_RND_TRNG_ILLEGAL_PTR_ERROR;

    /* -------------------------------------------------------------- */
    /* 1. If full restart, get semaphore and set initial ROSCs      */
    /* -------------------------------------------------------------- */
    if (isRestart) {
        /* set ROSC to 1 (fastest)  */
        *roscsToStart_ptr = 1UL;

        /* init rndState flags to zero */
        rndState_ptr->TrngProcesState = 0;
    }

    if (*roscsToStart_ptr == 0)
        return LLF_RND_TRNG_REQUIRED_ROSCS_NOT_ALLOWED_ERROR;

    /* FE mode  */
    /* Get fastest allowed ROSC */
    error = LLF_RND_GetFastestRosc(trngParams_ptr, roscsToStart_ptr /* in/out */);
    if (error)
        return error;

    error = LLF_RND_GetRoscSampleCnt(*roscsToStart_ptr, trngParams_ptr);
    if (error)
        return error;

    roscNum = LLF_RND_TRNG_RoscMaskToNum(*roscsToStart_ptr);

    /* -------------------------------------------------------------- */
    /* 2. Restart the TRNG and set parameters                      */
    /* -------------------------------------------------------------- */
    /* RNG Block HW Specification (10 Programming Reference)        */

    /* enable the HW RND clock   */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_CLK_ENABLE), LLF_RND_HW_RND_CLK_ENABLE_VAL);

    /* do software reset */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_SW_RESET), 0x1);
    /* in order to verify that the reset has completed the sample count need to be verified */
    do {
        /* enable the HW RND clock   */
        SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_CLK_ENABLE), LLF_RND_HW_RND_CLK_ENABLE_VAL);

        /* set sampling ratio (rng_clocks) between consecutive bits */
        SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, SAMPLE_CNT1), trngParams_ptr->SubSamplingRatio);

        /* read the sampling ratio  */
        tmpSamplCnt = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(RNG, SAMPLE_CNT1));

    } while (tmpSamplCnt != trngParams_ptr->SubSamplingRatio);

    /* disable the RND source for setting new parameters in HW */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RND_SOURCE_ENABLE), LLF_RND_HW_RND_SRC_DISABLE_VAL);

    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_ICR), 0xFFFFFFFF);

    /* set interrupt mask */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, RNG_IMR), LLF_RNG_INT_MASK_ON_FETRNG_MODE);

    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, TRNG_CONFIG), roscNum);

    /* Debug Control register: set to 0 - no bypasses */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(RNG, TRNG_DEBUG_CONTROL), LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_FE_MODE);

    LLF_RND_TRNG_EnableRngSourceAndWatchdog(trngParams_ptr);

    /* set indication about current started ROSCs:  */
    /* new started */
    rndState_ptr->TrngProcesState = (rndState_ptr->TrngProcesState & 0x00ffffff) | (*roscsToStart_ptr << 24);
    /* total started */
    rndState_ptr->TrngProcesState |= (*roscsToStart_ptr << 8);

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

    int32_t i;
    uint32_t tmp;
    uint32_t roscToStart;
    DxSramAddr_t sramAddr;
    uint32_t *ramAddr;
    uint32_t trngBuff[LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_FE_MODE * LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS] = {
        0
    }; /* 2 EHR required */

    SASI_UNUSED_PARAM(entropySize_ptr);

    /* FUNCTION LOGIC */

    /* ............... local initializations .............................. */
    /* -------------------------------------------------------------------- */

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
               - full source size set in buffer[0],            *
               - count blocks set in buffer[1],                *
               *  - KAT source begins from buffer[2].            */
            tmp = (*sourceOut_ptr_ptr)[1]; /* count blocks for estimation */
            if (tmp == 0) {
                return SaSi_RND_KAT_DATA_PARAMS_ERROR;
            }
            return SaSi_RND_TRNG_KAT_NOT_SUPPORTED_ERROR;
            // goto Estimator;
        } else {
            goto End;
        }
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
        if (error) {
            goto End;
        }
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

    /* ==================================================== */
    /* FE mode processing: start Roscs sequentially -   *
     * from fast to slow Rosc                   */
    /* ==================================================== */

    for (i = 0; i < LLF_RND_NUM_OF_ROSCS; ++i) {
        /* read the first EHR */
        error = LLF_RND_TRNG_ReadEhrData(trngBuff, isFipsSupported);
        if (error == SaSi_OK) {
            /* read the second EHR */
            LLF_RND_TRNG_EnableRngSourceAndWatchdog(trngParams_ptr);
            error = LLF_RND_TRNG_ReadEhrData(trngBuff + LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS, isFipsSupported);
            if (error == SaSi_OK) {
                break;
            }
        }
        if (error == LLF_RND_CTRNG_TEST_FAIL_ERROR) {
            /* LLF_RND_CTRNG_TEST_FAIL_ERROR is set only in FIPS mode. do not continue to the next rosc. */
            break;
        }
        if (error != SaSi_OK) { /* try next rosc */

            /*  if no remain roscs to start, return error */
            if (roscToStart == 0x8) {
                error = LLF_RND_TRNG_GENERATION_NOT_COMPLETED_ERROR;
                break;
            } else {
                /* Call StartTrng, with next ROSC */
                roscToStart <<= 1;
                error =
                    LLF_RND_StartTrngHW(rndState_ptr, trngParams_ptr, SASI_FALSE /* isRestart */, &roscToStart, sramAddr);

                /* if no remain valid roscs, return error */
                if (error == LLF_RND_TRNG_REQUIRED_ROSCS_NOT_ALLOWED_ERROR && (trngParams_ptr->RoscsAllowed != 0)) {
                    error = LLF_RND_TRNG_GENERATION_NOT_COMPLETED_ERROR;
                }

                if (error != SaSi_OK) {
                    goto End;
                }
            }
        }

        /* update total processed ROSCs */
        rndState_ptr->TrngProcesState |= ((rndState_ptr->TrngProcesState >> 8) & 0x00FF0000);
        /* clean started & not processed */
        rndState_ptr->TrngProcesState &= 0x00FFFFFF;
    }

    if (error == SaSi_OK) {
        memcpy(ramAddr, trngBuff, LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_FE_MODE * LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES);
        *sourceOutSize_ptr = LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_FE_MODE * LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES;
    }

    /* end FE mode */

    /* ................. end of function ..................................... */
    /* ----------------------------------------------------------------------- */
End:

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
