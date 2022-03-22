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

/* ************ Include Files ************** */

#include "dx_rng.h"
#ifndef CRYS_RND_SEM_DISABLE
#include "DX_PAL_Sem.h"
#include "PLAT_SystemDep.h"
#endif
#include "dx_pal_mem.h"
#include "dx_pal_mutex.h"
#include "dx_rng_plat.h"
#include "dx_pal_abort.h"
#include "cc_plat.h"
#include "dx_pal_dma.h"
#include "dx_crys_kernel.h"
#include "dx_hal.h"
#include "hw_queue.h"
#include "crys.h"
#include "crys_common_math.h"
#include "crys_rnd_local.h"
#include "crys_rnd_error.h"
#include "llf_rnd_hwdefs.h"
#include "llf_rnd.h"
#include "llf_rnd_error.h"
#include "dx_sram_map.h"

/*
 *  Object %name    : %
 *  State           :  %state%
 *  Creation date   :  09 March 2010
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief A brief description of this module
 *
 *  \version LLF_AES.c#1:csrc:1
 *  \author R.Levin
 *  \remarks Copyright (C) 2010 by Discretix Technologies Ltd.
 *           All Rights reserved
 */

/* canceling the lint warning:
   Use of goto is deprecated */


/* canceling the lint warning:
   Info 717: do ... while(0) */


/* ******************************** Defines **************************** */
#ifndef max
#define max(a, b) (a) > (b) ? (a) : (b)
#endif

/* definitions used in the Entropy Estimator functions */
#define S(a, n) ((uint32_t)((a) * (1 << (n)))) /* a scaled by n: a \times 2^n */
#define U(a, n) ((uint32_t)(a) >> (n))         /* unscale unsigned: a / 2^n */
#define SQR(x)  (((x)&0xffff) * ((x)&0xffff))

/* macros for updating histogram for any separate bit;
   where x represents cw  or e1 */
#define LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, x)                                                                  \
    h_ptr[x & 0xff]++;                                                                                              \
    ec_ptr[x & 0x7f] = ((ec_ptr[x & 0x7f] & 1) == ((x & 0xff) >> 7)) ? ec_ptr[x & 0x7f] + 2 : ec_ptr[x & 0x7f] ^ 1; \
    x >>= 1;

/* Entropy estimation histogram width (prefix size + 1) */
#define LLF_RND_nb CRYS_RND_nb
#define LLF_RND_NB CRYS_RND_NB
#define halfNB     (LLF_RND_NB / 2)

/* macro for calculation max. allowed time for */
#define LLF_RND_CalcMaxTrngTime(ehrSamples, SubSamplingRatio)                                                        \
    (((ehrSamples)*LLF_RND_TRNG_MAX_TIME_COEFF * LLF_RND_TRNG_VON_NEUMAN_COEFF * LLF_RND_HW_TRNG_EHR_WIDTH_IN_BITS * \
      (SubSamplingRatio)) >>                                                                                         \
     LLF_RND_TRNG_MAX_TIME_SCALE)

#define ROSC_INIT_START_BIT 0x80000000

/* ********************************** Enums **************************** */
/* ********************************Typedefs **************************** */

/* *************** Global Data to be read by RNG function ************** */

extern DX_PAL_MUTEX dxSymCryptoMutex;
/* test variables */
#ifdef RND_TEST_TRNG_WITH_ESTIMATOR
uint32_t gEntrSize[4];
#endif

/* *************************************************************************** */
/* **************   Prototypes and Private functions    ********************** */
/* *************************************************************************** */
/* ************************************************************************* */
/* **********         Functions used for Entropy estimation      *********** */
/* ************************************************************************* */
/*
 * The function calculates low half of 32*32 bits multiplication result
 *
 * @param a
 * @param b
 *
 * @return uint64_t
 */
uint64_t Mult32x32(uint32_t a, uint32_t b)
{
    uint64_t res = 0;

    res = (((a >> 16) * (b >> 16)) + (((a >> 16) * (b & 0xffff)) >> 16) + (((b >> 16) * (a & 0xffff)) >> 16));
    res <<= 32;
    res += (uint64_t)((a & 0xffff) * (b & 0xffff)) + (((a >> 16) * (b & 0xffff)) << 16) +
           (((b >> 16) * (a & 0xffff)) << 16);

    return res;
}

/* Calculate 48*16 bits multiple using 16*16 bit multiplier */
/* Code ASM takes 62 bytes */
uint64_t Mult48x16(uint64_t a, uint32_t b)
{
    uint32_t a3 = (a >> 32), a2 = (a >> 16) & 0xffff, a1 = a & 0xffff;
    uint32_t b1  = (b & 0xffff);
    uint32_t r31 = a3 * b1, r21 = a2 * b1, r11 = a1 * b1;
    return (((uint64_t)r31) << 32) + (((uint64_t)r21) << 16) + ((uint64_t)r11);
}

/* approximation of entropy  */
/*
 * @brief The function approximates the entropy for separate prefix
 *        ae = n * log2(n/m).
 *
 *    Implementation according A.Klimov algorithm uses approximation by
 *    polynomial: ae = (n-m)*(A1 + A2*x + A3*x^2), where x = (n-m)/n <= 0.5 .
 *    The coefficients are defined above in this file.
 *
 * @param[in] n - The summ of  0-bits and 1-bits in the test.
 * @param[in] m - The maximal from the two above named counts.
 *
 * @return - result value of entropy ae.
 */
static uint32_t ae(uint32_t n, uint32_t m)
{
/* logarithm calculation constants */
#define A1 1.4471280
#define A2 0.6073851
#define A3 0.9790318

    uint32_t d = n - m, x = S(d, 16) / n, /* x; 16 */
        a = S(A3, 14) * x,                /* x*A3; 30 */
        b = U(S(A2, 30) + a, 16) * x,     /* x*(A2 + x*A3); 30 */
        c = (S(A1, 30) + b),              /* (A1 + x*(A2 + x*A3)); 30 */
        r = d * U(c, 14);                 /* result: 16 bits scaled */

    return r;
}

/* ************************************************************************** */
/*
 * @brief The function calculates a histogram of 0-s and 1-s distribution
 *        depending on forgouing bits combination - prefix.
 *
 *     Implementation according A.Klimov algorithm modified by A.Ziv
 *
 * @param[in]  h_ptr - The pointer to the histogramm h buffer.
 * @param[in]  ec_ptr - The pointer to the histogramm equality counter (ec) buffer.
 * @param[in]  r_ptr - The pointer to Entropy source.
 * @param[in]  nr    - The size of Entropy source in words.
 * @param[in/out] pref_ptr - The pointer to last saved prefix.
 * @param[in]  snp_ptr   - The pointer to the flag defining whether the new prefix should be set.
 *
 * @return CRYSError_t - no return value
 */
static void LLF_RND_HistogramUpdate(uint32_t *h_ptr,  /* in/out */
                                    uint32_t *ec_ptr, /* in/out */
                                    uint32_t *r_ptr,  /* in - input sequence */
                                    uint32_t nr)      /* in - input sequence size in words */
{
    int32_t i, j = 0;
    uint32_t cW; /* current word of sequence */
    uint32_t pref;

    /* FUNCTION  LOGIC  */

    /* ------------------------------------------------------ */
    /* update for first word of sequence: begin new prefix  */
    /* ------------------------------------------------------ */
    cW = r_ptr[0];
    /* 25 sequences are purely from new bits */
    for (i = 0; i < 5; i++) {
        LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, cW);
        LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, cW);
        LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, cW);
        LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, cW);
        LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, cW);
    }

    pref = cW;
    j    = 1;

    /* ----------------------------------------------------------------------- */
    /* update for remaining words of sequence: continue with previous prefix */
    /* ----------------------------------------------------------------------- */
    for (; j < nr; j++) {
        uint32_t e1;

        /* current word of random sequence */
        cW = r_ptr[j];
        /* concatenation of previous saved prefix and new bits */
        e1 = (cW << 7) | pref;

        /* first 7 sequences are combined from previous prefix and new bits  */
        LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, e1);
        LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, e1);
        LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, e1);
        LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, e1);
        LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, e1);
        LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, e1);
        LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, e1);

        /* next 25 sequences are purely from new bits */
        for (i = 0; i < 5; i++) {
            LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, cW);
            LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, cW);
            LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, cW);
            LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, cW);
            LLF_RND_UpdateHistOneBit(h_ptr, ec_ptr, cW);
        }

        pref = cW;
    }

} /* End of LLF_RND_HistogramUpdate() */

/* ************************************************************************** */
/*
 * @brief The function calculates estimation of entropy, generated by TRNG and
 *        used for control the TRNG work.
 *
 *   Implementation based on algorithm developed by A.Klimov.
 *
 * @param[in] h - The pointer to the h-buffer (counts of 0-s and 1-s for each prefix).
 * @param[in] ec - The pointer to the ec-buffer (equality counters).
 * @param[out] e_ptr - The pointer to count of accumulated Entropy (bits multiplied by 2^16).
 *
 * @return CRYSError_t - according to module definitions
 */
static CRYSError_t LLF_RND_EntropyEstimate(uint32_t *h,                   /* in/out */
                                           uint32_t *ec, uint32_t *e_ptr) /* out - result Entropy size */
{
    uint64_t t = 0;     /* total entropy */
    uint32_t i, ac = 0; /* number of active prefixes */

    /* -------------  calculate entropy ----------------- */

    for (i = 0; i < halfNB; ++i) {
        uint32_t n = h[i] + h[i + halfNB], m = max(h[i], h[i + halfNB]);

        /* check that n < 2^16, else return overflow error */
        if (n >= (1UL << 16))
            return LLF_RND_TRNG_ENTR_ESTIM_SIZE_EXCEED_ERROR;

        if (n != m) { /* if active prefix */
            uint32_t n2, pp, od;
            uint64_t od2, od2n, var;

            /* increment count of active prefixes */
            ++ac;

            pp = SQR(m) + SQR(n - m);        /* related to theoretical "autocorrelation" probability */
            n2 = Mult16x16((ec[i] >> 1), n); /* n2 used as temp */

            /* value, related to observed deviation of autocorrelation */
            if (n2 > pp)
                od = n2 - pp;
            else
                od = pp - n2;

            /* theoretical variance of B(n, pp): always > 0 */
            n2  = SQR(n);
            var = Mult32x32(pp, (n2 - pp));

            /* if  n*od^2 < var then accumulate entropy, else return Error;
               Note: that this condition is True only if od < 2^32 */
            if (od < ~0UL) {
                od2 = Mult32x32(od, od);

                /* scale variables */
                if (od2 > ((uint64_t)1ULL << 48)) {
                    od2 /= (1UL << 16);
                    var /= (1UL << 16);
                }

                od2n = Mult48x16(od2, n);

                if (od2n < var)
                    t += ae(n, m);
            }
        }
    }

    /* output entropy size value in bits (rescaled) */

    *e_ptr = ac > 3 ? (t / (1UL << 16)) : 0;

    return CRYS_OK;

} /* End of LLF_RND_EntropyEstimate */

/* ************************************************************************** */
/*
 * @brief The function calculates estimation of entropy, generated by 4 ROSCs
 *
 * @param[in] ramAddr - The pointer to random source.
 * @param[in] blockSizeWords - The size of each block of random source in words.
 * @param[in] countBlocks - The blocks count (according to given ROSCS).
 * @param[in] h_ptr - The pointer to the h-buffer (counts of 0-s and 1-s for each prefix).
 * @param[in] ec_ptr - The pointer to the ec-buffer (equality counters).
 * @param[out] entrSize_ptr - The pointer to count of accumulated Entropy in bits.
 * @param[in] rndState_ptr - The pointer to random State.
 *
 * @return CRYSError_t - according to module definitions
 */
CRYSError_t LLF_RND_EntropyEstimateFull(uint32_t *ramAddr,              /* in */
                                        uint32_t blockSizeWords,        /* in */
                                        uint32_t countBlocks,           /* in */
                                        uint32_t *entrSize_ptr,         /* out */
                                        CRYS_RND_State_t *rndState_ptr, /* in */
                                        uint32_t *rndWorkBuff_ptr)      /* in */
{
    CRYSError_t error = 0;
    uint32_t i, totalEntr = 0, currEntr;
    uint32_t *h_ptr, *ec_ptr;
    uint32_t *eachRoscEntr_ptr = rndWorkBuff_ptr + CRYS_RND_WORK_BUFF_TMP2_OFFSET;

    /* Initialization */

    h_ptr  = rndWorkBuff_ptr + CRYS_RND_H_BUFF_OFFSET;
    ec_ptr = rndWorkBuff_ptr + CRYS_RND_EC_BUFF_OFFSET;

    /* estimate entropy for given blocks (ROSCs) */
    for (i = 0; i < countBlocks; i++) {
        /* Zeroe working buffer for entr. estimator */
        DX_PAL_MemSetZero(h_ptr, H_BUFF_SIZE_WORDS * 4);
        DX_PAL_MemSetZero(ec_ptr, EC_BUFF_SIZE_WORDS * 4);

        LLF_RND_HistogramUpdate(h_ptr, ec_ptr, ramAddr + i * blockSizeWords, blockSizeWords);

        error = LLF_RND_EntropyEstimate(h_ptr, ec_ptr, &currEntr); /* out - result Entropy size */

        if (error)
            goto End;

        /* total entropy and separate ROSCs entropy */
        totalEntr += currEntr;
        eachRoscEntr_ptr[i] = currEntr;
    }

    /* entropy correction: down ~1.5% */
    totalEntr -= totalEntr >> 6;

    *entrSize_ptr = totalEntr;

End:
    return error;
}

/* ************************************************************************************* */
/* **********************      Auxiliary Functions              ************************ */
/* ************************************************************************************* */

/* ********************************************************************************* */
/* !
 * Busy wait upon RNG Interrupt signals.
 *
 * This function waits RNG interrupt and then disables RNG source.
 * It uses DX_HAL_WaitInterrupt function
 * to receive common RNG interrupt and then reads and
 * outputs the RNG ISR (status) register.
 *
 *
 * \return uint32_t RNG Interrupt status.
 */
static void LLF_RND_WaitRngInterrupt(CRYS_RND_Params_t *trngParams_ptr, uint32_t *isr_ptr)
{
    uint32_t tmp = 0;

    /* busy wait upon RNG IRR signals */
    DX_CC_REG_FLD_SET(HOST_RGF, HOST_IRR, RNG_INT, tmp, 1);
    /* wait for watermark signal */
    DX_HAL_WaitInterrupt(tmp);

    /* stop DMA and the RNG source */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RNG_DMA_ENABLE), 0);
    /* !!TBD: DMA_ENABLE -> SOURCE_ENABLE */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RND_SOURCE_ENABLE), 0);

    /* read specific RNG interrupt status */
    *isr_ptr = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(RNG, RNG_ISR));

    /* clear RNG interrupt status besides HW errors */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RNG_ICR), *isr_ptr);

    return;
}

/* ********************************************************************************* */
/*
 * The function checks that parameters, loaded in the TRNG HW
 * are match to parameters, required by trngParams_ptr structures.
 *
 * @author reuvenl (6/25/2012)
 *
 * @param rndState_ptr
 * @param trngParams_ptr
 *
 * @return CRYSError_t
 */
static CRYSError_t LLF_RND_TRNG_CheckHwParams(CRYS_RND_Params_t *trngParams_ptr)
{
    uint32_t temp;
    DxBool_t isTrue = DX_TRUE;

    /* check Debug control - masked TRNG tests according to mode */
    temp = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(RNG, TRNG_DEBUG_CONTROL));
    if (trngParams_ptr->TrngMode == CRYS_RND_Fast)
        isTrue &= (temp == LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_FAST_MODE);
    else
        isTrue &= (temp == LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_SLOW_MODE);
    /* check samplesCount */
    temp = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(RNG, SAMPLE_CNT1));
    isTrue &= (temp == trngParams_ptr->SubSamplingRatio);

    /* if any parameters are not match return an Error */
    if (isTrue == DX_FALSE)
        return LLF_RND_TRNG_PREVIOUS_PARAMS_NOT_MATCH_ERROR;
    else
        return CRYS_OK;
}

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
static uint32_t LLF_RND_DescBypass(DxSramAddr_t inSramAddr, uint32_t inSize, uint32_t *outAddr_ptr)
{
    uint32_t error = 0;
    HwDesc_s desc;
    /* Virtual and physical address of allocated temp buffer */
    uint8_t *tmpVirtAddr_ptr;
    DX_PAL_DmaBlockInfo_t tmpBlockInfo;
    uint32_t numOfBlocks = 1;
    DX_PAL_DmaBufferHandle dmaH;

    error = DX_PAL_MutexLock(&dxSymCryptoMutex, DX_INFINITE);
    if (error != DX_SUCCESS) {
        DX_PAL_Abort("Fail to acquire mutex\n");
    }
    /* Allocate contigious buffer for DMA transfer */
    error = DX_PAL_DmaContigBufferAllocate(inSize, &tmpVirtAddr_ptr);
    if (error != 0) {
        goto End;
    }

    numOfBlocks = 1;
    error =
        DX_PAL_DmaBufferMap(tmpVirtAddr_ptr, inSize, DX_PAL_DMA_DIR_FROM_DEVICE, &numOfBlocks, &tmpBlockInfo, &dmaH);
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
    DX_PAL_DmaBufferUnmap(tmpVirtAddr_ptr, inSize, DX_PAL_DMA_DIR_FROM_DEVICE, numOfBlocks, &tmpBlockInfo, dmaH);

    /* Copy data from temp buffer into RAM output, usung virt. addresses */
    DX_PAL_MemCopy((uint8_t *)outAddr_ptr, tmpVirtAddr_ptr, inSize);

    /* Release the temp buffer */
    error = DX_PAL_DmaContigBufferFree(inSize, tmpVirtAddr_ptr);

End:
    if (DX_PAL_MutexUnlock(&dxSymCryptoMutex) != DX_SUCCESS) {
        DX_PAL_Abort("Fail to release mutex\n");
    }
    return error;
}

/* ************************************************************** */
/*
 * The function gets next allowed rosc
 *
 * @author reuvenl (9/12/2012)
 *
 * @param trngParams_ptr - a pointer to params structure.
 * @param rosc_ptr - a pointer to previous rosc /in/, and
 *             to next rosc /out/.
 * @param isNext - defines is increment of rosc ID needed or not.
 *             if isNext = TRUE - the function shifts rosc by one bit; Then
 *             the function checks is this rosc allowed, if yes - updates
 *             the rosc, else repeats previous steps. If no roscs allowed -
 *             returns an error.
 *
 *
 * @return CRYSError_t
 */
static CRYSError_t LLF_RND_GetFastestRosc(CRYS_RND_Params_t *trngParams_ptr, uint32_t *rosc_ptr, /* in/out */
                                          DxBool_t isNext)
{
    /* setting rosc */
    do {
        if (*rosc_ptr & trngParams_ptr->RoscsAllowed) {
            return CRYS_OK;
        } else {
            *rosc_ptr <<= 1;
        }

    } while (*rosc_ptr <= 0x08);

    return LLF_RND_TRNG_REQUIRED_ROSCS_NOT_ALLOWED_ERROR;
}

/*
 * The macros calculates count ROSCs to start, as count of bits "1" in allowed
 * roscToStart parameter.
 *
 * @author reuvenl (9/20/2012)
 *
 * @param roscsAllowed
 * @param roscToStart
 *
 * @return uint32_t
 */
static uint32_t LLF_RND_GetCountRoscs(uint32_t roscsAllowed, uint32_t roscToStart)
{
    uint32_t countRoscs = 0;

    roscToStart &= roscsAllowed;
    while (roscToStart) {
        countRoscs += (roscToStart & 1UL);
        roscToStart >>= 1;
    }

    return countRoscs;
}
/*
 * The function returns number of ROSC with best entropy performance
 *
 * @author taniam (3/13/2014)
 *
 * @param trngParams_ptr
 * @param rndWorkBuff_ptr
 *
 * @return uint32_t
 */
static uint32_t LLF_RND_GetPreferableRosc(uint32_t *rndWorkBuff_ptr)
{
    uint32_t *eachRoscEntr_ptr = rndWorkBuff_ptr + CRYS_RND_WORK_BUFF_TMP2_OFFSET;
    uint32_t indexOfPreferableRosc, maxValueOfEntropy, i;

    maxValueOfEntropy     = 0;
    indexOfPreferableRosc = 0xf;

    for (i = 0; i < LLF_RND_MAX_NUM_OF_ROSCS; i++) {
        if (eachRoscEntr_ptr[i] > maxValueOfEntropy) {
            indexOfPreferableRosc = i;
            maxValueOfEntropy     = eachRoscEntr_ptr[i];
        }
    }
    return indexOfPreferableRosc;
}
/* ************************************************************************************* */
/* ****************************       Public Functions      **************************** */
/* ************************************************************************************* */

/* ********************************************************************************* */
/*
 * @brief The LLF_RND_TurnOffTrng stops the hardware random bits collection
 *        closes RND clocks and releases HW semaphore.
 *
 *
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
void LLF_RND_TurnOffTrng(void)
{
    /* LOCAL DECLARATIONS */

    uint32_t temp = 0;

    /* FUNCTION LOGIC */

    /* disable the RND source  */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RND_SOURCE_ENABLE), LLF_RND_HW_RND_SRC_DISABLE_VAL);

    /* close the Hardware clock */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RNG_CLK_ENABLE), LLF_RND_HW_RND_CLK_DISABLE_VAL);

    /* clear RNG interrupts */
    DX_CC_REG_FLD_SET(HOST_RGF, HOST_ICR, RNG_INT_CLEAR, temp, 1);
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_ICR), temp);
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RNG_ICR), 0xFFFFFFFF);

    return;

} /* END OF LLF_RND_TurnOffTrng */

/* ************************************************************************************* */
/*
 * @brief The function starts the TRNG with given parameters and ROSCs lengths
 *
 *      NOTE: It is assumed, that before calling this function, the previously
 *            started TRNG processes were compleated and Interrupts cleared.
 *
 *      Algorithm:
 *      1. If is continued mode, the function does:
 *              checks actual parameters, loaded in TRNG registers,
 *              vs. user given parameters; if any not matchs - returns Error.
 *         Else /do restart/:
 *          sets ROSCs to start: for "fast" - all allowed, for "slow" -
 *          fastest from allowed; gets the user given parameters and sets
 *          them in the HW, starts the TRNG clocks and sets TRNG parameters
 *          into HW registers.
 *      2. Initializes the RND DMA according to ROSCs required to start,
 *         initializes the TRNG Interrupt. Enables RNG source.
 *      3. Exits.
 *
 * @param[in/out] rndState_ptr - The pointer to the internal State buffer of DRNG.
 * @param[in/out] trngParams_ptr - The pointer to structure, containing TRNG parameters.
 * @isContinued[in] isRestart - The variable indicates is a restart required or not.
 * @roscsToStart[in] roscsToStart_ptr - The variable, defining which ROSCs to
 *                      start according to bits set: b'0...b'3. When
 *                      isRestart=TRUE, then:
 *                      for "fast" - starts all allowed ROSCs, for
 *                      "slow" - starts fastest ROSC from allowed.
 *                      Note: if isRestart = 1, then
 * @sramAddr[in] SRAM address to write the random source.
 *
 * @return CRYSError_t - no return value
 */
CRYSError_t LLF_RND_StartTrngHW(CRYS_RND_State_t *rndState_ptr, CRYS_RND_Params_t *trngParams_ptr, DxBool_t isRestart,
                                uint32_t *roscsToStart_ptr, DxSramAddr_t sramAddr)
{
    /* LOCAL DECLARATIONS */

    CRYSError_t error = CRYS_OK;
    uint32_t temp, ehrSamples, tmpSamplCnt = 0;

    /* FUNCTION LOGIC */

    /* Check pointers */
    if ((rndState_ptr == DX_NULL) || (trngParams_ptr == DX_NULL) || (roscsToStart_ptr == DX_NULL) || (sramAddr == 0))
        return LLF_RND_TRNG_ILLEGAL_PTR_ERROR;

    /* get user's TRNG parameters */
    error = RNG_PLAT_SetUserRngParameters(rndState_ptr, trngParams_ptr);

    if (error != CRYS_OK)
        return error;

    /* -------------------------------------------------------------- */
    /* 1. If full restart, get semaphore and set initial ROSCs      */
    /* -------------------------------------------------------------- */
    if (isRestart) {
        if (trngParams_ptr->TrngMode == CRYS_RND_Slow) {
            /* set ROSC to 1 (fastest)  */
            *roscsToStart_ptr = 1UL;
            ;
        } else {
            /* Fast mode - start all allowed ROSCs */
            *roscsToStart_ptr = 0x0f & trngParams_ptr->RoscsAllowed;
        }

        /* init rndState flags to zero */
        rndState_ptr->TrngProcesState = 0;
    }

    if (*roscsToStart_ptr == 0)
        return LLF_RND_TRNG_REQUIRED_ROSCS_NOT_ALLOWED_ERROR;

    /* -------------------------------------------------------------- */
    /* 2. Restart the TRNG and set  parameters              */
    /* -------------------------------------------------------------- */

    /* enable the HW RND clock   */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RNG_CLK_ENABLE), LLF_RND_HW_RND_CLK_ENABLE_VAL);

    /* do software reset */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RNG_SW_RESET), 0x1);
    /* in order to verify that the reset has completed the sample count need to be verified */
    do {
        /* enable the HW RND clock   */
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RNG_CLK_ENABLE), LLF_RND_HW_RND_CLK_ENABLE_VAL);

        /* set sampling ratio (rng_clocks) between consequtive bits */
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, SAMPLE_CNT1), trngParams_ptr->SubSamplingRatio);

        /* read the sampling ratio  */
        tmpSamplCnt = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(RNG, SAMPLE_CNT1));

    } while (tmpSamplCnt != trngParams_ptr->SubSamplingRatio);

    /* disable the RND source for setting new parameters in HW */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RND_SOURCE_ENABLE), LLF_RND_HW_RND_SRC_DISABLE_VAL);

    /* set TRNG_CONFIG to choose SOP_SEL = 1 - i.e. EHR output */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, TRNG_CONFIG), LLF_RND_HW_TRNG_WITH_DMA_CONFIG_VAL);

    /* Fast mode */
    if (trngParams_ptr->TrngMode == CRYS_RND_Fast) {
        /* Debug Control register: NC_BYPASS + TRNG_CRNGT_BYPASS + AUTO_CORRELATE_BYPASS set to 1   */
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, TRNG_DEBUG_CONTROL), LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_FAST_MODE);

        /* set interrupt mask */
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RNG_IMR), LLF_RNG_INT_MASK_ON_FAST_MODE);
        ehrSamples = LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_FAST_MODE;
    }

    /* Slow mode  */
    else {
        /* Get fastest allowed ROSC */
        error = LLF_RND_GetFastestRosc(trngParams_ptr, roscsToStart_ptr, /* in/out */
                                       1 /* isNext */);
        if (error)
            return error;

        /* Debug Control register: set to 0 - no bypasses */
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, TRNG_DEBUG_CONTROL), LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_SLOW_MODE);

        /* set interrupt mask */
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RNG_IMR), LLF_RNG_INT_MASK_ON_SLOW_MODE);

        /* set EHR samples = 2 /384 bit/ for both AES128 and AES256 */
        ehrSamples = LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_SLOW_MODE;

        /* Set watchdog threshold to maximal allowed time (in CPU cycles)
           maxTime = (expectTimeInClocks*timeCoeff) */
        temp = LLF_RND_CalcMaxTrngTime(ehrSamples, trngParams_ptr->SubSamplingRatio);
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RNG_WATCHDOG_VAL), temp);
    }

    /* set ROSCS to start and EHR samples from each ROSC to DMA transfer */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RNG_DMA_SRC_MASK), *roscsToStart_ptr);
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RNG_DMA_SAMPLES_NUM), ehrSamples);

    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RNG_DMA_SRAM_ADDR), (uint32_t)sramAddr);

    /* clear RNG interrupts !!TBD */
    temp = 0;
    DX_CC_REG_FLD_SET(HOST_RGF, HOST_ICR, RNG_INT_CLEAR, temp, 1);
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_ICR), temp);
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RNG_ICR), 0xFFFFFFFF);

    /* enable DMA (automatically enables RNG source) */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(RNG, RNG_DMA_ENABLE), LLF_RND_HW_RND_DMA_ENABLE_VAL);

    /* set indication about current started ROSCs:  */
    /* new started */
    rndState_ptr->TrngProcesState = (rndState_ptr->TrngProcesState & 0x00ffffff) | (*roscsToStart_ptr << 24);
    /* total started */
    rndState_ptr->TrngProcesState |= (*roscsToStart_ptr << 8);

    /* end  of function */
    return error;
}

/* **************************************************************************** */
/*
 * @brief The LLF_RND_GetTrngSource reads random source of needed size from TRNG.
 *
 *        The function is used in Self, Instantiation and Reseeding functions.
 *
 * @param[in/out] rndState_ptr - The pointer to the internal State buffer of DRNG.
 * @param[in/out] trngParams_ptr - The pointer to structure, containing TRNG parameters.
 * @isContinued[in] isContinued - The variable indicates is the required process should
 *                  continue a  previous one or restart TRNG.
 * @entropySize_ptr[in/out] - The pointer to size of entropy in bits: input - required,
 *                            output - actual size.
 * @sourceOut_ptr_ptr[out] - The pointer to to pointer to the entropy source buffer.
 *                   The buffer contains one empty word for using by CRYS level
 *                   and then buffer for output the rng source.
 * @param[out] - sourceOutSize_ptr - The pointer to the size in bytes of entropy source
 *                      in - requirred size, output - actual size.
 * @param[in/out] - rndWorkBuff_ptr - The pointer to the temp buffer for allocation of
 *                     estimator buffers.
 *
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CRYSError_t LLF_RND_GetTrngSource(CRYS_RND_State_t *rndState_ptr,    /* in/out */
                                  CRYS_RND_Params_t *trngParams_ptr, /* in/out */
                                  DxBool_t isContinued,              /* in */
                                  uint32_t *entropySize_ptr,         /* in/out */
                                  uint32_t **sourceOut_ptr_ptr,      /* out */
                                  uint32_t *sourceOutSize_ptr,       /* in/out */
                                  uint32_t *rndWorkBuff_ptr)         /* in */
{
    /* LOCAL DECLARATIONS */

    /* The return error identifier */
    CRYSError_t error = 0, descrError = 0;

    int32_t i;
    uint32_t isr;
    uint32_t tmp;
    uint32_t roscToStart, sizeToProcessBytes, prefRoscIndex;
    DxSramAddr_t sramAddr;
    uint32_t *ramAddr;

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
    error = CRYS_OK;

    /* Set source RAM address with offset 8 bytes from sourceOut address in
      order to remain empty bytes for CRYS operations */
    *sourceOut_ptr_ptr = rndWorkBuff_ptr + CRYS_RND_SRC_BUFF_OFFSET_WORDS;
    ramAddr            = *sourceOut_ptr_ptr + CRYS_RND_TRNG_SRC_INNER_OFFSET_WORDS;
    sramAddr           = DX_SRAM_RND_HW_DMA_ADDRESS;
    /* init to 0 for Slow mode */
    *sourceOutSize_ptr = 0;

    /* Case of RND KAT or TRNG KAT testing  */
    if ((rndState_ptr->StateFlag & CRYS_RND_KAT_DRBG_mode) || (rndState_ptr->StateFlag & CRYS_RND_KAT_TRNG_mode)) {
        /* set source sizes given by the user in KAT test and placed
           in the rndWorkBuff with offset CRYS_RND_SRC_BUFF_OFFSET_WORDS */
        *sourceOutSize_ptr = (*sourceOut_ptr_ptr)[0];
        if (*sourceOutSize_ptr == 0) {
            return CRYS_RND_KAT_DATA_PARAMS_ERROR;
        }

        /* Go to Estimator */
        if (rndState_ptr->StateFlag & CRYS_RND_KAT_TRNG_mode) {
            /* Assumed, that KAT data is set in the rnd Work      *
               buffer as follows:                     *
               - full source size set in buffr[0],            *
               - count blocks set in buffr[1],                *
            *  - KAT source begins from buffer[2].            */
            tmp = (*sourceOut_ptr_ptr)[1]; /* count blocks for estimation */
            if (tmp == 0) {
                return CRYS_RND_KAT_DATA_PARAMS_ERROR;
            }
            sizeToProcessBytes = (*sourceOut_ptr_ptr)[0] / tmp; /* one block size */
            goto Estimator;
        } else
            goto End;
    }
    /* If not continued mode, set TRNG parameters and restart TRNG     */
    /* -------------------------------------------------------------- */
    if (isContinued == DX_FALSE) {
        /* set user's TRNG parameters */
        error = RNG_PLAT_SetUserRngParameters(rndState_ptr, trngParams_ptr);
        if (error != CRYS_OK)
            return error;

        /* Set instantiation, TRNG errors and time   *
         * exceeding bits of State to 0           */
        rndState_ptr->StateFlag &= ~(CRYS_RND_Instantiated | CRYS_RND_InstantReseedAutocorrErrors |
                                     CRYS_RND_InstantReseedTimeExceed | CRYS_RND_InstantReseedLessEntropy);

        /* Full restart TRNG */
        error = LLF_RND_StartTrngHW(rndState_ptr, trngParams_ptr, DX_TRUE /* isRestart */, &roscToStart, sramAddr);

        /* Note: in case of error the TRNG HW is still not started */
        if (error)
            goto End;
    }

    /* On continued mode check HW TRNG */
    else {
        /* check TRNG parameters */
        error = LLF_RND_TRNG_CheckHwParams(trngParams_ptr);
        if (error != CRYS_OK)
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
    /* Fast mode processing (yet started all 4 ROSCs):
       wait interrupt, estimate entropy and output the source  */
    /* ========================================================= */
    if (trngParams_ptr->TrngMode == CRYS_RND_Fast) {
        /* save entropy */
        requirEntropy = *entropySize_ptr;

        /* Perform collection of bits until required entropy is reached or max number of iteration exceeded */
        while ((entropyFlag == LLF_RNG_ENTROPY_FLAG_LOW) && (collectionIndex < LLF_RNG_MAX_COLLECTION_ITERATION_SIZE)) {
            /* wait and output irr = RNG_ISR */
            LLF_RND_WaitRngInterrupt(trngParams_ptr, &isr);

            /* source size from one rosc and from all started rosc's */
            sizeToProcessBytes = LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_FAST_MODE * LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES;

            /* calculate count of rosc's started */
            tmp = LLF_RND_GetCountRoscs(trngParams_ptr->RoscsAllowed, roscToStart);

            /* Calculate size of current and total source size */
            *sourceOutSize_ptr = tmp * sizeToProcessBytes;
            totalSourceSize += *sourceOutSize_ptr;

            /* Execute BYPASS operation similar to DescBypass() */
            error = LLF_RND_DescBypass(sramAddr /* in */, *sourceOutSize_ptr /* inSize */, (uint32_t *)ramAddr /* out */);
            if (error)
                goto End;

#ifdef BIG__ENDIAN
            /* set endianness */
            for (i = 0; i < (*sourceOutSize_ptr) / 4; ++i) {
                ramAddr[i] = CRYS_COMMON_REVERSE32(ramAddr[i]);
            }
#endif

        Estimator:
            if (requirEntropy != 1) { /* the condition need for performance test */

                error = LLF_RND_EntropyEstimateFull(ramAddr,                 /* in */
                                                    sizeToProcessBytes >> 2, /* 1 block size, words */
                                                    tmp /* count blocks */,    /* in */
                                                    entropySize_ptr,         /* out */
                                                    rndState_ptr,            /* in */
                                                    rndWorkBuff_ptr);        /* in */
                if (error)
                    goto End;
            }
            /* save entropy size for testing */
            totalEntropyValue += *entropySize_ptr;
            rndState_ptr->EntropySizeBits = totalEntropyValue;

            /* if not KAT mode check entropy */
            if (!(rndState_ptr->StateFlag & (CRYS_RND_KAT_DRBG_mode | CRYS_RND_KAT_TRNG_mode))) {
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
                            return LLF_RND_TRNG_GENERATION_NOT_COMPLETED_ERROR; // add relevant error
                        }
                        /* Update RAM address for next entropy source */
                        ramAddr += (sizeToProcessBytes >> 2) * tmp;
                    } else { /* If entropy was collected from chosen ROSC */
                        /* Update RAM address for next entropy source */
                        ramAddr += (LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_FAST_MODE * LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS);
                    }

                    /* Start TRNG with updated ROSC */
                    error = LLF_RND_StartTrngHW(rndState_ptr, trngParams_ptr, DX_FALSE /* isRestart */, &roscToStart,
                                                sramAddr);
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
    }

    /* ==================================================== */
    /* Slow mode processing: start Roscs sequentionally - *
     * from fast to slow Rosc                   */
    /* ==================================================== */
    else {
        sizeToProcessBytes = LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_SLOW_MODE * LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES;

        for (i = 0; i < 4; ++i) {
            /* wait RNG interrupt: isr signals error bits */
            LLF_RND_WaitRngInterrupt(trngParams_ptr, &isr);

            /* get DMA done status */
            tmp = (isr >> DX_RNG_ISR_RNG_DMA_DONE_BIT_SHIFT) & 1UL;

            /* update output source size and sramAddr */
            *sourceOutSize_ptr += sizeToProcessBytes;
            sramAddr += sizeToProcessBytes;

            /* update total processed ROSCs */
            rndState_ptr->TrngProcesState |= ((rndState_ptr->TrngProcesState >> 8) & 0x00FF0000);
            /* clean started & not processed */
            rndState_ptr->TrngProcesState &= 0x00FFFFFF;

            /* if DMA done and no HW errors - exit */
            if ((tmp == 1) && ((isr & LLF_RNG_ERRORS_MASK) == 0))
                break;

            else { /* case of erors or watchdog exceed  - try next rosc */

                /*  if no remain roscs to start, return error */
                if (roscToStart == 0x8) {
                    error = LLF_RND_TRNG_GENERATION_NOT_COMPLETED_ERROR;
                    break;
                } else {
                    /* Call StartTrng, whith next ROSC */
                    roscToStart <<= 1;
                    error = LLF_RND_StartTrngHW(rndState_ptr, trngParams_ptr, DX_FALSE /* isRestart */, &roscToStart,
                                                sramAddr);

                    if (error != CRYS_OK)
                        goto End;
                }
            }
        }

        /* Execute BYPASS operation from initial sramAddr */
        sramAddr = DX_SRAM_RND_HW_DMA_ADDRESS;

        descrError = LLF_RND_DescBypass(sramAddr /* in */, *sourceOutSize_ptr /* inSize */, (uint32_t *)ramAddr /* out */);
        if (descrError) {
            /* Note: Priority to SW error */
            error = descrError;
            goto End;
        }

    } /* end slow mode */

/* ................. end of function ..................................... */
/* ----------------------------------------------------------------------- */
End:

    /* turn the RNG off    */
    if ((rndState_ptr->StateFlag & CRYS_RND_KAT_TRNG_mode) == 0) {
        LLF_RND_TurnOffTrng();
    }

    return error;

} /* END of LLF_RND_GetTrngSource */
