/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef LLF_RND_HW_DEFS_H
#define LLF_RND_HW_DEFS_H

/* *********************** Defines **************************** */

/* SRAM base address */
extern uint32_t g_MemOffsetAddr;

/* The number of words generated in the entropy holding register (EHR)
   6 words (192 bit) according to HW implementation */
#define LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS 6
#define LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES (LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS * sizeof(uint32_t))
#define LLF_RND_HW_TRNG_EHR_WIDTH_IN_BITS  (8 * LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES)

/* ring oscillator length maximal level */
#define LLF_RND_HW_TRNG_ROSC_FAST_MAX_LEVEL 3UL
#define LLF_RND_HW_TRNG_ROSC_LENGTH_MASK    0x0f

/* ring oscillator offsets and numbers */
#define LLF_RND_HW_TRNG_ROSC0_BIT 0x1
#define LLF_RND_HW_TRNG_ROSC1_BIT 0x2
#define LLF_RND_HW_TRNG_ROSC2_BIT 0x4
#define LLF_RND_HW_TRNG_ROSC3_BIT 0x8
#define LLF_RND_HW_TRNG_ROSC0_NUM 0x0
#define LLF_RND_HW_TRNG_ROSC1_NUM 0x1
#define LLF_RND_HW_TRNG_ROSC2_NUM 0x2
#define LLF_RND_HW_TRNG_ROSC3_NUM 0x3

/* TRNG_CONFIG value for SRC_SEL = 0, SOP_SEL = 1 (SOP = TRNG EHR output) */
#define LLF_RND_HW_TRNG_WITH_DMA_CONFIG_VAL 0x4

/* HW_TRNG values on SWEE mode */
/* --------------------------------------- */
#define LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_SWEE_MODE 0x0000000E
#define LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_SWEE_MODE 21UL

/* HW_TRNG registers values on FE mode */
/* --------------------------------------- */
#define LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_FE_MODE 0x00000000
#define LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_FE_MODE 2UL /* for both AES128 and AES256 */

/* HW_TRNG registers values on 800-90b mode */
/* --------------------------------------- */
#define LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_TRNG90B_MODE \
    0x0000000A /* bypass Von-Neumann balancer and autocorrelation test */
#define LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_TRNG90B_MODE 22UL

/* HW RND DMA SRAM address offset, bytes */

#define LLF_RND_HW_RND_DMA_ENABLE_VAL  1UL
#define LLF_RND_HW_RND_DMA_DISABLE_VAL 0UL
#define LLF_RND_HW_RND_SRC_ENABLE_VAL  1UL
#define LLF_RND_HW_RND_SRC_DISABLE_VAL 0UL
#define LLF_RND_HW_RND_CLK_ENABLE_VAL  1UL
#define LLF_RND_HW_RND_CLK_DISABLE_VAL 0UL

/* currently DX_RNG_ISR_RNG_WATCHDOG_BIT (bit 4 in RNG_ISR) is not defined in dx_rng.h */
#define DX_RNG_ISR_RNG_WATCHDOG_BIT_SHIFT 0x4UL
#define DX_RNG_ISR_RNG_WATCHDOG_BIT_SIZE  0x1UL

/*
   LLF_RND_TRNG_MAX_TIME_COEFF - scaled coefficient, defining relation of
   maximal allowed time for TRNG generation (per one ROSC) expected minimal
   time: MaxAllowedTime = (ExpectTime*LLF_RND_TRNG_MAX_TIME_COEFF) / 64, where
   64 = (1<<6) is a scaling coefficient.
   Example: if LLF_RND_TRNG_MAX_TIME_COEFF = 128, then MaxAllowedTime =
   2*ExpectTime.
*/
#define LLF_RND_TRNG_MAX_TIME_SCALE   6   /* scaling down by 64 */
#define LLF_RND_TRNG_MAX_TIME_COEFF   128 /* preferable set value as power of 2  */
#define LLF_RND_TRNG_VON_NEUMAN_COEFF 4   /* increases time because part of bits are rejected */

/* RNG interrupt masks */
/* on trng90b DMA mode masked bits:  EHR_VALID, CTRNGT;
   unmasked:  AutoCorrT, VNT and RNG_DMA_DONE, other bits masked: 0xFFFFFFC5 */
#define LLF_RNG_INT_MASK_ON_TRNG90B_MODE 0xFFFFFFC5

/* on swee mode:  masked all bits besides b'5 - RNG_DMA_DONE: 0xFFFFFFDF   */
#define LLF_RNG_INT_MASK_ON_SWEETRNG_MODE 0xFFFFFFDF

/* on fe-trng mode: masked all bits besides - EHR_VALID, AUTOCORR_ERR, and WATCHDOG: 0xFFFFFFEC */
#define LLF_RNG_INT_MASK_ON_FETRNG_MODE 0xFFFFFFEC

/* TRNG errors mask - masking all bits besides TRNG errors: AutoCorr + VN +   *
 *  Watchdog                                       */
#define LLF_RNG_ERRORS_MASK                                                                                \
    ((1UL << DX_RNG_IMR_AUTOCORR_ERR_INT_MASK_BIT_SHIFT) | (1UL << DX_RNG_IMR_VN_ERR_INT_MASK_BIT_SHIFT) | \
     (1UL << DX_RNG_IMR_WATCHDOG_INT_MASK_BIT_SHIFT))

/* auxilary defines */
#define DX_SEP_HW_RESET_SEED_OVERRIDE_FLAG 0x2Ul

/* ********************** Macros ****************************** */

/* This busy loop waits for the valid bit to be set to 0x1 */
#define LLF_RND_HW_WAIT_VALID_EHR_BIT(void)                                            \
    do {                                                                               \
        volatile uint32_t output_reg_val;                                              \
        for (output_reg_val = 0; output_reg_val < 2; output_reg_val++)                 \
            ;                                                                          \
        do {                                                                           \
            output_reg_val = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(RNG, TRNG_VALID)); \
        } while (output_reg_val == 0x0);                                               \
    } while (0)

/* Macros for indirect access to SRAM */

/* defining a macro to clear SRAM memory */

#ifdef __cplusplus
}
#endif

#endif
