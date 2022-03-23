/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_RNG_PLAT_H
#define _SSI_RNG_PLAT_H

#include "sasi_rnd_local.h"
#include "cc_plat.h"

/* ***************  Defines  ****************** */

/* NVM OTP TRNG defines */
#define RNG_PLAT_OTP_READ_ADDR   (0x1 << DX_HOST_AIB_ADDR_REG_READ_ACCESS_BIT_SHIFT)
#define RNG_PLAT_OTP_WRITE_ADDR  (0x1 << DX_HOST_AIB_ADDR_REG_WRITE_ACCESS_BIT_SHIFT)
#define RNG_PLAT_OTP_TRNG_MASK   0xfff00000UL
#define RNG_PLAT_OTP_TRNG_OFFSET (0x0A * sizeof(uint32_t)) /* SASI_OTP_MANUFACTURE_FLAG_OFFSET */

/* TRNG filds offsets and masks  */
#define SASI_RNG_OTP_ROSCS_ALLOWED_BIT_OFFSET   20
#define SASI_RNG_OTP_ROSCS_ALLOWED_BIT_MASK     0x0FUL
#define SASI_RNG_OTP_SUB_SAMPL_RATIO_BIT_OFFSET 24
#define SASI_RNG_OTP_SUB_SAMPL_RATIO_BIT_MASK   0x7fUL
#define SASI_RNG_OTP_SUB_SAMPL_RATIO_BIT_SIZE   7
#define SASI_RNG_OTP_TRNG_MODE_BIT_OFFSET       31

#define SASI_RNG_OTP_SUB_SAMPL_RATIO_MAX_VAL ((1UL << SASI_RNG_OTP_SUB_SAMPL_RATIO_BIT_SIZE) - 1)

/* Default TRNG parameters: used when in OTP set 0 in appropriate bits */
#define SASI_RNG_DEFAULT_TRNG_MODE          SaSi_RND_SWEE
#define SASI_RNG_DEFAULT_ROSCS_ALLOWED_FLAG 0xF

/* Default, increment and mininimal values, for Sampling Ratio */
/* On Fast mode */
#define SASI_RNG_DEFAULT_SAMPL_RATIO_ON_SWEE_MODE 30
#define SASI_RNG_SAMPL_RATIO_INCREM_ON_SWEE_MODE  1
#define SASI_RNG_MIN_SAMPL_RATIO_ON_SWEE_MODE     1
/* On  Slow mode */
#define SASI_RNG_DEFAULT_SAMPL_RATIO_ON_FE_MODE 1000
#define SASI_RNG_SAMPL_RATIO_INCREM_ON_FE_MODE  50
#define SASI_RNG_MIN_SAMPL_RATIO_ON_FE_MODE     1000

/* Maximal value of SamplingRatio */
#define SASI_RNG_MAX_SAMPL_RATIO_ON_SWEE_MODE SASI_RNG_OTP_SUB_SAMPL_RATIO_MAX_VAL
#define SASI_RNG_MAX_SAMPL_RATIO_ON_FE_MODE \
    (SASI_RNG_MIN_SAMPL_RATIO_ON_FE_MODE +  \
     SASI_RNG_SAMPL_RATIO_INCREM_ON_FE_MODE * SASI_RNG_OTP_SUB_SAMPL_RATIO_MAX_VAL)

/* Poll on the LCS valid register */
#define RNG_PLAT_WAIT_ON_LCS_VALID_BIT()                                                \
    do {                                                                                \
        uint32_t regValTT;                                                              \
        do {                                                                            \
            regValTT = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, LCS_IS_VALID)); \
        } while (!(regValTT & 0x1));                                                    \
    } while (0)

/* Poll on the AIB acknowledge bit */
#define RNG_PLAT_WAIT_ON_AIB_ACK_BIT()                                                  \
    do {                                                                                \
        uint32_t regValTT;                                                              \
        do {                                                                            \
            regValTT = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, AIB_FUSE_ACK)); \
        } while (!(regValTT & 0x1));                                                    \
    } while (0)

/* Read from the AIB  */
#define RNG_PLAT_READ_WORD_FROM_AIB(nvmAddr, nvmData)                                     \
    do {                                                                                  \
        SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_AIB_ADDR_REG), (nvmAddr)); \
        RNG_PLAT_WAIT_ON_AIB_ACK_BIT();                                                   \
        nvmData = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_AIB_RDATA_REG));  \
    } while (0)

/* !
 * @brief This function returns a word from the OTP according to a given address.
 *
 * @param[in] hwBaseAddress     - CryptoCell base address
 * @param[in] otpAddress    - Address in OTP [in Bytes]
 * @param[out] otpWord        - the returned OTP word
 *
 * @return SaSiError_t         - On success: the value DX_OK is returned,
 *                       On failure: a value from sbrom_bsv_error.h
 */
#define RNG_PLAT_READ_OTP(regVal)                                                                 \
    do {                                                                                          \
        RNG_PLAT_WAIT_ON_LCS_VALID_BIT();                                                         \
        RNG_PLAT_READ_WORD_FROM_AIB(RNG_PLAT_OTP_TRNG_OFFSET | RNG_PLAT_OTP_READ_ADDR, (regVal)); \
    } while (0)

/* ************************************************************************************* */
/*
 *
 * @brief The function retrievess the TRNG parameters, provided by the User trough NVM,
 *        and sets them into structures given by pointers rndState_ptr and trngParams_ptr.
 *
 * @author reuvenl (6/26/2012)
 *
 * @param[in/out] pRndState  - Pointer to the RND context buffer.
 * @param[out] pTrngParams - The pointer to structure, containing parameters
 *                            of HW TRNG.
 *
 * @return SaSiError_t - no return value
 */
SaSiError_t RNG_PLAT_SetUserRngParameters(SaSi_RND_State_t *pRndState, SaSi_RND_Params_t *pTrngParams);

#endif /* _SSI_RNG_PLAT_H */
