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

#ifndef DX_RNG_PLAT_H
#define DX_RNG_PLAT_H

#include "crys_rnd_local.h"

/* ***************  Defines  ****************** */

/* NVM OTP TRNG defines */
#define RNG_PLAT_OTP_READ_ADDR   (0x1 << DX_HOST_AIB_ADDR_REG_READ_ACCESS_BIT_SHIFT)
#define RNG_PLAT_OTP_WRITE_ADDR  (0x1 << DX_HOST_AIB_ADDR_REG_WRITE_ACCESS_BIT_SHIFT)
#define RNG_PLAT_OTP_TRNG_MASK   0xfff00000UL
#define RNG_PLAT_OTP_TRNG_OFFSET (0x0A * sizeof(uint32_t)) /* DX_MNG_OTP_MANUFACTRER_FLAG_OFFSET */

/* TRNG filds offsets and masks  */
#define DX_RNG_OTP_ROSCS_ALLOWED_BIT_OFFSET   20
#define DX_RNG_OTP_ROSCS_ALLOWED_BIT_MASK     0x0FUL
#define DX_RNG_OTP_SUB_SAMPL_RATIO_BIT_OFFSET 24
#define DX_RNG_OTP_SUB_SAMPL_RATIO_BIT_MASK   0x7fUL
#define DX_RNG_OTP_SUB_SAMPL_RATIO_BIT_SIZE   7
#define DX_RNG_OTP_TRNG_MODE_BIT_OFFSET       31

#define DX_RNG_OTP_SUB_SAMPL_RATIO_MAX_VAL ((1UL << DX_RNG_OTP_SUB_SAMPL_RATIO_BIT_SIZE) - 1)

/* Default TRNG parameters: used when in OTP set 0 in appropriate bits */
#define DX_RNG_DEFAULT_TRNG_MODE          CRYS_RND_Fast
#define DX_RNG_DEFAULT_ROSCS_ALLOWED_FLAG 0xF

/* Default, increment and mininimal values, for Sampling Ratio */
/* On Fast mode */
#define DX_RNG_DEFAULT_SAMPL_RATIO_ON_FAST_MODE 30
#define DX_RNG_SAMPL_RATIO_INCREM_ON_FAST_MODE  1
#define DX_RNG_MIN_SAMPL_RATIO_ON_FAST_MODE     1
/* On  Slow mode */
#define DX_RNG_DEFAULT_SAMPL_RATIO_ON_SLOW_MODE 1000
#define DX_RNG_SAMPL_RATIO_INCREM_ON_SLOW_MODE  50
#define DX_RNG_MIN_SAMPL_RATIO_ON_SLOW_MODE     1000

/* Maximal value of SamplingRatio */
#define DX_RNG_MAX_SAMPL_RATIO_ON_FAST_MODE DX_RNG_OTP_SUB_SAMPL_RATIO_MAX_VAL
#define DX_RNG_MAX_SAMPL_RATIO_ON_SLOW_MODE \
    (DX_RNG_MIN_SAMPL_RATIO_ON_SLOW_MODE + DX_RNG_SAMPL_RATIO_INCREM_ON_SLOW_MODE * DX_RNG_OTP_SUB_SAMPL_RATIO_MAX_VAL)

/* Poll on the LCS valid register */
#define RNG_PLAT_WAIT_ON_LCS_VALID_BIT()                                                \
    do {                                                                                \
        uint32_t regValTT;                                                              \
        do {                                                                            \
            regValTT = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, LCS_IS_VALID)); \
        } while (!(regValTT & 0x1));                                                    \
    } while (0)

/* Poll on the AIB acknowledge bit */
#define RNG_PLAT_WAIT_ON_AIB_ACK_BIT()                                                  \
    do {                                                                                \
        uint32_t regValTT;                                                              \
        do {                                                                            \
            regValTT = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, AIB_FUSE_ACK)); \
        } while (!(regValTT & 0x1));                                                    \
    } while (0)

/* Read from the AIB  */
#define RNG_PLAT_READ_WORD_FROM_AIB(nvmAddr, nvmData)                                     \
    do {                                                                                  \
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_AIB_ADDR_REG), (nvmAddr)); \
        RNG_PLAT_WAIT_ON_AIB_ACK_BIT();                                                   \
        nvmData = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_AIB_RDATA_REG));  \
    } while (0)

/* !
 * @brief This function returns a word from the OTP according to a given address.
 *
 * @param[in] hwBaseAddress     - cryptocell base address
 * @param[in] otpAddress    - Address in OTP [in Bytes]
 * @param[out] otpWord        - the returned OTP word
 *
 * @return DxError_t         - On success: the value DX_OK is returned,
 *                       On failure: a value from sbrom_management_error.h
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
 * @param[out] rndState_ptr - The pointer to structure, containing PRNG data and
 *                            parameters.
 * @param[out] trngParams_ptr - The pointer to structure, containing parameters
 *                            of HW TRNG.
 *
 * @return CRYSError_t - no return value
 */
CRYSError_t RNG_PLAT_SetUserRngParameters(CRYS_RND_State_t *rndState_ptr, CRYS_RND_Params_t *trngParams_ptr);

#endif /* DX_RNG_PLAT_H */
