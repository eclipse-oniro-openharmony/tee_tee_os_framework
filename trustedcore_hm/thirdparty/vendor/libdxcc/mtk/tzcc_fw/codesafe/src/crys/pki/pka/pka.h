/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef PKA_H
#define PKA_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */

#include "ssi_pal_types.h"
#include "pka_error.h"
#include "pka_hw_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines **************************** */

/* values for defining, that PKA entry is not in use */
#define PKA_SIZE_ENTRY_NOT_USED    0xFFFFFFFF
#define PKA_ADDRESS_ENTRY_NOT_USED 0xFFC

/* difine result discard value */
#define RES_DISCARD 0x3F

/* **********************  Macros ***************************** */
#define PKA_SwapInt8(x, y) \
    {                      \
        uint32_t temp;     \
        temp = (x);        \
        x    = (y);        \
        y    = temp;       \
    }

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Public Variables ********************* */

/* *********************** Public Functions ********************* */

/* ******************************************************************************************** */
/* ******************************************************************************************** */
/*                                                                                             */
/*                FUNCTIONS PERFORMING ALGORITHMS and USED IN PKI                              */
/*                                                                                             */
/* ******************************************************************************************** */
/* ******************************************************************************************** */

/* ***************************************************************************** */
/* ************   Auxiliary functions used in PKA               **************** */
/* ***************************************************************************** */

/* **********      PKA_GetBitFromPkaReg     ******************** */
/*
 * @brief This function returns bit i from PKA register.
 *
 *
 * @param[in] rX       - Virtual pointer to PKA register.
 * @param[in] LenId    - ID of entry of regsSizesTable containing rX register length
 *                       with word extension.
 * @param[in] i        - number of bit to be tested.
 * @param[in] rT       - temp register. If it is not necessary to keep rX, then
 *                       set rT=rX for saving memory space.
 *
 * @return - returns the bit number i (counting from left).
 *
 */
uint8_t PKA_GetBitFromPkaReg(uint32_t rX, uint32_t LenID, int32_t i, uint32_t rT);

/* **********        PKA_ModDivideBy2            ******************** */
/*
 * @brief This function performs modular division by 2: rRes = rX / 2 mod rN.
 *
 * @param[in] LenId  - ID of entry of regsSizesTable containing rX modulus exact length.
 * @param[in] rX     - Virtual pointer to PKA register X.
 * @param[out] rN    - Virtual pointer to PKA register, containing the modulus N.
 * @param[out] rRes  - Virtual pointer to PKA register, containing the result.
 * @param[in] Tag    - The user defined value (Tag <= 31), used for indication goals.
 *
 * @return - no return parameters.
 *
 */
void PKA_ModDivideBy2(uint32_t LenID, uint32_t rX, uint32_t rN, uint32_t rRes, uint32_t Tag);

/* **************************************************************************************** */
/*
 *
 * Function name: LLF_PKI_RSA_Call_Div
 *
 * Description: This function performs division of big numbers, passed by physical pointers,
 *              using the PKA.
 *              .
 *     Computes modRes = A mod B. divRes_ptr = floor(A/B)
 *     Lengths: A[ALen], B[BLen], modRes[BLen], divRes[ALen].
 *     Assumes:  c > 0.
 *
 *     PKA registers using: A=>r2, B=>r3, divRes=>r4, modRes=>r2 (r2 is rewritten by remainder).
 *
 * Author: R.Levin
 *
 * Last Revision: 1.00.00
 *
 * @param[in] A_ptr          - The pointer to numerator A vector.
 * @param[in] ASizeInWords   - Length of numerator A in words.
 * @param[in] B_ptr          - The pointer to divider B (modulus).
 * @param[in] BSizeInWords   - The size of B vector in words.
 * @param[out] modRes_ptr    - The pointer to modulus result (reminder of division).
 * @param[out] divRes_ptr    - The pointer to result of division.
 * @param[in] tempBuff_ptr   - The pointer to temp buffer - not used, may be set NULL.
 *
 * @return  - no return value
 *
 * Update History:
 * Rev 1.00.00, Date 4 Feb. 2008,
 *
 */

SaSiError_t LLF_PKI_RSA_Call_Div(uint32_t *A_ptr, uint32_t ASizeInWords, uint32_t *B_ptr, uint32_t BSizeInWords,
                                 uint32_t *modRes_ptr, uint32_t *divRes_ptr, uint32_t *tempBuff_ptr);

/* **************************************************************************************** */
/*
 *
 * Function name: LLF_PKI_RSA_CallRMul
 *
 * Description: This function performs multiplication of big numbers, passed by physical
 *              pointers, using the PKA.
 *
 *        The RMul operation is : (A * B)
 *
 *        The function performs the following algorithm:
 *
 *
 * @param[in] A_ptr       - The pointer of A words array (LS word is left most).
 * @param[in] B_ptr       - The pointer of B words array (LS word is left most).
 * @param[in] ASizeInBits - The size of vectors in bits.
 * @param[out] Res_ptr    - The pointer to the result buffer.
 *
 * @return SaSiError_t - SaSi_OK
 */
SaSiError_t LLF_PKI_RSA_CallRMul(uint32_t *A_ptr, uint32_t ASizeInBits, uint32_t *B_ptr, uint32_t *Res_ptr);

SaSiError_t PKA_InitAndMutexLock(uint32_t sizeInBits, uint32_t *pkaRegCount);
void PKA_FinishAndMutexUnlock(uint32_t pkaRegCount);
void PKA_SetLenIds(uint32_t sizeInBits, uint32_t lenId);
void PKA_ClearAllPka(void);

/* !
 * The function performs conditional swapping of two values in secure
 * mode
 *
 * if(swp == 1) {tmp = *x; *x = *y; *y = tmp;}
 *
 * \param x  - the pointer to x-variable
 * \param y  - the pointer to y-variable
 * \param swp - swapping condition [0,1]
 */
void PKA_ConditionalSecureSwapUint32(uint32_t *x, uint32_t *y, uint32_t swp);

#ifdef __cplusplus
}
#endif

#endif
