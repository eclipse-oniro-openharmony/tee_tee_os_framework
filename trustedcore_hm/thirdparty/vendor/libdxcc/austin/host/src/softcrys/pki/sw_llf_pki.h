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

#ifndef SW_LLF_PKI_H
#define SW_LLF_PKI_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */

#include "dx_pal_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Object %name    : %
 *  State           :  %state%
 *  Creation date   :  Wed Nov 17 17:39:48 2004
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief A brief description of this module
 *
 *  \version LLF_PKI.h#1:incl:1
 *  \author adams
 */

/* *********************** Defines **************************** */

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  *************************** */

/* *********************** Public Variables ******************* */

/* *********************** Public Functions ******************* */

/*
 * @brief The LLF_PKI_UTIL_CalcExponentCrt calculates The exponent on the CRT mode.
 *        it does the following:
 *
 *                   m1 = (Base ^ dP) mod P.
 *                   m2 = (Base ^ dQ) mod Q.
 *                   h = (m1 - m2) * Qinv mod P
 *                   res = m2 + qh
 *
 * @Base_ptr[in]         - The pointer to the base buffer.
 * @BaseSizeInBits[in]   - The size of the base value in bits.
 * @N_ptr[in]            - The pointer to the modulus buffer.
 * @NSizeInBits[in]      - The modulus size in bits.
 * @P_ptr[in]            - The pointer to the first factor buffer.
 * @PSizeInBits          - The first factor size in bits.
 * @Q_ptr[in]            - The pointer to the second factor buffer.
 * @QSizeInBits          - The second factor size in bits.
 * @Qinv_ptr             - The pointer to the coefficient.
 * @QinvSizeInBits       - The coefficient size in bits.
 * @TempBuff1_ptr[in]    - temporary buffer
 * @TempBuff2_ptr[in]    - temporary buffer
 * @Res_ptr[out]         - The pointer to the buffer that will contain the result.
 *
 * @Output_ptr[in,out] The output vector.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CRYSError_t LLF_PKI_UTIL_CalcExponentCrt(uint32_t *Base_ptr, uint32_t BaseSizeInBits, uint32_t *N_ptr,
                                         uint32_t NSizeInBits, uint32_t *P_ptr, uint32_t PSizeInBits, uint32_t *Q_ptr,
                                         uint32_t QSizeInBits, uint32_t *dP_ptr, uint32_t dPSizeInBits,
                                         uint32_t *dQ_ptr, uint32_t dQSizeInBits, uint32_t *Qinv_ptr,
                                         uint32_t QinvSizeInBits, uint32_t *TempBuff1_ptr, uint32_t *TempBuff2_ptr,
                                         uint32_t *Res_ptr);

/* *********************************************************************************** */
/*
 * @brief The SW_LLF_PKI_genKey calculates generates a public and private keys
 *
 *
 * @param[in] Prime1Random_ptr   - first prime random number - set at the beginning.
 * @param[in] Prime2Random_ptr   - second prime random number - set at the beginning.
 * @param[in] e_ptr              - The pointer to the public exponent.
 * @param[in] eLenInWords        - The public exponent size in words.
 * @param[out] n_ptr             - The pointer to the public key modulus .
 * @param[in] nLenInWords        - The required size of the key in words.
 * @param[out] d_ptr             - The pointer to the private exponent ( non CRT ).
 * @param[out] p_ptr             - The first factor pointer.
 * @param[out] q_ptr             - The second factor pointer.
 * @param[out] dp_ptr            - The first factor exp pointer only on CRT.
 * @param[out] dq_ptr            - The second factor exp pointer only on CRT.
 * @param[out] qinv_ptr          - The first coefficient - CRT
 * @param[in]  temp buffer       - temporary buffer.
 * @param[in]  IsCrtMode         - PLS_TRUE - CRT mode , PLS_FALSE - non CRT mode.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CRYSError_t SW_LLF_PKI_genKey(uint32_t *e_ptr, uint32_t eLenInWords, uint32_t *n_ptr, uint32_t nLenInWords,
                              uint32_t *d_ptr, uint32_t *p_ptr, uint32_t *q_ptr, uint32_t *dp_ptr, uint32_t *dq_ptr,
                              uint32_t *qinv_ptr, uint32_t *temp_ptr, uint32_t IsCrtMode);

/* *********************************************************************************** */

#ifdef __cplusplus
}
#endif

#endif
