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

#ifndef LLF__PKI_RSA_H
#define LLF__PKI_RSA_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */
#include "dx_pal_types.h"
#include "sw_llf_pki_error.h"
#include "llf_pki_util.h"
#ifdef DX_SOFT_KEYGEN
#include "ccsw_crys_rsa_types.h"
#else
#include "crys_rsa_types.h"
#include "sw_crys_rsa_types_conv.h"
#endif

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
 *  \version sw_llf_pki_rsa.h#1:incl:1
 *  \author adams
 */

/* *********************** Defines **************************** */

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions **************************** */

/* *****************************************************************************************
 * @brief This function initializes the low level key database public structure.
 *        On the Lite platform the Hn vector is initialized
 *
 *
 * @param[in] LLFSpesificParams - spesific parameters required on this LLF implementation.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t SW_LLF_PKI_RSA_InitPubKeyDb(SW_CRYSRSAPubKey_t *PubKey_ptr);

/* *****************************************************************************************
 * @brief This function initializes the low level key database private structure.
 *        On the Lite platform the Hn vector is initialized
 *
 *
 * @param[in] LLFSpesificParams - spesific parameters required on this LLF implementation.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t SW_LLF_PKI_RSA_InitPrivKeyDb(SW_CRYSRSAPrivKey_t *PrivKey_ptr);

/* *****************************************************************************************
 * @brief This function executes the RSA primitive public key exponent engine
 *
 *
 * @param[in] PubKey_ptr - the public key database.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t SW_LLF_PKI_RSA_ExecPubKeyExp(SW_CRYSRSAPubKey_t *PubKey_ptr, SW_CRYS_RSAPrimeData_t *PubData_ptr);

/* *****************************************************************************************
 * @brief This function executes the RSA primitive private key exponent engine
 *
 *
 * @param[in] PubKey_ptr - the private key database.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t SW_LLF_PKI_RSA_ExecPrivKeyExp(SW_CRYSRSAPrivKey_t *PrivKey_ptr, SW_CRYS_RSAPrimeData_t *PrivData_ptr);

/* *****************************************************************************************
 * @brief This function generates a key pair
 *
 *
 * @param[in] PubKey_ptr - the public key database.
 * @param[in] PrivKey_ptr - the private key database.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t SW_LLF_PKI_RSA_GenerateKeyPair(SW_CRYSRSAPubKey_t *PubKey_ptr, SW_CRYSRSAPrivKey_t *PrivKey_ptr,
                                           SW_CRYS_RSAKGData_t *KeyGenData_ptr);

/* *****************************************************************************************
 * @brief This function calculates the N using P,Q ( CRT ) : N = P*Q
 *
 *
 * @param[in] P_ptr - the first prime.
 * @param[in] P_SizeInBits - the first prime size in bits.
 * @param[in] Q_ptr - the second prime.
 * @param[in] Q_SizeInBits - the second prime size in bits.
 * @param[in] N_ptr        - the N vector.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t SW_LLF_PKI_RSA_CRTCalcN(uint32_t *P_ptr, uint32_t PSizeInBits, uint32_t *Q_ptr, uint32_t QSizeInBits,
                                    uint32_t *N_ptr);

/* ******************************************************************************************
 * @brief This function is used to test a primality according to ANSI X9.42 standard.
 *
 *        The function calls the SW_LLF_PKI_primeTest function which performs said algorithm.
 *
 * @param[in] P_ptr           - The pointer to the prime buff.
 * @param[in] sizeWords       - The prime size in words.
 * @param[in] rabinTestsCount - The count of Rabin-Miller tests repetition.
 * @param[in] isPrime         - The flag indicates primality:
 *                                  if is not prime - PLS_FALSE, otherwise - PLS_TRUE.
 * @param[in] TempBuff_ptr   - The temp buffer of minimum size:
 *                               - on HW platform  8*MaxModSizeWords,
 *                               - on SW platform  41*MaxModSizeWords.
 * @param[in] primeTestMode - primality testing mode (RSA or DH - defines how are performed some
 *            operations on temp buffers.
 */
CRYSError_t SW_LLF_PKI_PrimeTestCall(uint32_t *P_ptr, int32_t sizeWords, int32_t rabinTestsCount, int8_t *isPrime_ptr,
                                     uint32_t *TempBuff_ptr, CRYS_RSA_DH_PrimeTestMode_t primeTestMode);

#define SW_LLF_PKI_RSA_primeTestCall SW_LLF_PKI_PrimeTestCall

#ifdef __cplusplus
}
#endif

#endif
