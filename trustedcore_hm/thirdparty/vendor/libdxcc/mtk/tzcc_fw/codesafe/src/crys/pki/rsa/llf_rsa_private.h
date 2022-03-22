/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef LLF_RSA_PRIVATE_H
#define LLF_RSA_PRIVATE_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */

#include "sasi_error.h"
#include "sasi_rsa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef union { // taken from llf_pki_priv_key_db_defs.h
    struct {
        /* the Barrett mod N tag  NP for N-modulus - used in the modular multiplication and
          exponentiation, calculated in SaSi_RSA_Build_PrivKey_MTK function */
        uint32_t NP[SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS];

    } NonCrt;

    struct {
        /* the Barrett mod P tag  PP for P-factor - used in the modular multiplication and
          exponentiation, calculated in SaSi_RSA_Build_PrivKey_MTK function */
        uint32_t PP[SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS];

        /* the Barrett mod Q tag  QP for Q-factor - used in the modular multiplication and
          exponentiation, calculated in SaSi_RSA_Build_PubKey_MTK function */
        uint32_t QP[SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS];

    } Crt;

} LLF_pki_priv_key_db_t;

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions **************************** */

/* **************************************************************************************** */
/*
 * @brief This function initializes the low level key database private structure.
 *        On the HW platform the Barrett tag is initialized
 *
 *
 * @param[in] PrivKey_ptr - The pointer to private key structure.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
SaSiError_t LLF_PKI_RSA_InitPrivKeyDb(SaSiRSAPrivKey_t *PrivKey_ptr);

/* **************************************************************************************** */
/*
 * @brief This function executes the RSA private key exponentiation
 *
 *    Algorithm [PKCS #1 v2.1]:
 *
 *     1. If NonCRT exponent, then  M  =  C^D  mod N.
 *
 *     2. If CRT exponent, then:
 *        2.1. M1  =  C^dP mod P,
 *        2.2. M2  =  C^dQ mod Q;
 *        2.3  h = (M1-M2)*qInv mod P;
 *        2.4. M = M2 + Q * h.
 *
 *     Where: M- message representative, C- ciphertext, N- modulus,
 *            P,Q,dP,dQ, qInv - CRT private key parameters;
 *            ^ - exponentiation symbol.
 *
 *     Note: PKA registers used: NonCrt: r0-r4,   r30,r31, size of registers - Nsize;
 *                               Crt:    r0-r10,  r30,r31, size of registers - Nsize;
 *
 * @param[in] PubKey_ptr - the private key database.
 * @param[in/out] PrivData_ptr - the structure, containing DataIn and DataOut buffers.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
SaSiError_t LLF_PKI_RSA_ExecPrivKeyExp(SaSiRSAPrivKey_t *PrivKey_ptr, SaSi_RSAPrimeData_t *PrivData_ptr);

#ifdef __cplusplus
}
#endif

#endif
