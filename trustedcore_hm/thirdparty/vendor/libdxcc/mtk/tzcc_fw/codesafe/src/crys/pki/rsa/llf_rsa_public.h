/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef LLF_RSA_PUBLIC_H
#define LLF_RSA_PUBLIC_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */

#include "sasi_error.h"
#include "sasi_rsa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* the Barrett mod tag  NP for N-modulus - used in the modular multiplication and
       exponentiation, calculated in SaSi_RSA_Build_PrivKey_MTK function */
    uint32_t NP[SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS];
} host_rsa_pub_key_db_t;

/* *********************** Public Variables ******************** */

/* *********************** Public Functions **************************** */

/* **************************************************************************************** */
/*
 * @brief This function executes the RSA primitive public key exponent :
 *
 *    pPubData->DataOut =  pPubData->DataIn ** pPubKey->e  mod  pPubKey->n,
 *    where: ** - exponent symbol.
 *
 *    Note: PKA registers used: r0-r4,   r30,r31, size of registers - Nsize.
 *
 * @param[in] pPubKey  - The public key database.
 * @param[in] pPubData - The structure, containing input data and output buffer.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */

SaSiError_t LLF_PKI_RSA_ExecPubKeyExp(SaSiRSAPubKey_t *pPubKey, SaSi_RSAPrimeData_t *pPubData);

/* **************************************************************************************** */
/*
 * @brief This function initializes the low level key database public structure.
 *        On the HW platform the Barrett tag is initialized
 *
 *
 * @param[in] pPubKey - The pointer to public key structure.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
SaSiError_t LLF_PKI_RSA_InitPubKeyDb(SaSiRSAPubKey_t *pPubKey);

#ifdef __cplusplus
}
#endif

#endif
