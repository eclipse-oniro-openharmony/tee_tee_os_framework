/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */

#include "sasi_rsa_error.h"
#include "llf_rsa_public.h"
#include "sasi_rsa_types.h"
#include "pka.h"
#include "pka_export.h"
#include "ssi_pal_mutex.h"
#include "pka_error.h"

/* *********************** Defines ********************************* */
/* *********************** Enums *********************************** */
/* *********************** Typedefs ******************************** */
/* *********************** Global Data ***************************** */

/* ***************** External functions propotypes **************** */

/* ************ Private functions prototypes *********************** */

/* ************ Exported functions prototypes ********************** */
extern const int8_t regTemps[PKA_MAX_COUNT_OF_PHYS_MEM_REGS];

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
SaSiError_t LLF_PKI_RSA_InitPubKeyDb(SaSiRSAPubKey_t *pPubKey)
{
    /* error identification */
    SaSiError_t Error = SaSi_OK;

    if (pPubKey == NULL) {
        return SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;
    }

    /* calculate Barrett tag NP by initialization PKA for modular operations.
       Default settings: N=PKA_REG_N, NP=PKA_REG_NP, T0=30, T1=31.
       Our settings for temps: rT0=2, rT1=3, rT2=4 */
    Error = PKA_CalcNp(((host_rsa_pub_key_db_t *)(pPubKey->sasiRSAIntBuff))->NP, /* out */
                       pPubKey->n,                                               /* in */
                       pPubKey->nSizeInBits);

    return Error;

} /* END OF HostRsaInitPubKeyDb */

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

SaSiError_t LLF_PKI_RSA_ExecPubKeyExp(SaSiRSAPubKey_t *pPubKey, SaSi_RSAPrimeData_t *pPubData)
{
    /* error identification */
    SaSiError_t Error = SaSi_OK;

    /* modulus and exponent sizes in bytes */
    uint32_t nSizeInWords, eSizeInWords;
    uint32_t pkaReqRegs = 7;

    uint8_t rT2 = regTemps[2];
    uint8_t rT3 = regTemps[3];
    uint8_t rT4 = regTemps[4];

    /* FUNCTION LOGIC */

    /* .................... initialize local variables ...................... */
    /* ---------------------------------------------------------------------- */

    /* modulus size in bytes */
    nSizeInWords = CALC_FULL_32BIT_WORDS(pPubKey->nSizeInBits);
    eSizeInWords = CALC_FULL_32BIT_WORDS(pPubKey->eSizeInBits);

    /* ............... getting the hardware semaphore ..................... */
    /* -------------------------------------------------------------------- */

    Error = PKA_InitAndMutexLock(pPubKey->nSizeInBits, &pkaReqRegs);
    if (Error != SaSi_OK) {
        return Error;
    }

    /* copy modulus N into r0 register */
    PKA_CopyDataIntoPkaReg(PKA_REG_N /* dstReg */, LEN_ID_MAX_BITS /* LenID */, pPubKey->n /* srcPtr */, nSizeInWords);

    /* copy the NP into r1 register NP */
    PKA_CopyDataIntoPkaReg(PKA_REG_NP /* dstReg */, LEN_ID_MAX_BITS /* LenID */,
                           ((host_rsa_pub_key_db_t *)(pPubKey->sasiRSAIntBuff))->NP /* srcPtr */,
                           SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);

    /* copy input data into PKI register: DataIn=>r2 */
    PKA_CopyDataIntoPkaReg(rT2 /* dstReg */, LEN_ID_MAX_BITS /* LenID */, pPubData->DataIn, nSizeInWords);

    /* copy exponent data PKI register: e=>r3 */
    PKA_CopyDataIntoPkaReg(rT3 /* dstReg */, LEN_ID_MAX_BITS /* LenID */, pPubKey->e, eSizeInWords);

    /* .. calculate the exponent Res = OpA**OpB mod N;                  ... */
    /* -------------------------------------------------------------------- */
    PKA_MOD_EXP(LEN_ID_N_BITS /* LenID */, rT4 /* Res */, rT2 /* OpA */, rT3 /* OpB */);

    /* copy result into output: r4 =>DataOut */
    PKA_CopyDataFromPkaReg(pPubData->DataOut, nSizeInWords, rT4 /* srcReg */);

    PKA_FinishAndMutexUnlock(pkaReqRegs);

    return Error;
} /* END OF HostRsaExecPubKeyExp */
