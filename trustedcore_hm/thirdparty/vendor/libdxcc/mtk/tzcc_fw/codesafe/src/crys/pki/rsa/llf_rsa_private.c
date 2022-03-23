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
#include "sasi_rsa_types.h"
#include "pka.h"
#include "pka_export.h"
#include "ssi_pal_mutex.h"
#include "pka_error.h"
#include "sasi_rnd.h"
#include "llf_rsa.h"
#include "llf_rsa_private.h"

/* *********************** Defines ********************************* */
extern const int8_t regTemps[PKA_MAX_COUNT_OF_PHYS_MEM_REGS];
/* *********************** Global Data ***************************** */

/* ***************** External functions propotypes **************** */

/* ************ Private functions prototypes *********************** */

/* **************************************************************************************** */
/*
 * @brief This function executes the RSA primitive: private key CRT exponent
 *
 *    Algorithm [PKCS #1 v2.1]:
 *
 *     1. If NonCRT exponent, then  M  =  C^D  mod N.
 *
 *     Where: M- message representative, C- ciphertext, D- priv.exponent, N- modulus,
 *            ^ - exponentiation symbol.
 *
 *     Note: PKA registers used: r0,r1,r2,r3,r4,  r30,r31.
 *
 * @param[in]     PubKey_ptr    - the private key database.
 * @param[in/out] PrivData_ptr  - the structure, containing DataIn and DataOut buffers.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
static SaSiError_t PKI_ExecPrivKeyExpNonCrt(SaSiRSAPrivKey_t *PrivKey_ptr, SaSi_RSAPrimeData_t *PrivData_ptr)
{
    /* LOCAL DECLARATIONS */

    /* error identification */
    SaSiError_t Error = SaSi_OK;

    /* modulus and exponents sizes in bytes */
    uint32_t modSizeWords, dSizeInWords;
    uint32_t pkaReqRegs = 7;

    /* FUNCTION LOGIC */
    /* set virtual registers pointers  */
    uint8_t rT2 = regTemps[2]; /* 2 */
    uint8_t rT3 = regTemps[3]; /* 3 */
    uint8_t rT4 = regTemps[4]; /* 4 */

    /* .................... initialize local variables ...................... */
    /* ---------------------------------------------------------------------- */

    /* modulus N size in bytes */
    modSizeWords = CALC_FULL_32BIT_WORDS(PrivKey_ptr->nSizeInBits);

    /* priv. exponent size in bytes */
    dSizeInWords = CALC_FULL_32BIT_WORDS(PrivKey_ptr->PriveKeyDb.NonCrt.dSizeInBits);

    Error = PKA_InitAndMutexLock(PrivKey_ptr->nSizeInBits, &pkaReqRegs);
    if (Error != SaSi_OK) {
        return Error;
    }

    /* -------------------------------------------------------------------- */
    /*      copy the N, Np DataIn and D into PKA registers                  */
    /* -------------------------------------------------------------------- */
    /* N => r0 */
    /* copy modulus N into PKA register: N=>r0 */
    PKA_CopyDataIntoPkaReg(PKA_REG_N /* dstReg */, LEN_ID_MAX_BITS /* LenID */, PrivKey_ptr->n /* srcPtr */, modSizeWords);

    /* copy the NP into r1 register NP */
    PKA_CopyDataIntoPkaReg(PKA_REG_NP /* dstReg */, LEN_ID_MAX_BITS /* LenID */,
                           ((LLF_pki_priv_key_db_t *)(PrivKey_ptr->sasiRSAPrivKeyIntBuff))->NonCrt.NP /* srcPtr */,
                           SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);

    /* copy input data into PKI register: DataIn=>r2 */
    PKA_CopyDataIntoPkaReg(rT2 /* dstReg */, LEN_ID_MAX_BITS /* LenID */, PrivData_ptr->DataIn, modSizeWords);

    /* copy input data into PKI register: DataIn=>r2 */
    PKA_CopyDataIntoPkaReg(rT3 /* dstReg */, LEN_ID_MAX_BITS /* LenID */, PrivKey_ptr->PriveKeyDb.NonCrt.d, dSizeInWords);

    /* .. calculate the exponent Res = DataIn^D mod N;                  ... */
    /* -------------------------------------------------------------------- */
    PKA_MOD_EXP(LEN_ID_N_BITS /* LenID */, rT4 /* Res */, rT2 /* OpA */, rT3 /* OpB */);

    /* ----------------------------- */
    /*  Finish PKA and copy result */
    /* ----------------------------- */

    /* copy result into output buffer */
    /* copy result into output: r4 =>DataOut */
    PKA_CopyDataFromPkaReg(PrivData_ptr->DataOut, modSizeWords, rT4 /* srcReg */);

    PKA_FinishAndMutexUnlock(pkaReqRegs);

    return Error;

} /* END OF PKI_ExecPrivKeyExpNonCrt */

/* **************************************************************************************** */
/*
 * @brief This function executes the RSA primitive: private key CRT exponent.
 *        adapted for Keys up to 2K bits size.
 *
 *    Algorithm [PKCS #1 v2.1]:
 *
 *   CRT exponentiation algorithm:
 *        1. Mq  =  C^dQ mod Q;
 *        2. Mp  =  C ^dP mod P,
 *        3  h = (Mp-Mq)*qInv mod P;
 *        4. M = Mq + Q * h.
 *
 *     Where: M- message representative, C- ciphertext, D- priv.exponent, N- modulus,
 *            P,Q,dP,dQ, qInv - CRT private key parameters;
 *            ^ - exponentiation symbol.
 *
 *     Note: 9 PKA registers are used: r0-r6,  r30,r31.
 *
 * @param[in]     PubKey_ptr    - the private key database.
 * @param[in/out] PrivData_ptr  - the structure, containing DataIn and DataOut buffers.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
static SaSiError_t PKI_ExecPrivKeyExpCrt(SaSiRSAPrivKey_t *PrivKey_ptr, SaSi_RSAPrimeData_t *PrivData_ptr)

{
    /* LOCAL DECLARATIONS */
    /* error identification */
    SaSiError_t Error = SaSi_OK;

    /* modulus and exponents sizes in bytes */
    uint32_t modSizeWords, PQSizeInWords;
    uint32_t pkaReqRegs = 10;

    /* virtual registers pointers
       Note: don't change rQ = 6  */
    int8_t rN    = PKA_REG_N;
    int8_t rNP   = PKA_REG_NP;
    int8_t rD    = regTemps[2];
    int8_t rT    = regTemps[3];
    int8_t rT1   = regTemps[4];
    int8_t rMq   = regTemps[5];
    int8_t rQ    = regTemps[6];
    int8_t rqInv = regTemps[7];

    /* FUNCTION LOGIC */

    /* ---------------------------------------------------------------------- */
    /* .................... initializations            ...................... */
    /* ---------------------------------------------------------------------- */

    /* modulus N size in bytes */
    modSizeWords = CALC_FULL_32BIT_WORDS(PrivKey_ptr->nSizeInBits);

    Error = PKA_InitAndMutexLock(PrivKey_ptr->nSizeInBits, &pkaReqRegs);
    if (Error != SaSi_OK) {
        return Error;
    }

    /*  set Sizes table: 0- Nsize, 1- Nsize+1w (is done), 2- Psize  */
    PKA_SetLenIds(PrivKey_ptr->PriveKeyDb.Crt.PSizeInBits, LEN_ID_PQ_BITS);

    /* P and Q size in bytes */
    PQSizeInWords = CALC_FULL_32BIT_WORDS(PrivKey_ptr->PriveKeyDb.Crt.PSizeInBits);

    /* -------------------------------------------------------------- */
    /* PKA modular operations  according to modulus Q:              */
    /* -------------------------------------------------------------- */

    /* copy CRT parametersrs Q, dQ, QP into PKA registers */
    PKA_CopyDataIntoPkaReg(rN /* 0 dstReg */, LEN_ID_MAX_BITS /* LenID */, PrivKey_ptr->PriveKeyDb.Crt.Q /* src_ptr */,
                           PQSizeInWords);

    PKA_CopyDataIntoPkaReg(rD /* 2 dstReg */, LEN_ID_MAX_BITS /* LenID */, PrivKey_ptr->PriveKeyDb.Crt.dQ /* src_ptr */,
                           PQSizeInWords);

    PKA_CopyDataIntoPkaReg(rNP /* 1 dstReg */, LEN_ID_MAX_BITS /* LenID */,
                           ((LLF_pki_priv_key_db_t *)(PrivKey_ptr->sasiRSAPrivKeyIntBuff))->Crt.QP /* src_ptr */,
                           SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);
    /* copy DataIn into rT and rT! */
    PKA_CopyDataIntoPkaReg(rT /* 3 dstReg */, LEN_ID_MAX_BITS /* LenID */, PrivData_ptr->DataIn /* src_ptr */, modSizeWords);
    PKA_COPY(LEN_ID_MAX_BITS /* LenID */, rT1 /* 4 dest */, rT /* 3 src */);

    /* ----------------------------- */
    /*  Calculation of Mq          */
    /* ----------------------------- */
    /* reduction of the input data by modulus Q  rT = rT mod Q */
    PKA_DIV(LEN_ID_N_PKA_REG_BITS /* LenID */, rQ /* 6 Res not used */, rT /* 3 OpA */, rN /* 0 OpB=rN=Q */);

    /* operation changes from p/q size to N size, need clearing rT high bits */

    /*  calculate of Mq = DataIn^dQ mod Q: Mq = rT^rD mod rN        */
    PKA_MOD_EXP(LEN_ID_PQ_BITS /* LenID */, rMq /* 5 Res */, rT /* 3 OpA */, rD /* 2 OpB */);

    /* -------------------------------------------------------------- */
    /* PKA modular operations  according to modulus P:              */
    /* -------------------------------------------------------------- */

    /* copy prime factor P into rQ for swapping with rN */
    PKA_CopyDataIntoPkaReg(rQ /* 6 dstReg */, LEN_ID_MAX_BITS /* LenID */, PrivKey_ptr->PriveKeyDb.Crt.P /* src_ptr */,
                           PQSizeInWords);
    /* swap rQ <-> rN so that Q->rQ and P->rN */
    rQ = PKA_REG_N;
    rN = 6;

    /* set new value to N_NP_TO_T1 register according N->6, Np->1,T0->30,T1->31: 0x000FF826 */
    PKA_Set_N_NP_T0_T1_Reg(rN, PKA_REG_NP, PKA_REG_T0, PKA_REG_T1);

    /* copy Barrett tag PP: PP=>NP */
    PKA_CopyDataIntoPkaReg(rNP /* 1 dstReg */, LEN_ID_MAX_BITS /* LenID */,
                           ((LLF_pki_priv_key_db_t *)(PrivKey_ptr->sasiRSAPrivKeyIntBuff))->Crt.PP /* src_ptr */,
                           SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);

    /* copy priv. exponent factor dP: dP=>rD */
    PKA_CopyDataIntoPkaReg(rD /* 2 dstReg */, LEN_ID_MAX_BITS /* LenID */, PrivKey_ptr->PriveKeyDb.Crt.dP /* src_ptr */,
                           PQSizeInWords);

    /* copy qInv coefficient: qInv=>rqInv   */
    PKA_CopyDataIntoPkaReg(rqInv /* 7 dstReg */, LEN_ID_MAX_BITS /* LenID */, PrivKey_ptr->PriveKeyDb.Crt.qInv /* src_ptr */,
                           PQSizeInWords);

    /* ----------------------------- */
    /*  Calculation of Mp          */
    /* ----------------------------- */
    /* reduction of input data by modulus P:  rT = rT1 mod P  */
    PKA_DIV(LEN_ID_N_PKA_REG_BITS /* LenID */, rT /* 3 res not used */, rT1 /* 4 OpA and remainder */, rN /* 0 OpB */);

    /* operation changes from p/q size to N size, need clearing registers high bits */

    /* calculate exponent Mp = DataIn^dP mod P , i.e: rT = rT1^rD mod rP  */
    PKA_MOD_EXP(LEN_ID_PQ_BITS /* LenID */, rT /* 3 Res */, rT1 /* 4 OpA */, rD /* 2 exp */);

    /* ------------------------------------------- */
    /* Calculation of  h = (Mp-Mq)*qInv mod P    */
    /* ------------------------------------------- */

    /* rT1 = Mq mod P - needed for right calculating in next operation if Mq>P */
    PKA_MOD_ADD_IM(LEN_ID_PQ_BITS /* LenID */, rT1 /* Res */, rMq /* 5 OpA */, 0 /* immed OpB */);

    /* rT = Mp - Mq mod P */
    PKA_MOD_SUB(LEN_ID_PQ_BITS /* LenID */, rT /* Res */, rT /* OpA */, rT1 /* OpB */);

    /* rT1 = h = (Mp - Mq)*qInv mod P */
    PKA_MOD_MUL(LEN_ID_PQ_BITS /* LenID */, rT1 /* Res */, rT /* OpA */, rqInv /* rqInv */);

    /* ----------------------------- */
    /*       M = Mq + Q*h;         */
    /*  OpSize according Nsize     */
    /* ----------------------------- */

    /* operation changes from p/q size to N size, need clearing rT high bits */
    PKA_ClearPkaRegWords(rT1, PQSizeInWords);
    PKA_ClearPkaRegWords(rT, PQSizeInWords);
    PKA_ClearPkaRegWords(rQ, PQSizeInWords);
    PKA_ClearPkaRegWords(rMq, PQSizeInWords);

    /* copy rT1 and Mq in other registers for clearing junk from registers high part  */
    PKA_2CLEAR(LEN_ID_MAX_BITS /* LenID */, PKA_REG_T0 /* dest */);
    PKA_COPY(LEN_ID_MAX_BITS /* LenID */, rT /* dest */, rT1 /* src */);
    PKA_2CLEAR(LEN_ID_MAX_BITS /* LenID */, PKA_REG_T0 /* dest */);
    PKA_COPY(LEN_ID_MAX_BITS /* LenID */, rT1 /* dest */, rMq /* src */);

    /* Q*h => rT = rQ*rT */
    PKA_MUL_LOW(LEN_ID_N_PKA_REG_BITS /* LenID */, rT /* Res */, rT /* OpA */, rQ /* OpB */);

    PKA_ClearPkaRegWords(rT, PrivKey_ptr->nSizeInBits);

    /* M = rT1 = rMq + rT */
    PKA_ADD(LEN_ID_N_BITS /* LenID */, rT /* Res */, rT1 /* OpA */, rT /* OpB */);

    /* ----------------------------- */
    /*  Finish PKA and copy result */
    /* ----------------------------- */
    PKA_CopyDataFromPkaReg(PrivData_ptr->DataOut, modSizeWords, rT /* srcReg */);

    PKA_FinishAndMutexUnlock(pkaReqRegs);

    return Error;

} /* END OF LLF_PKI_ExecPrivKeyExpCrt */

/* ************ Exported functions prototypes ********************** */

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
SaSiError_t LLF_PKI_RSA_InitPrivKeyDb(SaSiRSAPrivKey_t *PrivKey_ptr)
{
    /* error identification */
    SaSiError_t Error = SaSi_OK;

    /* FUNCTION LOGIC */

    /* ---------------------------------------------------------------------- */
    /* ..........initialize PKA and calculate the Barrett tag ............... */
    /* ---------------------------------------------------------------------- */

    /* ------------------------------ */
    /* calculate NP on NonCRT mode  */
    /* ------------------------------ */
    if (PrivKey_ptr->OperationMode == SaSi_RSA_NoCrt) {
        /* check key size */
        if (PrivKey_ptr->nSizeInBits > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS) {
            Error = PKA_KEY_ILLEGAL_SIZE_ERROR;
            goto END;
        }

        /* calculate Barrett tag NP by initialization PKA for modular operations.
           Default settings: N=PKA_REG_N, NP=PKA_REG_NP, T0=30, T1=31.
           Our settings for temps: rT0=2, rT1=3, rT2=4 */
        Error = PKA_CalcNp(((LLF_pki_priv_key_db_t *)(PrivKey_ptr->sasiRSAPrivKeyIntBuff))->NonCrt.NP, /* out */
                           PrivKey_ptr->n,                                                             /* in */
                           PrivKey_ptr->nSizeInBits);                                                  /* in */

    } else {
        /* ----------------------------------------- */
        /* on CRT mode calculate the Barrett tags  */
        /*    PP and PQ for P and Q factors        */
        /* ----------------------------------------- */
        /* check key sizes */
        if (PrivKey_ptr->PriveKeyDb.Crt.PSizeInBits > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS / 2 ||
            PrivKey_ptr->PriveKeyDb.Crt.QSizeInBits > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS / 2) {
            Error = PKA_KEY_ILLEGAL_SIZE_ERROR;
            goto END;
        }
        /* calculate Barrett tag PP by initialization PKA for modular operations */
        Error = PKA_CalcNp(((LLF_pki_priv_key_db_t *)(PrivKey_ptr->sasiRSAPrivKeyIntBuff))->Crt.PP, /* out */
                           PrivKey_ptr->PriveKeyDb.Crt.P,                                           /* in */
                           PrivKey_ptr->PriveKeyDb.Crt.PSizeInBits);
        if (Error != SASI_SUCCESS) {
            goto END;
        }

        /* calculate Barrett tag PP by initialization PKA for modular operations */
        Error = PKA_CalcNp(((LLF_pki_priv_key_db_t *)(PrivKey_ptr->sasiRSAPrivKeyIntBuff))->Crt.QP, /* out */
                           PrivKey_ptr->PriveKeyDb.Crt.Q,                                           /* in */
                           PrivKey_ptr->PriveKeyDb.Crt.QSizeInBits);
        if (Error != SASI_SUCCESS) {
            goto END;
        }

    } /* end of CRT case */

END:
    return Error;
}

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
SaSiError_t LLF_PKI_RSA_ExecPrivKeyExp(SaSiRSAPrivKey_t *PrivKey_ptr, SaSi_RSAPrimeData_t *PrivData_ptr)
{
    /* error identification */
    SaSiError_t Error = SaSi_OK;

    /* FUNCTION LOGIC */

    /* ............... getting the hardware semaphore ..................... */
    /* -------------------------------------------------------------------- */

    /* ============================================== */
    /*         1.  NonCRT  case                     */
    /* ============================================== */
    if (PrivKey_ptr->OperationMode == SaSi_RSA_NoCrt) {
        Error = PKI_ExecPrivKeyExpNonCrt(PrivKey_ptr, PrivData_ptr);

    } else {
        /* =============================================== */
        /*         2.  CRT  case                         */
        /* =============================================== */
        Error = PKI_ExecPrivKeyExpCrt(PrivKey_ptr, PrivData_ptr);
    }

    /* .... un mappping the physical memory and releasing the semaphore ...... */
    /* ------------------------------------------------------------------------- */

    return Error;
}
