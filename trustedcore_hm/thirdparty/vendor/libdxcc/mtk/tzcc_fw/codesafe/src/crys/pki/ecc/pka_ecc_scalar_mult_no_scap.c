/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */

/* .............. SaSi level includes ................. */

#include "ssi_pal_mem.h"
#include "ssi_pal_mutex.h"
#include "ssi_pal_abort.h"
#include "sasi_common_math.h"
#include "sasi_ecpki_types.h"
#include "sasi_ecpki_error.h"
#include "sasi_ecpki_local.h"
#include "pka_hw_defs.h"
#include "pka_export.h"
#include "pka.h"
#include "pka_ecc_export.h"

/* .............. LLF level includes and definitions.............. */
#include "pka_ecc_error.h"
#include "pka_ecc.h"

// ! RL Temporary for ECDSA Verify testing
// #include "pka_dbg.h"

/* *********************** Defines **************************** */

/* canceling the lint warning:
   Info 717: do ... while(0) */


/* canceling the lint warning:
   Use of goto is deprecated */


/* canceling the lint warning:
Info 716: while(1) ... */


/* *********************** Defines **************************** */

extern const int8_t regTemps[PKA_MAX_COUNT_OF_PHYS_MEM_REGS];
/* *********************** Enums ****************************** */

/* *********************** Typedefs *************************** */

/* *********************** Global Data ************************ */

/* **********    External global variables      ********** */

/* Define common registers, used in ECC  */
#include "pka_ecc_glob_regs_def.h"

/* ************* Private functions prototypes  ************** */
void HostDivideVectorBy2(uint32_t *VecBuff_ptr, uint32_t SizeInWords);

/* *********************** Typedefs ************************* */
/* *********************** Global Data ********************** */

// extern const SaSi_ECPKI_Domain_t gEcDomans[];
extern SaSi_PalMutex sasiAsymCryptoMutex;

/* ************************************************************ */
/*
 * EC scalar multiplication
 *  p = k*p, not SCA-resistant
 *
 *  Implemented the algorithm, enhanced by A.Klimov
 *
 * Part of PKA registers are implicitly defined in pka_ecc_glob_regs_def.h file
 *
 * @author reuvenl (03/19/2015)
 *
 * @param [in/out] xr,yr - virt.pointers to PKA regs,
 *        containing coordinates of result EC point
 * @param [in] k - virt.pointer to PKA reg., containing scalar.
 * @param [in/out] xp,yp - virt.pointers to PKA regs,
 *        containing coordinates of input EC point
 */
void pka_smula(const uint32_t xr, const uint32_t yr, const char *k, const uint32_t xp, const uint32_t yp)
{
    uint8_t tp = regTemps[14];
    uint8_t zr = regTemps[15];
    uint8_t tr = regTemps[16];

    /* calculate auxiliary values */
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rn_4, rn, rn);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rn_4, rn_4, rn_4);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rn_8, rn_4, rn_4);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rn_12, rn_8, rn_4);

    PKA_SUB(LEN_ID_N_PKA_REG_BITS, tp, rn_4, yp); // ry of -p
    // ! RL may be changed to return error
    ASSERT(*k == '+');

    PKA_COPY(LEN_ID_N_PKA_REG_BITS, xr, xp);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, yr, yp); // r = p
    PKA_SET_VAL(zr, 1);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, tr, rec_a);

    while (*++k) {
        if (*k == '0') {
            pka_mm1(xr, yr, zr, tr, xr, yr, zr, tr); // *k = '0'
        } else {
            pka_mj(xr, yr, zr, xr, yr, zr, tr);
            if (*k == '+') {
                pka_ajm(xr, yr, zr, tr, xr, yr, zr, xp, yp); // *k = '+'
            } else {
                pka_ajm(xr, yr, zr, tr, xr, yr, zr, xp, tp); // *k = '-'
            }
        }
    }

    /* convert to affine */
    pka_a(SCAP_Inactive, xr, yr, zr);

    return;
}

/* *******************************************************************************
 * @brief This function divides a vector by 2 - in a secured way
 *
 *        The LSB of the vector is stored in the first cell in the array.
 *
 *        for example:
 *
 *        a vector of 128 bit : the value is :
 *
 *        word[3] << 96 | word[2] << 64 ............ word[1] << 32 | word[0]
 *
 * @param[in] VecBuff_ptr     -  The vector buffer.
 * @param[in] SizeInWords     -  the counter size in words.
 *
 * @return result - no return value.
 */

void HostDivideVectorBy2(uint32_t *VecBuff_ptr, uint32_t SizeInWords)
{
    /* FUNCTION LOCAL DECLERATIONS */

    uint32_t i;
    uint32_t Temp;

    /* FUNCTION LOGIC */

    /* for loop for dividing the vectors arrays by 2 */
    for (i = 0; i < (SizeInWords)-1; i++) {
        VecBuff_ptr[i] = VecBuff_ptr[i] >> 1;
        Temp           = VecBuff_ptr[i + 1] & 1UL;
        VecBuff_ptr[i] = VecBuff_ptr[i] | Temp << (32 - 1);
    }

    /* dividing the MS word */
    VecBuff_ptr[SizeInWords - 1] = VecBuff_ptr[SizeInWords - 1] >> 1;

    return;

} /* END OF HostDivideVectorBy2 */

/* *************************************************
   Input      K =    (Km-1 Km-2 иии K1 K0) binary
   Output     Z = (Zm Zm-1 Zm-2 иии Z1 Z0) NAF
   i <- 0
   while K > 0 do
       if K is odd then
           Zi <- 2 - (K mod 4)
       else
           Zi <- 0
       K <- (K - Zi)/2
       i <- i + 1
   return Z
   * *********************************************** */
/*
 * The function transforms integer buffer K to NAF string.
 *
 * @author reuvenl (6/20/2014)
 *
 * @param [out] pNaf - The pointer to NAF key buffer (msb->lsb).
 * @param [in/out] pNafSz - The pointer to size in bytes of the NAF output.
 *        Input - size of user given buffer, output - actual size of NAF key.
 * @param [in]  pK - The pointer to key buffer. Note: the key buffer
 *          should be corrupted by the function.
 * @param [in]  keySz - The size of key in bits.
 *
 * @return uint32_t error message
 */
SaSiError_t pka_build_naf(char **pNaf, uint32_t *pNafSz, uint32_t *pK, uint32_t keySzBit)
{
    SaSiError_t err = SaSi_OK;
    uint32_t wK, i = 0;
    char *p; /* a pointer to the current NAF digit */

    /* check input parameters */
    if (keySzBit == 0 || (keySzBit + 2) > *pNafSz) {
        err = PKA_NAF_KEY_SIZE_ERROR;
        goto End;
    }
    /* MSBit must be 1 */
    if ((pK[(keySzBit - 1) / 32] >> ((keySzBit - 1) & 0x1F)) != 1) {
        err = PKA_NAF_KEY_SIZE_ERROR;
        goto End;
    }

    /* set initial values */
    *pNafSz = 0;                    /* NAF size in bytes */
    p       = *pNaf + keySzBit + 1; /* start from the last byte */
    *p      = 0;
    wK      = CALC_FULL_32BIT_WORDS(keySzBit) /* +1 */; /* key size + extra word */

    /* zeroing extra word of key buffer */
    pK[wK] = 0;

    /* scan key bits and convert to NAF */
    while (keySzBit) {
        uint32_t carry, msBit;

        i++;
        (*pNafSz)++;
        --p;
        /* check overflow */
        if (p < *pNaf) {
            err = PKA_NAF_KEY_SIZE_ERROR;
            goto End;
        }
        /* set NAF digit */
        *p = (pK[0] & 1) ? ((pK[0] & 2) ? '-' : '+') : '0';

        msBit = pK[wK - 1] >> ((keySzBit % 32) - 1);
        if (*p == '-') {
            carry = SaSi_COMMON_IncLsbUnsignedCounter(pK, 1, wK); // k += 1
            if (carry) {
                pK[wK] = 1;
                keySzBit++;
            } else if ((pK[wK - 1] >> ((keySzBit % 32) - 1)) > msBit) {
                keySzBit++;
            }
        }

        HostDivideVectorBy2(pK, wK + 1); // k >>= 1
        keySzBit--;

        /* if MSbit is zeroed set new size value */
        wK = (CALC_FULL_32BIT_WORDS(keySzBit));
    }

    /* actual NAF vector begin */
    *pNaf = p;

End:
    return err;
}

/* ***************************************************************************** */
/*
 * EC scalar multiplication p = k*p, without SCA-protection features.
 *
 *  The function is more fast, than SCA protected function and performs:
 *  - PKA init,
 *  - setting input data into PKA registers,
 *  - calls pka_smul_aff function and then output of result data from PKA.
 *
 * @author reuvenl (03/19/2015)
 *
 * @param [in] domain - pointer to EC domain.
 * @param [out] bxr,byr - pointers to coordinates of result EC point.
 *          The size of each of buffers must be not less, than
 *          EC modulus size (in words).
 * @param [in] k - pointer to the scalar.
 * @param [in] kSizeBit - size of scalar in bits.
 * @param [in] bxp,byp  - pointers to coordinates of input EC point.
 * @param [in] tmpBuff - pointer to temp buffer of size
 *               not less than (2*ecOrderSizeInBits+1) in bytes.
 *
 */
SaSiError_t host_smul_aff(const SaSi_ECPKI_Domain_t *domain, uint32_t *bxr, uint32_t *byr, const uint32_t *k,
                          uint32_t kSizeBit, uint32_t *bxp, uint32_t *byp, uint32_t *tmpBuff)
{
    /* Define pka registers used */
    uint8_t xp = regTemps[18];
    uint8_t yp = regTemps[19];
    uint8_t xr = regTemps[20];
    uint8_t yr = regTemps[21];

    SaSiError_t err = SaSi_OK;
    uint32_t nafSz;
    uint32_t modSizeInBits, modSizeInWords, ordSizeInWords;
    /* pointer to copy of input key in the temp buffer */
    uint32_t *kt = tmpBuff;
    /* the pointer to */
    char *naf;
    uint32_t pkaReqRegs = PKA_MAX_COUNT_OF_PHYS_MEM_REGS;

    /* FUNCTION LOGIC */

    /* set domain parameters */
    modSizeInBits  = domain->modSizeInBits;
    modSizeInWords = CALC_FULL_32BIT_WORDS(modSizeInBits);
    ordSizeInWords = CALC_FULL_32BIT_WORDS(domain->ordSizeInBits);

    /* temp key buf + 1 word */
    kt[ordSizeInWords]     = 0;
    kt[ordSizeInWords - 1] = 0;
    SaSi_PalMemCopy(kt, k, sizeof(uint32_t) * ordSizeInWords);
    /* Naf buffer */
    naf   = (char *)(kt + ordSizeInWords + 1);
    nafSz = (ordSizeInWords + 1) * 32; /* NAF size in bytes */
    SaSi_PalMemSet(naf, 0, nafSz);

    /* build NAF */
    err = pka_build_naf(&naf, &nafSz, kt, kSizeBit);
    if (err)
        goto End;

    /*  Init PKA for modular operations */
    err = PKA_InitAndMutexLock(modSizeInBits, &pkaReqRegs);
    if (err != SaSi_OK) {
        return err;
    }

    /*   Set data into PKA registers  */
    /* -------------------------------- */
    /* set EC parameters */
    PKA_CopyDataIntoPkaReg(rn, 1, domain->ecP /* src_ptr */, modSizeInWords);
    PKA_CopyDataIntoPkaReg(rnp, 1, ((PKA_EcDomainLlf_t *)&domain->llfBuff)->modTag,
                           SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);
    PKA_CopyDataIntoPkaReg(rec_a, 1, domain->ecA, modSizeInWords);
    /* set point */
    PKA_CopyDataIntoPkaReg(xp, 1, bxp, modSizeInWords);
    PKA_CopyDataIntoPkaReg(yp, 1, byp, modSizeInWords);

    /* For SEP work:
    1. Change naf from str to buff (words) with 2-bit values.
       Add size of Naf as parameter. Change naf-function accordingly.
    2. Add set naf into 2 free registers and add reading from regs. */

    /* Call scalar mult */
    pka_smula(xr, yr, naf, xp, yp);

    /*  Output data from PKA registers  */
    /* ---------------------------------- */
    PKA_CopyDataFromPkaReg(bxr, modSizeInWords, xr);
    PKA_CopyDataFromPkaReg(byr, modSizeInWords, yr);

    PKA_FinishAndMutexUnlock(pkaReqRegs);

End:

    /* zeroing of kt and naf buffers */
    // RL NAF size according to NAF representation
    SaSi_PalMemSetZero(tmpBuff,
                       (ordSizeInWords + 1) * sizeof(uint32_t) + (ordSizeInWords + 1) * 32 /* NAF buff size in bytes */);
    return err;
}

/* ***************************************************************************** */
/*
 * brief ECC scalar multiplication function, without SCA protection
 *          features (NoScap).
 *               outPoint = scalsr * inPoint.
 *     The function performs the following:
 *       1. Checks the validity of input parameters.
 *       3. Calls the low level functions: host_smul (with SCA protection) or
 *          host_smul_aff according to SCA protection mode, to generate EC public key.
 *       4. Outputs the user public and private key structures in little endian form.
 *       5. Cleans temporary buffers.
 *       6. Exits.
 *     Mote: All buffers are given as 32-bit words arrays, where LSWord is a leftmost one.
 * @param [in] pDomain  - The pointer to current EC domain.
 * @param [in] scalar - The pointer to the scalsr buffer.
 * @param [in] scalSizeInBits - The exact size of the scalsr in words.
 * @param [in] inPointX - The pointer to the point X coordinate.
 * @param [in] inPointY - The pointer to the point Y coordinate.
 * @param [out] outPointX - The pointer to the point X coordinate.
 * @param [out] outPointY - The pointer to the point Y coordinate.
 * @param [in] tmpBuff - The pointer to the temp buffer of size not less,
 *                      than SaSi_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS,
 *                      defined according SCA protection compilation flag in proj. config.
 * @return <b>SaSiError_t</b>: <br>
 *                        SaSi_OK<br>
 */
SaSiError_t LLF_ECPKI_ScalarMult(const SaSi_ECPKI_Domain_t *pDomain, /* in */
                                 const uint32_t *scalar,             /* in */
                                 uint32_t scalSizeInWords,           /* in */
                                 uint32_t *inPointX,                 /* out */
                                 uint32_t *inPointY,                 /* out */
                                 uint32_t *outPointX,                /* out */
                                 uint32_t *outPointY,                /* out */
                                 uint32_t *tmpBuff)                  /* in */
{
    /* DECLARATIONS */

    SaSiError_t err = SaSi_OK; /* the error identifier */
    uint32_t scalarSizeInBits;
    SaSi_COMMON_CmpCounter_t cmp;

    /* FUNCTION LOGIC */

    /* get exact size of scalar */
    scalarSizeInBits = SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(scalar, scalSizeInWords);

    /* compare scalar to EC generator order (0 < scalar < EC order) */
    cmp = SaSi_COMMON_CmpLsWordsUnsignedCounters(scalar, scalSizeInWords, pDomain->ecR,
                                                 CALC_FULL_32BIT_WORDS(pDomain->ordSizeInBits));

    if ((scalarSizeInBits == 0) || (cmp == SaSi_COMMON_CmpCounter1GraterThenCounter2)) {
        return LLF_ECPKI_SCALAR_MULT_INVALID_SCALAR_VALUE_ERROR;
    }

    /* call scalar mult. function with affine coordinates, no SCAP */
    err = host_smul_aff(pDomain, outPointX, outPointY, scalar, scalarSizeInBits, inPointX, inPointY, tmpBuff);
    /* Note: host_smul_aff has zeroing the tmpBuff */

    return err;

} /* END OF LLF_ECPKI_ScalarMult */

/* Undefine PKA registers names */
#include "pka_ecc_glob_regs_undef.h"
