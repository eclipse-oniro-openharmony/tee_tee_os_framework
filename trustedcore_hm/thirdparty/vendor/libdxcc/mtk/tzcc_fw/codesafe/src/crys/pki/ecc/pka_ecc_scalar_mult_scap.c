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

#include "pka_ecc.h"
#include "pka_export.h"
#include "pka_ecc_error.h"
#include "pka_ecc_export.h"

/* .............. LLF level includes and definitions.............. */
/* *********************** Defines **************************** */

/* Define common ECC PKA registers allocation */
#include "pka_ecc_glob_regs_def.h"

extern const int8_t regTemps[PKA_MAX_COUNT_OF_PHYS_MEM_REGS];
/* *********************** Enums ****************************** */

/* *********************** Typedefs *************************** */

/* *********************** Global Data ************************ */

/* ************ Private function prototype ******************** */

/* *********************** Public Functions ***************** */

/*
 * EC point doubling: p = 2*p1  modified-modified.
 *
 * All parameters are ID-s of PKA registers, containing the data.
 *
 * Part of PKA registers are implicitly defined in pka_ecc_glob_regs_def.h file
 *
 * \param x,y,z,t - output point coordinates
 * \param x,y,z,t - input point coordinates
 */
void pka_mm(const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t t, const uint32_t x1,
            const uint32_t y1, const uint32_t z1, const uint32_t t1)
{ // t cannot be aliased
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, t, y1, y1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, z, t, z1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, y, y1, y1);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, t, x1, x1);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, t, t, t);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, t, y, t);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt2, x1, x1);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, x, rt2, rt2);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt2, rt2, x);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt2, t1, rt2);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, t, rn_4, t);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, x, rt2, rt2, t);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, x, t, x);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, t, x, t);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, rt3, rn_12, t);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, y, y, y);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, y, y, y);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, y, y, y);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, t, y, y);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, t, t, t1);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, y, rn_8, y);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, y, rt3, rt2, y);
    return;
}

/* ************************************************************ */
/*
 * pka ecc points adding: jacob-jacob-modified
 *
 * All parameters are ID-s of PKA registers, containing the data.
 *
 * Part of PKA registers are implicitly defined in pka_ecc_glob_regs_def.h file
 *
 * \param x,y,z,t - output point coordinates
 * \param x1,y1,z1 - input point1 coordinates
 * \param x2,y2,z2 - input point1 coordinates
 */
void pka_jjm(const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t t, const uint32_t x1,
             const uint32_t y1, const uint32_t z1, const uint32_t x2, const uint32_t y2, const uint32_t z2)
{
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, t, z2, z2);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, x, x1, t);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, x, rn_4, x);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, t, z2, t);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, y, y1, t);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, y, rn_4, y);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, t, z1, z1);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, rt1, x2, t, x);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, t, z1, t);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, t, y2, t, y);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, z, z1, z2);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, z, z, rt1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt2, rt1, rt1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt1, rt1, rt2);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, rt1, rn_4, rt1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, y, rt1, y);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt2, x, rt2);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, x, t, t, rt1);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, x, rt2, x);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, x, rt2, x);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt2, x, rt2);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, y, t, rt2, y);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, y, rn_4, y);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, t, z, z);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, t, t, t);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, t, rec_a, t);
    return;
}

/* ************************************************************ */
/*
 * pka ecc points adding: jacob-jacob-jacob
 *
 * All parameters are ID-s of PKA registers, containing the data.
 *
 * Part of PKA registers are implicitly defined in pka_ecc_glob_regs_def.h file
 *
 * \param x,y,z,t - output point coordinates
 * \param x1,y1,z1 - input point1 coordinates
 * \param x2,y2,z2 - input point2 coordinates
 */
void pka_jjj(const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t x1, const uint32_t y1,
             const uint32_t z1, const uint32_t x2, const uint32_t y2, const uint32_t z2)
{
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt, z2, z2);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, x, x1, rt);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, x, rn_4, x);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt, z2, rt);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, y, y1, rt);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, y, rn_4, y);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt, z1, z1);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, rt1, x2, rt, x);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt, z1, rt);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, rt, y2, rt, y);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, z, z1, z2);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, z, z, rt1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt2, rt1, rt1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt1, rt1, rt2);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, rt1, rn_4, rt1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, y, rt1, y);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt2, x, rt2);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, x, rt, rt, rt1);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, x, rt2, x);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, x, rt2, x);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt2, x, rt2);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, y, rt, rt2, y);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, y, rn_4, y);
    return;
}

/* ************************************************************ */
/*
 * EC scalar multiplication
 *  p = k*p, SCA-resistant
 *
 *  Implemented algorithm, enhanced by A.Klimov
 *
 *  Part of PKA registers are implicitly defined in pka_ecc_glob_regs_def.h file
 *
 * @author reuvenl (3/19/2015)
 *
 * Implicit parameters, defined in pka_ecdsa_sign_regs_def.h:
 * @param [in] rk - virt.pointers to PKA reg., containing scalar.
 * @param [in/out] xp,yp -virt.pointers to PKA regs, containing coordinates of
 *        EC point
 */
void pka_smul(void)
{
    uint32_t isK;
    uint32_t sz1, sz2, sz, b2;
    uint32_t W;
    int32_t i, carry = 0; // always 0 or -1
    uint32_t isNew;

    /* define locally used PKA registers allocation */
#include "pka_ecdsa_sign_regs_def.h"

    /* calc. globals */
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rn_4, rn, rn);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rn_4, rn_4, rn_4);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rn_8, rn_4, rn_4);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rn_12, rn_8, rn_4);

    // To mask the size of k we calculate either k*p or -(-k)*p
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, tp, rk);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, zp, ord, tp); // zp is -k
    sz1 = PKA_GetRegEffectiveSizeInBits(rk);
    sz2 = PKA_GetRegEffectiveSizeInBits(zp);
    /* chose k or -k to mask size of scalar */
    if (sz1 > sz2) {
        sz  = sz1;
        isK = 1;
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, rk, tp); // Used k
    } else {
        sz  = sz2;
        isK = 0;
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, rk, zp); // Used -k
    }

    PKA_SET_VAL(zp, 1); // or random and adjust xp, yp, tp

    pka_mm(x2, y2, z2, t2, xp, yp, zp, rec_a); // 2p
    pka_mm(x4, y4, z4, t4, x2, y2, z2, t2);    // 4p

    i = ((sz + 1) & ~1) - 2; // round size up to even

    isNew = 1;
    b2    = pka_get2msbits(rk, i, &W, &isNew);

    switch (b2) {
    case 1:
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, xs, x2);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, ys, y2);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, zs, z2);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, ts, t2);
        carry = -1; /* pnt=2; */
        break;
    case 2:
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, xs, x2);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, ys, y2);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, zs, z2);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, ts, t2);
        carry = 0; /* pnt=2; */
        break;
    case 3:
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, xs, x4);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, ys, y4);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, zs, z4);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, ts, t4);
        carry = -1; /* pnt=4; */
        break;
    default:
        ASSERT(0);
    }

    // t of p,2,4 are no longer needed, let us use them for -ry
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, tp, rn_4, yp); // ry of -p
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, t2, rn_4, y2); // ry of -2p
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, t4, rn_4, y4); // ry of -4p

    for (i -= 2; i >= 0; i -= 2) {
        int32_t swt;
        pka_mm(xs, ys, zs, zr, xs, ys, zs, ts); // zr as a temporary
        pka_mj(xs, ys, zs, xs, ys, zs, zr);     // s *= 4

        /* get next two bits of key */
        b2  = pka_get2msbits(rk, i, &W, &isNew);
        swt = carry * 4 + b2;
        /* choose which point to add or subtract and update the carry */
        switch (swt) {
        case (uint32_t)-4:
            pka_jjm(xs, ys, zs, ts, xs, ys, zs, x4, t4, z4);
            carry = 0;
            break;
        case (uint32_t)-3:
            pka_jjm(xs, ys, zs, ts, xs, ys, zs, x2, t2, z2);
            carry = -1;
            break;
        case (uint32_t)-2:
            pka_jjm(xs, ys, zs, ts, xs, ys, zs, x2, t2, z2);
            carry = 0;
            break;
        case (uint32_t)-1:
            pka_jjm(xs, ys, zs, ts, xs, ys, zs, xp, tp, zp);
            carry = 0;
            break;
        case 0:
            pka_jjm(xs, ys, zs, ts, xs, ys, zs, xp, yp, zp);
            carry = -1;
            break;
        case +1:
            pka_jjm(xs, ys, zs, ts, xs, ys, zs, xp, yp, zp);
            carry = 0;
            break;
        case +2:
            pka_jjm(xs, ys, zs, ts, xs, ys, zs, x2, y2, z2);
            carry = 0;
            break;
        case +3:
            pka_jjm(xs, ys, zs, ts, xs, ys, zs, x4, y4, z4);
            carry = -1;
            break;
        default:
            ASSERT(0);
        }
    }

    pka_jjj(x2, y2, z2, xs, ys, zs, xp, tp, zp); // used only then carry is -1

    if (carry == -1) {
        PKA_SUB(LEN_ID_N_PKA_REG_BITS, t2, rn_4, y2);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, xp, x2);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, yp, isK == 1 ? y2 : t2);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, zp, z2);
    } else {
        PKA_SUB(LEN_ID_N_PKA_REG_BITS, ts, rn_4, ys);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, xp, xs);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, yp, isK == 1 ? ys : ts);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, zp, zs);
    }
    // convert to affine
    pka_a(SCAP_Active, xp, yp, zp);

    /* undefine internal registers names */
#include "pka_ecdsa_sign_regs_undef.h"

    return;
}

/* ************************************************************ */
/*
 * EC scalar multiplication p = k*p, with SCA-protection features.
 *
 *  The function performs:
 *  - PKA init,
 *  - setting input data into PKA registers,
 *  - calls pkaSmul function and then output result data from PKA.
 *
 * Part of PKA registers are implicitly defined in pka_ecc_glob_regs_def.h
 * and pka_ecdsa_sign_regs_def.h files
 *
 * @author reuvenl (03/19/2015)
 *
 * @param [in] domain - pointer to EC domain.
 * @param [out] bxr,byr - pointers to coordinates of result EC point.
 *          The size of each of buffers must be not less, than
 *          EC modulus size (in words).
 * @param [in] k - pointer to the scalar.
 * @param [in] kSizeBit - size if the scalar in bits.
 * @param [in] bxp,byp  - pointers to coordinates of input EC point.
 *
 */
SaSiError_t host_smul(const SaSi_ECPKI_Domain_t *domain, uint32_t *bxr, uint32_t *byr, const uint32_t *k,
                      uint32_t kSizeBit, uint32_t *bxp, uint32_t *byp)
{
    /*  DEFINITIONS AND DECLARATIONS  */

    /* define locally used PKA registers */

    // RL change name to pka_ecdsa_smul_regs_def
#include "pka_ecdsa_sign_regs_def.h"
    uint8_t ord = regTemps[26];
    uint8_t rk  = regTemps[27];
    uint8_t rxp = regTemps[28];
    uint8_t ryp = regTemps[29];

    uint32_t err;
    uint32_t modSizeInBits, modSizeInWords;
    uint32_t pkaReqRegs = PKA_MAX_COUNT_OF_PHYS_MEM_REGS;

    /* FUNCTION LOGIC */

    /* set domain parameters */
    modSizeInBits  = domain->modSizeInBits;
    modSizeInWords = CALC_FULL_32BIT_WORDS(modSizeInBits);

    /*  Init PKA for modular operations: regs mappimg according to max.   *
     *   size of order or modulus                                          */
    err = PKA_InitAndMutexLock(SaSi_MAX(modSizeInBits, domain->ordSizeInBits), &pkaReqRegs);
    if (err != SaSi_OK) {
        return err;
    }
    /* Set modulus sizes to L0, L1 and order sizes in L2, L3 */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, PKA_L0), modSizeInBits);

    /*   Set data into PKA registers  */
    /* -------------------------------- */
    /* set EC parameters */
    PKA_CopyDataIntoPkaReg(rn, 1, domain->ecP /* src_ptr */, modSizeInWords);
    PKA_CopyDataIntoPkaReg(rnp, 1, ((PKA_EcDomainLlf_t *)&domain->llfBuff)->modTag,
                           SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);
    PKA_CopyDataIntoPkaReg(rec_a, 1, domain->ecA, modSizeInWords);
    PKA_CopyDataIntoPkaReg(ord, 1, domain->ecR, CALC_FULL_32BIT_WORDS(domain->ordSizeInBits));
    /* set point */
    PKA_CopyDataIntoPkaReg(rxp, 1, bxp, modSizeInWords);
    PKA_CopyDataIntoPkaReg(ryp, 1, byp, modSizeInWords);
    /* set key */
    PKA_CopyDataIntoPkaReg(rk, 1, k, CALC_FULL_32BIT_WORDS(kSizeBit));

    /* Call scalar mult */
    pka_smul();

    /*  Output data from PKA registers  */
    /* ---------------------------------- */
    PKA_CopyDataFromPkaReg(bxr, modSizeInWords, rxp);
    PKA_CopyDataFromPkaReg(byr, modSizeInWords, ryp);

    /* undefine internal registers names */
#include "pka_ecdsa_sign_regs_undef.h"

    /*   Finish the function and clear PKA regs.  */
    PKA_FinishAndMutexUnlock(pkaReqRegs);

    return err;
}

/* undefine global registers names */
#include "pka_ecc_glob_regs_undef.h"

/* ************************************************************ */
/* ************         Public Functions             ********** */
/* ************************************************************ */

/* ************************************************************ */
/*
 @brief ECC scalar multiplication function, without SCA protection
         features (NoScap).
              outPoint = scalsr * inPoint.

    The function performs the following:
      1. Checks the validity of input parameters.
      2. Calls the low level functions: host_smul (with SCA protection) or
         host_smul_aff according to SCA protection mode, to generate EC public key.
      3. Outputs the user public and private key structures in little endian form.
      4. Cleans temporary buffers.
      5. Exits.

    Mote: All buffers are given as 32-bit words arrays, where LSWord is a leftmost one.
          Sizes of buffers of in/out points coordinates are equal to EC modulus
          size.

 @param [in] pDomain  - The pointer to current EC domain.
 @param [in] scalar - The pointer to the scalsr buffer.
 @param [in] scalSizeInBits - The size of the scalsr in 32-bit words.
 @param [in] inPointX - The pointer to the input point X coordinate.
 @param [in] inPointY - The pointer to the point Y coordinate.
 @param [out] outPointX - The pointer to the point X coordinate.
 @param [out] outPointY - The pointer to the point Y coordinate.
 @param [in]  tmpBuff - the pointer to the dummy buffer, allowed be NULL.

 @return <b>SaSiError_t</b>: <br>
                       SaSi_OK<br>
                       SaSi_ECPKI_GEN_KEY_ILLEGAL_D0MAIN_ID_ERROR<br>
                       SaSi_ECPKI_GEN_KEY_INVALID_PRIVATE_KEY_PTR_ERROR<br>
                       SaSi_ECPKI_GEN_KEY_INVALID_PUBLIC_KEY_PTR_ERROR<br>
                       SaSi_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR<br>
                       SaSi_ECPKI_BUILD_SCA_RESIST_ILLEGAL_MODE_ERROR<br>
*/
SaSiError_t LLF_ECPKI_ScalarMult(const SaSi_ECPKI_Domain_t *pDomain, /* in */
                                 const uint32_t *scalar,             /* in */
                                 uint32_t scalSizeInWords,           /* in */
                                 uint32_t *inPointX,                 /* out */
                                 uint32_t *inPointY,                 /* out */
                                 uint32_t *outPointX,                /* out */
                                 uint32_t *outPointY,                /* out */
                                 uint32_t *tmpBuff)                  /* not in use here, used in non protected mode */
{
    /* DECLARATIONS */

    /* the error identifier */
    SaSiError_t err = SaSi_OK;
    uint32_t scalarSizeInBits;
    SaSi_COMMON_CmpCounter_t cmp;

    /* FUNCTION LOGIC */

    SASI_UNUSED_PARAM(tmpBuff); // remove compilation warning

    /* get exact size of scalar */
    scalarSizeInBits = SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(scalar, scalSizeInWords);

    /* compare scalar to EC generator order (0 < scalar < order) */
    cmp = SaSi_COMMON_CmpLsWordsUnsignedCounters(scalar, scalSizeInWords, pDomain->ecR,
                                                 CALC_FULL_32BIT_WORDS(pDomain->ordSizeInBits));

    if (scalarSizeInBits == 0 || cmp == SaSi_COMMON_CmpCounter1GraterThenCounter2)
        return LLF_ECPKI_SCALAR_MULT_INVALID_SCALAR_VALUE_ERROR;

    /* perform scalar mult. with SCA protect features */
    err = host_smul(pDomain, outPointX, outPointY, scalar, scalarSizeInBits, inPointX, inPointY);

    return err;

} /* END OF LLF_ECPKI_ScalarMult */
