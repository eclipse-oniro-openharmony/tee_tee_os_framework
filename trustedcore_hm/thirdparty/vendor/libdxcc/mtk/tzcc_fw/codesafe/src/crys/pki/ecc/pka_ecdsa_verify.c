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
#include "sasi_common.h"
#include "sasi_common_math.h"
#include "sasi_ecpki_types.h"
#include "sasi_ecpki_error.h"
#include "sasi_ecpki_local.h"
#include "pka_hw_defs.h"
#include "pka_export.h"
#include "pka.h"
#include "pka_ecc.h"
#include "pka_ecc_error.h"

/* *********************** Defines **************************** */

/* Define common ECC PKA registers allocation */
#include "pka_ecc_glob_regs_def.h"

/* *********************** Enums **************************** */
/* *********************** Typedefs ************************* */
/* *********************** Global Data ********************** */

extern const SaSi_ECPKI_Domain_t gEcDomans[];

/* ************ Private function prototypes ***************** */

/*
 * pka ecc points adding: affine-affine-affine
 *
 * All parameters are ID-s of PKA registers, containing the data.
 *
 * \param x,y - output point coordinates
 * \param x1,y1 - input point1 coordinates
 * \param x2,y2 - input point2 coordinates
 */
void pka_aaa(const uint32_t x, const uint32_t y, const uint32_t x1, const uint32_t y1, const uint32_t x2,
             const uint32_t y2)
{
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, x, rn_1, x1);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, raaa_z, x, x2);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, rt, rn_1, y2);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt, y1, rt);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt2, raaa_z, raaa_z);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt1, raaa_z, rt2);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, rt1, rn_4, rt1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, y, rt1, y1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt2, x, rt2);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, x, rt, rt, rt1);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, x, rt2, x);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, x, rt2, x);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt2, x, rt2);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, y, rt, rt2, y);
    pka_a(SCAP_Inactive, x, y, raaa_z);

    return;
}

/*
 * The function calculates simultaneously summ of two scalar
 * multiplications of EC points.
 *
 * Used the Strauss algorithm, optimized by A.Klimow:
 *     R = a*P + b*Q, where R,P,Q - EC points, a,b - scalars.
 *
 * @author reuvenl (8/26/2014)
 *
 * @param xr,yr - The PKA registers, containing point R coordinates;
 * @param a - The PKA register, containing scalar a.
 * @param xp,yp - PKA registers, containing point P coordinates;
 * @param b - The PKA register, containing scalar b.
 * @param xq,yq - PKA registers, containing point Q coordinates;
 * @return - uint32_t error message in case of fail
 */
uint32_t pka_2mul(const uint32_t xr, const uint32_t yr, const uint32_t a, const uint32_t xp, const uint32_t yp,
                  const uint32_t b, const uint32_t xq, const uint32_t yq)
{
    uint32_t wA, wB, err = 0;
    uint32_t stat;
    int32_t b2, i;
    uint32_t isNewA = true, isNewB = true;
#define r2mul_xpq 14
#define r2mul_ypq 15
#define r2mul_zr  16
#define r2mul_tr  17

    /* check that a>0 and b>0 */
    PKA_COMPARE_IM_STATUS(LEN_ID_N_PKA_REG_BITS, a, 0, stat);
    if (stat == 1) {
        err = LLF_ECDSA_VERIFY_2MUL_FACTOR_A_NULL_ERROR;
        goto End;
    }
    PKA_COMPARE_IM_STATUS(LEN_ID_N_PKA_REG_BITS, b, 0, stat);
    if (stat == 1) {
        err = LLF_ECDSA_VERIFY_2MUL_FACTOR_B_NULL_ERROR;
        goto End;
    }

    /* get max effective size of factors minus 1 */
    i = SaSi_MAX(PKA_GetRegEffectiveSizeInBits(a), PKA_GetRegEffectiveSizeInBits(b)) - 1;

    pka_aaa(r2mul_xpq, r2mul_ypq, xp, yp, xq, yq); // p+q

#ifdef ARM_DSM
    *((volatile uint32_t *)(uint32_t)(0x44440000)) = i;
#endif

    b2 = pka_getNextMsBit(a, i, &wA, &isNewA) * 2 + pka_getNextMsBit(b, i, &wB, &isNewB);
    switch (b2) {
    case 1:
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, xr, xq);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, yr, yq);
        break; // 01: r = q
    case 2:
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, xr, xp);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, yr, yp);
        break; // 10: r = p
    case 3:
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, xr, r2mul_xpq);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, yr, r2mul_ypq);
        break; // 11: r = p+q
    default:
        err = LLF_ECDSA_VERIFY_2MUL_FIRST_B2_ERROR;
        goto End;
    }
    PKA_SET_VAL(r2mul_zr, 1);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, r2mul_tr, rec_a);

    while (--i >= 0) {
#ifdef ARM_DSM
        *((volatile uint32_t *)(uint32_t)(0x44440000)) = i;
#endif
        b2 = pka_getNextMsBit(a, i, &wA, &isNewA) * 2 + pka_getNextMsBit(b, i, &wB, &isNewB);
        if (b2 == 0) {
            pka_mm1(xr, yr, r2mul_zr, r2mul_tr, xr, yr, r2mul_zr, r2mul_tr);
        } else {
            pka_mj(xr, yr, r2mul_zr, xr, yr, r2mul_zr, r2mul_tr);
            switch (b2) {
            case 1:
                pka_ajm(xr, yr, r2mul_zr, r2mul_tr, xr, yr, r2mul_zr, xq, yq);
                break; // 01: r += p
            case 2:
                pka_ajm(xr, yr, r2mul_zr, r2mul_tr, xr, yr, r2mul_zr, xp, yp);
                break; // 10: r += q
            case 3:
                pka_ajm(xr, yr, r2mul_zr, r2mul_tr, xr, yr, r2mul_zr, r2mul_xpq, r2mul_ypq);
                break; // 11: r += p+q
            default:
                err = LLF_ECDSA_VERIFY_2MUL_NEXT_B2_ERROR;
                goto End;
            }
        }
    }
    pka_a(SCAP_Inactive, xr, yr, r2mul_zr);

End:

#undef r2mul_xpq
#undef r2mul_ypq
#undef r2mul_zr
#undef r2mul_tr

    return err;
}

/* *********************** Public Functions ***************** */

/* ***************************************************************************************
 *            PkaEcdsaVerify function /ECVP_DSA in IEEE-1363                *
 * ************************************************************************************* */
/* *FIRST
 * This function performs verification of ECDSA signature using PKA.
 *
 * 1. Compute  h = d^-1,  h1 = f*h mod r,  h2 = c*h mod r.
 * 2. Compute  P(Xp,Yp) =  h1*G  + h2*W; c1 = Px mod r
 * 3. Compare  If  c1 != c,  then output "Invalid", else - "valid".
 *
 * Assuming: - PKA is initialized, all data is set into SRAM.
 *
 * @author reuvenl (8/7/2014)
 *
 * @return SaSiError_t - SaSi_OK or error
 *         LLF_ECDSA_VERIFY_CALC_SIGNATURE_IS_INVALID
 */
SaSiError_t PkaEcdsaVerify(void)
{
/* LOCAL DECLARATIONS */

/* define virtual pointers to PKA registers */
#include "pka_ecdsa_verify_regs_def.h"

    /* errors identifier */
    SaSiError_t err = SaSi_OK;
    int32_t modSizeInBits, ordSizeInBits; // , regSizeInBits;
    /* indication variables */
    uint32_t status1, status2;

    /* FUNCTION LOGIC */

    /* Get sizes */
    ordSizeInBits = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, PKA_L0));
    modSizeInBits = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, PKA_L2));

    /* ----------------------------------------------------------------------- */
    /*  1. If  C or D are not in interval [1,r-1] then output "invalid"        */
    /* ----------------------------------------------------------------------- */

    /* temporary set rn = rn - 1 for the following checking */
    PKA_FLIP_BIT0(LEN_ID_N_PKA_REG_BITS, rn, rn);

    /* check C */
    PKA_SUB_IM(LEN_ID_N_PKA_REG_BITS, RES_DISCARD, rC, 1 /* imm */);
    PKA_GET_StatusCarry(status1); /* if rC >= 1, then status = 0 */
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, RES_DISCARD, rn, rC);
    PKA_GET_StatusCarry(status2); /* if rC <= rn, then status = 1 */
    if (status1 == 0 || status2 == 0) {
        err = LLF_ECDSA_VERIFY_CALC_SIGN_C_INVALID_ERROR;
        goto End;
    }

    /* check D */
    PKA_SUB_IM(LEN_ID_N_PKA_REG_BITS, RES_DISCARD, rD, 1 /* imm */);
    PKA_GET_StatusCarry(status1); /* if rC >= 1, then status = 0 */
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, RES_DISCARD, rn, rD);
    PKA_GET_StatusCarry(status2); /* if rD <= rR, then status = 1 */
    if (status1 == 0 || status2 == 0) {
        err = LLF_ECDSA_VERIFY_CALC_SIGN_D_INVALID_ERROR;
        goto End;
    }

    /* restore rn  */
    PKA_FLIP_BIT0(LEN_ID_N_PKA_REG_BITS, rn, rn);

    /* ------------------------------------------- */
    /* 2. Calculate h, h1, h2 and normalize rF     */
    /* ------------------------------------------- */

    /* 2.1. h = d^-1  mod r */
    PKA_MOD_INV_W_EXP(rh, rD, rTmp); // PPR(rh);

    // RL TBD Enough pka_reduce
    PKA_DIV(LEN_ID_N_PKA_REG_BITS, rTmp, rF /* rem */, rn /* div */);
    /* 2.2. h1 = f*h  mod r */
    PKA_MOD_MUL(LEN_ID_N_BITS, rh1 /* Res */, rF /* OpA */, rh /* OpB */);
    /* 2.3. h2 = c*h mod r  */
    PKA_MOD_MUL(LEN_ID_N_BITS, rh2 /* Res */, rC /* OpA */, rh /* OpB */);

    /* ---------------------------------------------------- */
    /* set PKA for operations according to ECC modulus    */
    /* ---------------------------------------------------- */
    PKA_CLEAR(LEN_ID_N_PKA_REG_BITS, PKA_REG_T0);
    PKA_CLEAR(LEN_ID_N_PKA_REG_BITS, PKA_REG_T1);
    PKA_WAIT_ON_PKA_DONE();
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, PKA_L0), modSizeInBits);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, rTmp, rn);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, rn, rn_t);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, rn_t, rTmp); // swap mod<->ord
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, rnp, rnp_t);

    /* Auxiliary values: rn_X = X*rn */
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rn_4, rn, rn);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rn_4, rn_4, rn_4);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rn_8, rn_4, rn_4);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rn_12, rn_8, rn_4);

    /* ---------------------------------------------------- */
    /* 3. Compute EC point  P1 =  h1*G + h2*W by mod P    */
    /* ---------------------------------------------------- */
    err = pka_2mul(pR_x, pR_y, rh1, pG_x, pG_y, rh2, pW_x, pW_y);
    if (err)
        goto End;

    /* ------------------------------------------------------------------ */
    /* 4. Normalize: C' = pRx mod r. Compare C' == C              */
    /* ------------------------------------------------------------------ */
    PKA_WAIT_ON_PKA_DONE();
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, PKA_L0), ordSizeInBits);
    PKA_DIV(LEN_ID_N_PKA_REG_BITS, rTmp, pR_x /* rem */, rn_t /* div */);
    PKA_COMPARE_STATUS(LEN_ID_N_PKA_REG_BITS, pR_x, rC, status1);
    if (status1 != 1) {
        err = LLF_ECDSA_VERIFY_CALC_SIGNATURE_IS_INVALID;
    }
End:
/* undefine virtual pointers to PKA registers */
#include "pka_ecdsa_verify_regs_undef.h"

    return err;

} /* END OF PkaEcdsaVerify */

#include "pka_ecc_glob_regs_undef.h"
