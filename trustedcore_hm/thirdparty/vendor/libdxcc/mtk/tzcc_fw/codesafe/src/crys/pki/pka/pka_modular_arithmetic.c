/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#include "ssi_pal_types.h"
#include "ssi_pal_mem.h"
#include "sasi_common_math.h"
#include "sasi_ecpki_types.h"
#include "pka.h"
#include "pka_ut.h"
#include "pka_export.h"
#include "pka_modular_arithmetic.h"

#include "pka_dbg.h"
/* virt. pointers to pka regs. (regs. ID-s) */
#include "pka_point_compress_regs_def.h"

/* **************************************** defines ********************************* */

/*
 * Calculate Jacoby symbol for a and prime b numbers.
 *     Assumed: a, b are a positive numbers.
 *     Note: rA, rB registers are destroed by the function.
 *
 * @author reuvenl (10/26/2014)
 *
 * @return int jacoby symbol value.
 */
int pka_jacobi_symb(void /* uint32_t rA, uint32_t rB */)
{
    int32_t r, t;
    uint32_t stat, w, w1;

    /* Note: Check GCD - not need because b - prime.
       Convert a to  positive numbers - not need  */

    /* case rA = 0 or rA = 1 */
    PKA_COMPARE_IM_STATUS(LEN_ID_N_PKA_REG_BITS, rA, 0, stat); /* if(a==0) r = 0 */
    if (stat == 1) {
        r = 0;
        goto End;
    }

    PKA_COMPARE_IM_STATUS(LEN_ID_N_PKA_REG_BITS, rA, 1, stat); /* if(a==0) r = 0 */
    if (stat == 1) {
        r = 1;
        goto End;
    }

    r = 1;

    /* Evaluate Jacobi symb. */
    do {
        /* 1. Remove 0-LS bits of rA */
        t = 0;
        w = 0;

        while (w == 0) { /* remove 0- words */
            PKA_READ_WORD_FROM_REG(w, 0, rA);
            if (w == 0) {
                PKA_SHR_FILL0(LEN_ID_N_PKA_REG_BITS, rA, rA, 32 - 1);
                t += 32;
            }
        }

        while ((w & 1) == 0) {
            w >>= 1;
            t += 1;
        }
        if ((t & 0x1F) != 0) { /* removes 0-bits */
            PKA_SHR_FILL0(LEN_ID_N_PKA_REG_BITS, rA, rA, (t & 0x1F) - 1);
        }

        /* 2. Change sign if b mod 8 == 3 or 5 */
        PKA_READ_WORD_FROM_REG(w1, 0, rB);

        if (t & 1) {
            if ((w1 & 7) == 3 || (w1 & 7) == 5)
                r = -r;
        }

        /* 3. Quadratic reciprocity law */
        if ((w & 3) == 3 && (w1 & 3) == 3) {
            r = -r;
        }

        PKA_COPY(LEN_ID_N_PKA_REG_BITS, rC, rA);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, rA, rB);
        PKA_DIV(LEN_ID_N_PKA_REG_BITS, rB, rA, rC); /* a = b mod a */
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, rB, rC);    /* b = a prev. */

        PKA_COMPARE_IM_STATUS(LEN_ID_N_PKA_REG_BITS, rA, 0, stat);

    } while (stat != 1); /* while a != 0 */
End:

    return r;

} /* End of pka_jacobi_symb */

static void calculate_ry1(uint32_t stat)
{
    PKA_SUB_IM(LEN_ID_N_PKA_REG_BITS, rYt, rN, 1); /* rYt = rN-1 */
    PKA_SHR_FILL0(LEN_ID_N_PKA_REG_BITS, rZ, rYt, 2 - 1);
    PKA_MOD_EXP(LEN_ID_N_BITS, rT, rY2, rZ); /* d = rT = rY2^((rN-1)/4) */
    PKA_COMPARE_IM_STATUS(LEN_ID_N_PKA_REG_BITS, rT, 1, stat);
    if (stat == 1) {
        PKA_ADD_IM(LEN_ID_N_PKA_REG_BITS, rT, rN, 3);
        PKA_SHR_FILL0(LEN_ID_N_PKA_REG_BITS, rT, rT, 3 - 1);
        PKA_MOD_EXP(LEN_ID_N_BITS, rY1, rY2, rT);
    } else {
        PKA_COMPARE_STATUS(LEN_ID_N_PKA_REG_BITS, rT, rYt, stat); /* rT =? rN-1 */
        if (stat == 1) {
            PKA_SUB_IM(LEN_ID_N_PKA_REG_BITS, rT, rN, 5);
            PKA_SHR_FILL0(LEN_ID_N_PKA_REG_BITS, rT, rT, 3 - 1);
            PKA_SHL_FILL0(LEN_ID_N_PKA_REG_BITS, rYt, rY2, 2 - 1); /* rYt = 4*rY2 */
            PKA_MOD_EXP(LEN_ID_N_BITS, rZ, rYt, rT);
            PKA_SHL_FILL0(LEN_ID_N_PKA_REG_BITS, rYt, rY2, 1 - 1); /* rYt = 2*rY2 */
            PKA_MOD_MUL(LEN_ID_N_BITS, rY1, rZ, rYt);              /* rY1 = 2*rY2*(4rY2)^((rN-5)/8) */
        }
    }
}
/*
 * The function calculates square root modulo prime:
 *   rY1 = rY2 ^ 1/2 mod rP if root exists, else returns an error.
 *
 *   Assuming: 1. The modulus N is a prime.
 *             2. Y2 is less than modulus.
 *
 *   Implicit input and local parameters (registers ID-s) are defined in
 *   included pka_point_compress_regs_def.h file).
 *
 * @param rY1 - A virt. pointer to result square root PKA register.
 * @param rY2 - A virt. pointer to input value PKA register.
 * @param rN  - A virt. pointer to  modulus PKA register, assumed rN = 0.
 *
 * @return int: returns 1, if the root exists, or 0 if not.
 */
int pka_mod_square_root(void)
{
    uint32_t w = 0, stat;
    int32_t s, i;
    int32_t rootEx = 0, jcb;

    /* if Y^2 = 0, return Y=0 */
    PKA_COMPARE_IM_STATUS(LEN_ID_N_PKA_REG_BITS, rY2, 0, stat);
    if (stat == 1) {
        PKA_CLEAR(LEN_ID_N_PKA_REG_BITS, rY1); /* Y1=0 */
        rootEx = 1;
        goto End;
    }

    /* read w = mod[0] */
    PKA_READ_WORD_FROM_REG(w, 0 /* i */, rN);

    /* ----------------------------------------- */
    /* Case P=3 mod 4, then rY1 = +- rY2^(P+1)/4 */
    /* ----------------------------------------- */
    if ((w & 0x3) == 3) {
        PKA_ADD_IM(LEN_ID_N_PKA_REG_BITS, rY1, rN, 1);
        PKA_SHR_FILL0(LEN_ID_N_PKA_REG_BITS, rT, rY1, 2 - 1);
        PKA_MOD_EXP(LEN_ID_N_BITS, rY1, rY2, rT);
        goto End;
    }

    /* ------------------------------------------------ */
    /* Case P=5 mod 8, then rY1 calculated by algorithm */
    /* ------------------------------------------------ */
    if ((w & 0x7) == 5) {
        calculate_ry1(stat);
        goto End;
    }

    /* --------------------------------- */
    /* Case of other modulus structure   */
    /* --------------------------------- */

    /* check if root exist using jacoby symbol */
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, rA, rY2);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, rB, rN);
    jcb = pka_jacobi_symb( /* , rA, rB */);
    if (jcb == -1)
        goto End;

    /* state P-1 as Q * 2^s, where Q is odd */
    PKA_SUB_IM(LEN_ID_N_PKA_REG_BITS, rY1, rN, 1);
    w -= 1;
    s = 0;
    while (w == 0) { /* remove 0-words */
        PKA_SHR_FILL0(LEN_ID_N_PKA_REG_BITS, rY1, rY1, 32 - 1);
        s += 32;
        PKA_READ_WORD_FROM_REG(w, 0 /* i */, rY1);
    }
    /* remove 0-bits */
    i = 0;
    while ((w & 1) == 0) {
        w >>= 1;
        i++;
    }
    s += i;
    if (i > 0)
        PKA_SHR_FILL0(LEN_ID_N_PKA_REG_BITS, rY1, rY1, i - 1);

    /* find first non residue number (modulo N) starting from 2 */
    jcb = 0;
    PKA_CLEAR(LEN_ID_N_PKA_REG_BITS, rZ);
    PKA_SET_BIT0(LEN_ID_N_PKA_REG_BITS, rZ, rZ); /* z = 1 */
    while (jcb != -1) {
        PKA_ADD_IM(LEN_ID_N_PKA_REG_BITS, rZ, rZ, 1);

        /* set jacoby input values */
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, rA, rZ);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, rB, rN);
        jcb = pka_jacobi_symb( /* , rA, rB */);
    }

    PKA_MOD_EXP(LEN_ID_N_BITS, rZ, rZ, rY1); /* */
    PKA_ADD_IM(LEN_ID_N_PKA_REG_BITS, rY1, rY1, 1);
    PKA_SHR_FILL0(LEN_ID_N_PKA_REG_BITS, rY1, rY1, 1 - 1); /* rY1 = (rY1+1)/2  */
    PKA_MOD_EXP(LEN_ID_N_BITS, rY1, rY2, rY1);             /* rY1 = rY2^rY1  */
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, rYt, rY2);
    PKA_MOD_INV(LEN_ID_N_BITS, rT, rYt);
    for (;;) {
        PKA_MOD_MUL(LEN_ID_N_BITS, rYt, rY1, rY1); /* rYt = rY1^2  */
        PKA_MOD_MUL(LEN_ID_N_BITS, rYt, rYt, rT);  /* rYt = rYt * rY2^-1  */
        i = 0;
        while (1) {
            /* if(rYt == 1) break; */
            PKA_COMPARE_IM_STATUS(LEN_ID_N_PKA_REG_BITS, rYt, 1, stat);
            if (stat == 1)
                break;
            i++;
            PKA_MOD_MUL(LEN_ID_N_BITS, rYt, rYt, rYt); /* rYt = rYt^2 */
        }
        /* if rY1^2 * rY2^-1 == 1 (mod rP), return */
        if (i == 0) {
            rootEx = 1;
            goto End;
        }
        if (s - i == 1) { /* mul instead pow */
            PKA_MOD_MUL(LEN_ID_N_BITS, rY1, rY1, rZ);
        } else {
            w = 1 << ((s - i - 1) & 31);
            i = (s - i - 1) / 32; /* i was free */
            PKA_CLEAR(LEN_ID_N_PKA_REG_BITS, rEx);
            PKA_WRITE_WORD_TO_REG(w, i, rEx);
            PKA_MOD_EXP(LEN_ID_N_BITS, rYt, rZ, rEx);
            PKA_MOD_MUL(LEN_ID_N_BITS, rY1, rY1, rYt); /* rY1 = r * rZ^(2^(s-i-1)) */
        }
    }
End:
    /* Check result for rN mod 8 = {3,5} */
    if ((w & 3) == 3 || (w & 7) == 5) {
        PKA_MOD_MUL(LEN_ID_N_BITS, rT, rY1, rY1);
        PKA_COMPARE_STATUS(LEN_ID_N_PKA_REG_BITS, rT, rY2, stat);
        if (stat == 1)
            rootEx = 1;
    }

    return rootEx;
}

#include "pka_point_compress_regs_undef.h"
