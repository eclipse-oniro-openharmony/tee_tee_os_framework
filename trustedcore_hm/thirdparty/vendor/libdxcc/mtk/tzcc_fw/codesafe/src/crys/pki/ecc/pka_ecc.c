/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */
#include "ssi_pal_mem.h"
#include "ssi_pal_types.h"
#include "ssi_hal_plat.h"
#include "sasi_common_math.h"
#include "sasi_ecpki_error.h"

#include "pka_hw_defs.h"
#include "pka_error.h"
#include "pka_export.h"
#include "pka.h"
#include "pka_ecc.h"
#include "pka_ut.h"
#include "pka_modular_arithmetic.h"

#include "pka_dbg.h"

/* **********    External global variables      ********** */

/* Define common registers, used in ECC  */
#include "pka_ecc_glob_regs_def.h"

/* *********    Private functions prototypes    ********** */

/*
 * The function performs doubling of modified EC point1 to modified point.
 *
 * All parameters are ID-s of PKA registers, containing the data.
 * Part of PKA registers are implicitly defined in pka_ecc_glob_regs_def.h file
 *
 * @param sca_protect - flag defining is SCA protection needed (1) or not (0).
 * @param x,y,z,t  - [out] EC point1 modified coordinates,
 * @param x,y,z,t  - [in] result EC point modified coordinates,
 * Part of PKA registers are implicitly defined in pka_ecc_glob_regs_def.h file
 */
void pka_mm1(const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t t, const uint32_t x1,
             const uint32_t y1, const uint32_t z1, const uint32_t t1)
{
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt4, y1, y1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, z, rt4, z1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, y, y1, y1);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt4, x1, x1);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt4, rt4, rt4);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt4, y, rt4);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt2, x1, x1);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, x, rt2, rt2);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt2, rt2, x);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt2, t1, rt2);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, rt4, rn_4, rt4);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, x, rt2, rt2, rt4);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, x, rt4, x);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt4, x, rt4);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, rt3, rn_12, rt4);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, y, y, y);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, y, y, y);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, y, y, y);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt4, y, y);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt4, rt4, t1);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, y, rn_8, y);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, y, rt3, rt2, y);
    PKA_COPY(LEN_ID_N_PKA_REG_BITS, t, rt4);
    return;
}

/*
 * The function performs doubling of modified EC point1 to jacobian point.
 *
 * All parameters are ID-s of PKA registers, containing the data.
 * Part of PKA registers are implicitly defined in pka_ecc_glob_regs_def.h file
 *
 * @param sca_protect - flag defining is SCA protection needed (1) or not (0).
 * @param x,y,z   - [out] EC point1 jacobian coordinates,
 * @param x,y,z,t - [in] result EC point modified coordinates,
 */
void pka_mj(const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t x1, const uint32_t y1,
            const uint32_t z1, const uint32_t t1)
{
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt, y1, y1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, z, rt, z1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, y, y1, y1);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt, x1, x1);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt, rt, rt);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt, y, rt);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt2, x1, x1);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, x, rt2, rt2);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt2, rt2, x);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt2, t1, rt2);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, rt, rn_4, rt);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, x, rt2, rt2, rt);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, x, rt, x);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt, x, rt);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, rt3, rn_12, rt);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, y, y, y);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, y, y, y);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, y, y, y);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, y, rn_8, y);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, y, rt3, rt2, y);
    return;
}

/*
 * The function performs adding of EC points p= p2+p1: affine-jacobian-modified.
 *
 * All coordinates parameters are ID-s of PKA registers, containing the data.
 * Part of PKA registers are implicitly defined in pka_ecc_glob_regs_def.h file
 *
 * @param sca_protect - flag defining is SCA protection needed (1) or not (0).
 * @param x,y,z,t - [out] result EC point modified coordinates,
 * @param x,y,z   - [in] EC point1 jacobian coordinates,
 * @param x2,y2   - [in] EC point2 affine coordinates,
 */
void pka_ajm(const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t t, const uint32_t x1,
             const uint32_t y1, const uint32_t z1, const uint32_t x2, const uint32_t y2)
{
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, t, z1, z1);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, x, rn_12, x1);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, rt1, x2, t, x);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, t, z1, t);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, t, y2, t);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, t, rn_4, t);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, t, y1, t);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, z, z1, rt1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt2, rt1, rt1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt1, rt1, rt2);
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, rt1, rn_4, rt1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, y, rt1, y1);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, rt2, x, rt2);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, x, t, t, rt1);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, x, rt2, x);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, x, rt2, x);
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rt2, x, rt2);
    PKA_MOD_MUL_ACC_NFR(LEN_ID_N_BITS, y, t, rt2, y);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, t, z, z);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, t, t, t);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, t, rec_a, t);
    return;
}

/*
 * The function converts the jacobian EC point to affine representation:
 *   p(x,y,z) -> p(x,y)
 *
 * Part of PKA registers are implicitly defined in pka_ecc_glob_regs_def.h file
 *
 * @param scaProtect - flag defining is SCA protection needed (1) or not (0).
 * @param x - [in/out] coordinate x,
 * @param y - [in/out] coordinate y,
 * @param z - [in] coordinate z.
 */
void pka_a(SaSi_ECPKI_ScaProtection_t scaProtect, const uint32_t x, const uint32_t y, const uint32_t z)
{
// RL check is the pka_inv_fast works right and delete compilation dependence
#ifndef INV_FAST_ALLOWED
    scaProtect = SCAP_Active;
#endif
    if ((scaProtect == SCAP_Inactive)) {
        PKA_MOD_INV(LEN_ID_N_BITS, ra_q, z); // no SCA protect
    } else {
        PKA_MOD_INV_W_EXP(ra_q, z, ra_nm2); // SCA protect
    }

    /* ecc-to-affine */
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, y, y, ra_q);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, ra_q, ra_q, ra_q);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, x, x, ra_q);
    PKA_MOD_MUL_NFR(LEN_ID_N_BITS, y, y, ra_q);

    PKA_REDUCE(LEN_ID_N_BITS, x, x);
    PKA_REDUCE(LEN_ID_N_BITS, y, y);

    return;
}
