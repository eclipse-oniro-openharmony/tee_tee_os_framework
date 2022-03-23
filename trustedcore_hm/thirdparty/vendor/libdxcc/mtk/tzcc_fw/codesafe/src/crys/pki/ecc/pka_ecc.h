/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef PKA_ECC_H_H
#define PKA_ECC_H_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */
#include "ssi_pal_types.h"
#include "sasi_ecpki_types.h"
#include "pka_hw_defs.h"
#include "pka.h"
#include "pka_ut.h"

/* ****************   Definitions    ********************* */

#define PKA_ECC_MAX_OPERATION_SIZE_BITS 640 /* for EC 521-bit */

/* maximal size of extended register in "big PKA words" and in 32-bit words:  *
   the size defined according to RSA as more large, and used to define some   *
*  auxiliary buffers sizes                                */
#define PKA_ECC_MAX_REGISTER_SIZE_IN_PKA_WORDS \
    ((PKA_ECC_MAX_OPERATION_SIZE_BITS + PKA_EXTRA_BITS + SASI_PKA_WORD_SIZE_IN_BITS - 1) / SASI_PKA_WORD_SIZE_IN_BITS)
#define PKA_ECC_MAX_REGISTER_SIZE_WORDS (PKA_ECC_MAX_REGISTER_SIZE_IN_PKA_WORDS * (SASI_PKA_WORD_SIZE_IN_BITS / 32))

/* *************************************************** */
/* *************************************************** */

/* affine ec-point in uint32 arrays format) */
typedef struct {
    uint32_t x[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t y[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
} i_point_t;

/* modified jacobian ec-point: X:x/z^2, Y:y/z^3, t:a*z^4 (uint32 arrays) */
typedef struct {
    uint32_t x[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t y[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t z[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t t[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
} i_mpoint_t;

/* EC curve (domain) structure as uint32 array */
typedef struct {
    uint32_t p[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS]; // modulo
    uint32_t a[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t b[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS]; // y^2 = x^3 + a.x + b (mod p)
    uint32_t Gx[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t Gy[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];        // generator
    uint32_t n[SaSi_ECPKI_ORDER_MAX_LENGTH_IN_WORDS];         // ord(G) = n
    uint32_t h[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];         // cofactor: #E = n.h
    uint32_t np[SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS]; // Barrett tag for modulus
    uint32_t nn[SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS]; // Barrett tag for order
} icurve_t;

/* affine ec-point (in PKA format) */
typedef struct {
    uint32_t x, y;
} pka_point_t;

/* jacobian ec-point: X:x/z^2, Y:y/z^3, t:a*z^4 (in PKA format) */
typedef struct {
    uint32_t x, y, z;
} pka_jpoint_t;

/* modified jacobian ec-point: X:x/z^2, Y:y/z^3, t:a*z^4 (in PKA format) */
typedef struct {
    uint32_t x, y, z, t;
} pka_mpoint_t;

/* ******************************************************** */
/* ***        Functions to operate PKA ec-points         ** */
/* ******************************************************** */

/* *   Functions, performing EC doubling, adding, scalar mult.  */
/* *  arguments: a - affine, j - jacobian, m - modified */

/* EC double: modified-modified */
void pka_mm(const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t t, const uint32_t x1,
            const uint32_t y1, const uint32_t z1, const uint32_t t1);
/* EC add: jacobi-jacobi-modified */
void pka_jjm(const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t t, const uint32_t x1,
             const uint32_t y1, const uint32_t z1, const uint32_t x2, const uint32_t y2, const uint32_t z2);
/* EC add: jacobi-jacobi-jacobi */
void pka_jjj(const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t x1, const uint32_t y1,
             const uint32_t z1, const uint32_t x2, const uint32_t y2, const uint32_t z2);

/* t can be aliased */
/* EC double: modified-modified */
void pka_mm1(const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t t, const uint32_t x1,
             const uint32_t y1, const uint32_t z1, const uint32_t t1);
/* EC double: modified-jacobi */
void pka_mj(const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t x1, const uint32_t y1,
            const uint32_t z1, const uint32_t t1);
/* EC add: affine-jacobi-modified */
void pka_ajm(const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t t, const uint32_t x1,
             const uint32_t y1, const uint32_t z1, const uint32_t x2, const uint32_t y2);

/* convert to affine */
void pka_a(SaSi_ECPKI_ScaProtection_t fr, const uint32_t x, const uint32_t y, const uint32_t z);
/* EC add: affine-affine-affine */
void pka_aaa(const uint32_t x, const uint32_t y, const uint32_t x1, const uint32_t y1, const uint32_t x2,
             const uint32_t y2);

/* EC scalar multiplication: p = k*p, with SCA-protection features */
void pka_smul(void);

/* EC scalar multiplication: r = k*p, k in NAF, not SCA-resistant */
void pka_smula(const uint32_t xr, const uint32_t yr, const char *k, const uint32_t xp, const uint32_t yp);

/* double EC scalar multiplication: R = a*p + b*q */
uint32_t pka_2mul(const uint32_t xr, const uint32_t yr, const uint32_t a, const uint32_t xp, const uint32_t yp,
                  const uint32_t b, const uint32_t xq, const uint32_t yq);

#ifdef __cplusplus
}

#endif

#endif
