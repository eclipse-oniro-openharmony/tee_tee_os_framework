/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_EC_MONT_API_TW_H
#define SaSi_EC_MONT_API_TW_H

#include "ssi_pal_types.h"
#include "sasi_rnd.h"
#include "sasi_pka_defs_hw.h"

#ifdef __cplusplus
#if __GNUC__
#pragma GCC diagnostic ignored "-Wlong-long"
#endif
extern "C" {
#endif

/* !
@file
@brief This file contains the SaSi APIs used for EC MONT (Montgomery Curve25519) algorithms.

@note  Algorithms of Montgomery and Edwards elliptic curves cryptography are developed by
       Daniel.J.Bernstein and described in SW library "NaCl" (Networking and
       Cryptographic Library).
*/

//#define SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS  18 /* !< \internal [(SaSi_ECPKI_MODUL_MAX_LENGTH_IN_BITS +
//31)/(sizeof(uint32_t)) + 1] */ #define SaSi_ECPKI_ORDER_MAX_LENGTH_IN_WORDS  (SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS +
// 1)

/* !< EC Montgomery curve25519 modulus size in bits, words and bytes  */
#define SaSi_EC_MONT_MOD_SIZE_IN_BITS 255U
#define SaSi_EC_MONT_MOD_SIZE_IN_32BIT_WORDS \
    ((SaSi_EC_MONT_MOD_SIZE_IN_BITS + SASI_BITS_IN_32BIT_WORD - 1) / SASI_BITS_IN_32BIT_WORD)
#define SaSi_EC_MONT_MOD_SIZE_IN_BYTES \
    ((SaSi_EC_MONT_MOD_SIZE_IN_BITS + SASI_BITS_IN_32BIT_WORD - 1) / sizeof(uint32_t))

/* !< Constant sizes of special EC_MONT buffers and arrays  */
#define SaSi_EC_MONT_SCALARBYTES     (SaSi_EC_MONT_MOD_SIZE_IN_32BIT_WORDS * SASI_32BIT_WORD_SIZE)
#define SaSi_EC_MONT_SCALARMULTBYTES (SaSi_EC_MONT_MOD_SIZE_IN_32BIT_WORDS * SASI_32BIT_WORD_SIZE)

/* !< EC Montgomery point 0 (on infinity) coordinates X,Y */
#define EC_MONT_POINT_0_X 1
#define EC_MONT_POINT_0_Y 0

/* *************************************************************************** */
/* *          EC Montgomery domain APIs:                                       */
/* *************************************************************************** */

/* !< EC Montgomery domains ID-s enumerator */
typedef enum {
    SaSi_EC_MONT_DOMAIN_CURVE_25519, /* !< EC Curve25519 */

    SaSi_EC_MONT_DOMAIN_OFF_MODE,
    SaSi_EC_MONT_DOMAIN_LAST = 0x7FFFFFFF
} SasiEcMontDomainId_t;

/* !< EC Montgomery curve domain structure type:
     Elliptic curve over prime fild GFp: y^2 = x^3 + Ax^2 + x */
typedef struct {
    /* !< EC prime modulus P */
    uint32_t ecModP[SaSi_EC_MONT_EDW_MODULUS_MAX_SIZE_IN_WORDS];
    /* !< modulus size in bits */
    uint32_t ecModSizeInBits;
    /* !< modulus size in words */
    uint32_t ecModSizeInWords;
    /* !< EC generator coordinates X */
    uint32_t ecGenX[SaSi_EC_MONT_EDW_MODULUS_MAX_SIZE_IN_WORDS];
    /* !< EC generator coordinates Y */
    uint32_t ecGenY[SaSi_EC_MONT_EDW_MODULUS_MAX_SIZE_IN_WORDS];
    /* !< EC generator order.  */
    uint32_t ecOrdN[SaSi_EC_MONT_EDW_MODULUS_MAX_SIZE_IN_WORDS];
    /* !< EC generator order size in bits */
    uint32_t ecOrdSizeInBits;
    /* !< EC generator order size in words */
    uint32_t ecOrdSizeInWords;
    /* !< EC generator order's cofactor */
    uint32_t ecOrdCofactor;
    /* !< EC equation parameter; (A+2)/4 - for Curve25519 */
    uint32_t ecParam[SaSi_EC_MONT_EDW_MODULUS_MAX_SIZE_IN_WORDS];
    /* !< Barrett tags for EC modulus */
    uint32_t ecModBarrTag[SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS];
    /* !< Barrett tags for EC generator order */
    uint32_t ecOrdBarrTag[SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS];
    /* parameters for bits setting in scalar multiplication LS/MS words */
    uint32_t scalarLsWordAndValue;
    uint32_t scalarMsWordAndValue;
    uint32_t scalarMsWordOrValue;
    /* !< EC Domain ID - enum */
    SasiEcMontDomainId_t domainId;
    /* !< EC Domain name */
    int8_t name[20];
} SasiEcMontDomain_t;

/* !< EC_MONT scalar mult temp buffer type definition */
typedef struct {
    uint32_t ecMontScalarMultTempBuff[SaSi_EC_MONT_TEMP_BUFF_SIZE_IN_32BIT_WORDS]; // ! ! Change as needed
} SasiEcMontScalrMultTempBuff_t;

/* !< EC_MONT temp buffer type definition */
typedef struct {
    /* ! Don't change sequence order of the buffers */
    uint32_t ecMontScalar[SaSi_EC_MONT_EDW_MODULUS_MAX_SIZE_IN_WORDS];
    uint32_t ecMontResPoint[SaSi_EC_MONT_EDW_MODULUS_MAX_SIZE_IN_WORDS];
    uint32_t ecMontInPoint[SaSi_EC_MONT_EDW_MODULUS_MAX_SIZE_IN_WORDS];
    SasiEcMontScalrMultTempBuff_t ecMontScalrMultTempBuff; // ! ???? not needed
} SasiEcMontTempBuff_t;

/* ****************************************************************** */
/* !
@brief The function performs EC Montgomery (Curve25519) scalar multiplication:
       resPoint = scalar * point.

       Libsodium analog: crypto_scalarmult_curve25519() function

 @return SaSiError_t
*/
CIMPORT_C SaSiError_t
SaSi_EC_MONT_Scalarmult(uint8_t *resPoint,      /* !< [out] pointer to the public (secret) key. */
                        size_t *resPointSize,   /* !< [in/out] - the pointer to the size of the public key in bytes.
                                                        in  - the size of buffer must be not less than EC order size;
                                                        out - the actual size. */
                        const uint8_t *scalar,  /* !< [out] pointer to the secret (private) key. */
                        size_t scalarSize,      /* !< [in/out] pointer to the size of the secret key in bytes
                                                     (must be equal EC order size). */
                        const uint8_t *inPoint, /* !< [in] pointer to the input point (compressed). */
                        size_t inPointSize,     /* !< [in] size of the point - must be equal to modulus size. */
                        const SasiEcMontDomain_t *ecDomain, /* !< [in] pointer to EC domain (curve). */
                        SasiEcMontTempBuff_t *ecMontTempBuff /* !< [in] pointer temp buffer. */);

/* ****************************************************************** */
/* !
@brief The function performs EC Montgomery (Curve25519) scalar multiplication of base point:
       res = scalar * base_point.

      Libsodium analog: crypto_scalarmult_curve25519_base() function

@return SaSiError_t
*/
CIMPORT_C SaSiError_t
SaSi_EC_MONT_ScalarmultBase(uint8_t *resPoint,     /* !< [out] pointer to the public (secret) key. */
                            size_t *resPointSize,  /* !< [in/out] - the pointer to the size of the public key in bytes.
                                                           in  - the size of buffer must be not less than EC order size;
                                                           out - the actual size. */
                            const uint8_t *scalar, /* !< [out] pointer to the secret (private) key. */
                            size_t scalarSize,     /* !< [in/out] pointer to the size of the secret key in bytes
                                                        (must be equal than EC order size). */
                            const SasiEcMontDomain_t *ecDomain, /* !< [in] pointer to EC domain (curve). */
                            SasiEcMontTempBuff_t *ecMontTempBuff /* !< [in] pointer temp buffer. */);

/* **************************************************************** */
/* !
@brief The function randomly generates  private and public keys for Montgomery
       Curve25519.

       Libsodium, TweetNaCl analog: crypto_box_seed_keypair().

       Note: 1. All byte arrays have LE order of bytes, i.e. LS byte is on left
             most place.
             2. LS and MS bits of the Secret key are set according to EC
             Montgomery scalar mult. algorithm:
                secrKey[0] &= 248; secrKey[31] &= 127; secrKey[31] |= 64;

@return SaSiError_t
*/
CIMPORT_C SaSiError_t
SaSi_EC_MONT_KeyPair(uint8_t *publKey,               /* !< [out] pointer to the public (secret) key. */
                     size_t *publKeySize,            /* !< [in/out] - the pointer to the size of the public key in bytes.
                                                             in  - the size of buffer must be not less than EC order size;
                                                             out - the actual size. */
                     uint8_t *secrKey,               /* !< [out] pointer to the secret (private) key. */
                     size_t *secrKeySize,            /* !< [in/out] pointer to the size of the secret key in bytes
                                                          (must be not less than EC order size). */
                     SaSi_RND_Context_t *rndContext, /* !< [in/out] pointer to the RND context buffer. */
                     const SasiEcMontDomain_t *ecDomain, /* !< [in] pointer to EC domain (curve). */
                     SasiEcMontTempBuff_t *ecMontTempBuff /* !< [in] pointer to EC domain (curve). */);

/* **************************************************************** */
/* !
@brief The function generates private and public keys for Montgomery algorithms.

       The generation performed using given seed.

       Libsodium, TweetNaCl analog: crypto_box_seed_keypair().

@return SaSi_OK on success,
@return a non-zero value on failure as defined sasi_ec_25519_error.h.
*/
CIMPORT_C SaSiError_t
SaSi_EC_MONT_SeedKeyPair(uint8_t *publKey,    /* !< [out] pointer to the public (secret) key. */
                         size_t *publKeySize, /* !< [in/out] - the pointer to the size of the public key in bytes.
                                                                  in  - the size of buffer must be not less than EC
                                                 order size; out - the actual size. */
                         uint8_t *secrKey,    /* !< [out] pointer to the secret (private) key. */
                         size_t *secrKeySize, /* !< [in/out] pointer to the size of the secret key in bytes
                                                   (must be not less than EC order size). */
                         const uint8_t *seed, /* !< [in] pointer to the given seed - 32 bytes. */
                         size_t seedSize,     /* !< [in/] size of the seed in bytes (must be equal the EC order size). */
                         const SasiEcMontDomain_t *ecDomain, /* !< [in] pointer to EC domain (curve) */
                         SasiEcMontTempBuff_t *ecMontTempBuff /* !< [in] pointer temp buffer. */);

/* !<
 @brief    The function returns EC_MONT domain pointer.

 @return   returns domain pointer or NULL if this domain not exists.

*/
const SasiEcMontDomain_t *SaSi_EC_MONT_GetEcDomain(SasiEcMontDomainId_t domainId);

#ifdef __cplusplus
}
#endif

#endif
