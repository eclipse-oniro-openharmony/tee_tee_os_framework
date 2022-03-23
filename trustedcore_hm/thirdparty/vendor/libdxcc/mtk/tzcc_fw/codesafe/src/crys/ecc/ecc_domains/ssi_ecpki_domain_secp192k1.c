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
#include "ssi_pal_types.h"
#include "sasi_ecpki_types.h"

/* *************** The domain structure describing *********** */
/*
// The structure containing EC domain parameters in little-endian form.
// Elliptic curve: Y^2 = X^3 + A*X + B over prime fild GFp

typedef  struct {

    // Field modulus:  GF_Modulus = P
    uint32_t    ecP [SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    // EC equation parameters a, b
    uint32_t    ecA [SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t    ecB [SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    // Order of generator: EC_GenerOrder
    uint32_t    ecOrd [SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1];
    // Generator (EC base point) coordinates in projective form
    uint32_t    ecGx [SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t    ecGy [SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    // EC cofactor EC_Cofactor_K
    uint32_t      ecH;
    // include the specific fields that are used by the low level
    uint32_t      barrTagBuff[SaSi_PKA_DOMAIN_BUFF_SIZE_IN_WORDS];
    // Size of fields in bits
    uint32_t      modSizeInBits;
    uint32_t      ordSizeInBits;
    // Size of each inserted Barret tag in words; 0 - if not inserted
    uint32_t     barrTagSizeInWords;
    SaSi_ECPKI_DomainID_t    DomainID;
    int8_t  name[20];

} SaSi_ECPKI_Domain_t;

*/

/* **********************************************************************************
 *   Data base of ssi_ecpki_domain_secp192k1: structure of type  SaSi_ECPKI_Domain_t    *
 *       All data is given in little endian order of words in arrays               *
 * ******************************************************************************** */
static const SaSi_ECPKI_Domain_t ssi_ecpki_domain_secp192k1 = {
    /* Field modulus :  GF_Modulus =  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37 - big end */
    { 0xFFFFEE37, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
    /* EC equation parameters a, b  */
    /* a = 0  - big end  from SEC2 */
    { 0x0 },
    /* b = 3 - big end  from SEC2 */
    { 0x3 },
    /* Order of generator: FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D big end  from SEC2 */
    { 0x74DEFD8D, 0x0F69466A, 0x26F2FC17, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF },
    /* Generator  coordinates in affine form: EC_Gener_X, EC_Gener_Y (in ordinary representation) */
    /* DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D   X - big end  from SEC2 */
    { 0xEAE06C7D, 0x1DA5D1B1, 0x80B7F434, 0x26B07D02, 0xC057E9AE, 0xDB4FF10E },
    /* 9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D  Y - big end  from SEC2 */
    { 0xD95E2F9D, 0x4082AA88, 0x15BE8634, 0x844163D0, 0x9C5628A7, 0x9B2F2F6D },
    1, /* EC cofactor K */

/* Barrett tags NP,RP */
#ifdef SSI_SUPPORT_PKA_128_32
    { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000080, 0x8681F478, 0x000000EC, 0x00000000, 0x00000000,
      0x00000080 }, // 80 00000000 00000000 000000EC 8681F478
#else               // SSI_SUPPORT_PKA_64_16
    { 0x00000000, 0x00000000, 0x00000080, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000080, 0x00000000,
      0x00000000 },
#endif

    192, /* Size of field modulus in bits */
    192, /* Size of order of generator in bits */
    5,   /* Size of each inserted Barret tag in words; 0 - if not inserted */

    SaSi_ECPKI_DomainID_secp192k1, /* EC Domain identifier - enum */
    "SECG_PRIME_192K1"
};

/*
 @brief    the function returns the domain pointer id the domain is supported for the product;
        otherwise return NULL
 @return   return domain pointer or NULL

*/
const SaSi_ECPKI_Domain_t *SaSi_ECPKI_GetSecp192k1DomainP(void)
{
    return &ssi_ecpki_domain_secp192k1;
}
