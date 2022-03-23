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
 *   Data base of ssi_ecpki_domain_secp192r1: structure of type  SaSi_ECPKI_Domain_t    *
 *       All data is given in little endian order of words in arrays               *
 * ******************************************************************************** */
static const SaSi_ECPKI_Domain_t ssi_ecpki_domain_secp192r1 = {
    /* Field modulus :  GF_Modulus =  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF - big end */
    { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
    /* EC equation parameters a, b  */
    /* a = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC  - big end  from SEC2 */
    { 0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
    /* b = 64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1 - big end  from SEC2 */
    { 0xC146B9B1, 0xFEB8DEEC, 0x72243049, 0x0FA7E9AB, 0xE59C80E7, 0x64210519 },

    /* Order of generator: FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831 big end  from SEC2 */
    { 0xB4D22831, 0x146BC9B1, 0x99DEF836, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },

    /* Generator  coordinates in affine form: EC_Gener_X, EC_Gener_Y (in ordinary representation) */
    /* 188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012   X - big end  from SEC2 */
    { 0x82FF1012, 0xF4FF0AFD, 0x43A18800, 0x7CBF20EB, 0xB03090F6, 0x188DA80E },
    /* 7192B95FFC8DA78631011ED6B24CDD573F977A11E794811  Y - big end  from SEC2 */
    { 0x1E794811, 0x73F977A1, 0x6B24CDD5, 0x631011ED, 0xFFC8DA78, 0x07192B95 },

    1, /* EC cofactor K */

/* Barrett tags NP,RP */
#ifdef SSI_SUPPORT_PKA_128_32
    { 0x00000080, 0x00000000, 0x00000000, 0x00000000, 0x00000080, 0x1083E4F5, 0x00000033, 0x00000000, 0x00000000,
      0x00000080 },
#else // SSI_SUPPORT_PKA_64_16
    { 0x00000000, 0x00000000, 0x00000080, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000080, 0x00000000,
      0x00000000 },
#endif

    192, /* Size of field modulus in bits */
    192, /* Size of order of generator in bits */
    5,   /* Size of each inserted Barret tag in words; 0 - if not inserted */

    SaSi_ECPKI_DomainID_secp192r1, /* EC Domain identifier - enum */
    "SECG_PRIME_192R1"             /* NIST_P192 */
};

/*
 @brief    the function returns the domain pointer id the domain is supported for the product;
        otherwise return NULL
 @return   return domain pointer or NULL

*/
const SaSi_ECPKI_Domain_t *SaSi_ECPKI_GetSecp192r1DomainP(void)
{
    return &ssi_ecpki_domain_secp192r1;
}
