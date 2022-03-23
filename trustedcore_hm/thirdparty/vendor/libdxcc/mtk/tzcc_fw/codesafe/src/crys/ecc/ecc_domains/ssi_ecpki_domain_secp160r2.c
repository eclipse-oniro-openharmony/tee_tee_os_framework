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
 *   Data base of ssi_ecpki_domain_secp160r2: structure of type  SaSi_ECPKI_Domain_t    *
 *       All data is given in little endian order of words in arrays               *
 * ******************************************************************************** */
static const SaSi_ECPKI_Domain_t ssi_ecpki_domain_secp160r2 = {
    /* Field modulus :  GF_Modulus = P = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73 */
    { 0xFFFFAC73, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
    /* EC equation parameters a, b  */
    /* a = -3 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70 = 0  - big end  from SEC2 */
    { 0xFFFFAC70, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
    /* b = B4E134D3FB59EB8BAB57274904664D5AF50388BA  - big end  from SEC2 */
    { 0xF50388BA, 0x04664D5A, 0xAB572749, 0xFB59EB8B, 0xB4E134D3 },
    /* Order of generator: 100000000000000000000351EE786A818F3A1A16B  - big end  from SEC2 */
    { 0xF3A1A16B, 0xE786A818, 0x0000351E, 0x00000000, 0x00000000, 0x00000001 },

    /* Generator  coordinates in affine form: EC_Gener_X, EC_Gener_Y (in ordinary representation) */
    /* X: 52DCB034293A117E1F4FF11B30F7199D3144CE6D - big end  from SEC2 */
    { 0x3144CE6D, 0x30F7199D, 0x1F4FF11B, 0x293A117E, 0x52DCB034 },
    /* Y: FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E   Y - big end  from SEC2 */
    { 0xA7D43F2E, 0xF9982CFE, 0xE071FA0D, 0xE331F296, 0xFEAFFEF2 },

    1, /* EC cofactor K */

/* Barrett tags NP,RP */
#ifdef SSI_SUPPORT_PKA_128_32
    { 0x00000080, 0x00000000, 0x00000000, 0x00000000, 0x00000080, 0x7957E70C, 0xFFCAE118, 0xFFFFFFFF, 0xFFFFFFFF,
      0x000000FF },
#else // SSI_SUPPORT_PKA_64_16
    { 0x00000000, 0x00000000, 0x00000080, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0x000000FF, 0x00000000,
      0x00000000 },
#endif

    160, /* Size of field modulus in bits */
    161, /* Size of generator in bits */
    5,   /* Size of each inserted Barret tag in words; 0 - if not inserted */

    SaSi_ECPKI_DomainID_secp160r2, /* EC Domain identifier - enum */
    "SECG_PRIME_160R2"
};

/*
 @brief    the function returns the domain pointer id the domain is supported for the product;
        otherwise return NULL
 @return   return domain pointer or NULL

*/
const SaSi_ECPKI_Domain_t *SaSi_ECPKI_GetSecp160r2DomainP(void)
{
    return &ssi_ecpki_domain_secp160r2;
}
