/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */
#include "cc_pal_types.h"
#include "cc_ecpki_types.h"


/**************** The domain structure describing *************/
/**
// The structure containing EC domain parameters in little-endian form.
// Elliptic curve: Y^2 = X^3 + A*X + B over prime fild GFp

typedef  struct {

	// Field modulus:  GF_Modulus = P
	uint32_t	ecP [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	// EC equation parameters a, b
	uint32_t	ecA [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	uint32_t	ecB [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	// Order of generator: EC_GenerOrder
	uint32_t	ecOrd [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1];
	// Generator (EC base point) coordinates in projective form
	uint32_t	ecGx [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	uint32_t	ecGy [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	// EC cofactor EC_Cofactor_K
	uint32_t  	ecH;
	// include the specific fields that are used by the low level
	uint32_t      barrTagBuff[CC_PKA_DOMAIN_BUFF_SIZE_IN_WORDS];
	// Size of fields in bits
	uint32_t  	modSizeInBits;
	uint32_t  	ordSizeInBits;
	// Size of each inserted Barret tag in words; 0 - if not inserted
	uint32_t 	barrTagSizeInWords;
	CCEcpkiDomainID_t	DomainID;
	int8_t  name[20];

} CCEcpkiDomain_t;

*/

/***********************************************************************************
 *   Data base of CC_ECPKI_DomainID_secp160r1: structure of type  CCEcpkiDomain_t    *
 *       All data is given in little endian order of words in arrays               *
 ***********************************************************************************/
static const CCEcpkiDomain_t ecpki_domain_secp160r1 = {
	/* Field modulus :  GF_Modulus = P = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF */
	{0x7FFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF},
	/* EC equation parameters a, b  */
	/* a = -3 = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 7FFFFFFC  - big end  from SEC2 */
	{0x7FFFFFFC,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF},
	/* b = 1C97BEFC 54BD7A8B 65ACF89F 81D4D4AD C565FA45  - big end  from SEC2 */
	{0xC565FA45,0x81D4D4AD,0x65ACF89F,0x54BD7A8B,0x1C97BEFC},
	/* Order of generator: 0x0100000000000000000001F4C8F927AED3CA752257  - big end from SEC2 */
	{0xCA752257,0xF927AED3,0x0001F4C8,0x00000000,0x00000000,0x00000001},

	/* Generator  coordinates in affine form: EC_Gener_X, EC_Gener_Y (in ordinary representation) */
	/* X - liitle end */   /* 4A96B568 8EF57328 46646989 68C38BB9 13CBFC82   X - big end  from SEC2 */
	{0x13CBFC82,0x68C38BB9,0x46646989,0x8EF57328,0x4A96B568},
	/* Y - liitle end */   /* 23A62855 3168947D 59DCC912 04235137 7AC5FB32   Y - big end  from SEC2 */
	{0x7AC5FB32,0x04235137,0x59DCC912,0x3168947D,0x23A62855},

	1, /* EC cofactor K */

	/* Barrett tags NP,RP */
	#ifdef CC_SUPPORT_PKA_128_32
	{0x00000040,0x00000000,0x00000000,0x00000000,0x00000080,
		0xD8512C35,0xFE0B3706,0xFFFFFFFF,0xFFFFFFFF,0x000000FF},
	#else  // CC_SUPPORT_PKA_64_16
	{0x00000000,0x00000000,0x00000080,0x00000000, 0x00000000,
		0xFFFFFFFF,0xFFFFFFFF,0x000000FF,0x00000000,0x00000000},
	#endif

	160, /* Size of field modulus in bits */
	161, /* Size of generator in bits */
	5,   /* Size of each inserted Barret tag in words; 0 - if not inserted */

	CC_ECPKI_DomainID_secp160r1,	/* EC Domain identifier - enum */
	"SECG_PRIME_160R1"
};




/**
 @brief    the function returns the domain pointer id the domain is supported for the product;
		otherwise return NULL
 @return   return domain pointer or NULL

*/
const CCEcpkiDomain_t *CC_EcpkiGetSecp160r1DomainP(void)
{
	return &ecpki_domain_secp160r1;
}

