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
 *   Data base of ecpki_domain_secp160r2: structure of type  CCEcpkiDomain_t    *
 *       All data is given in little endian order of words in arrays               *
 ***********************************************************************************/
static const CCEcpkiDomain_t ecpki_domain_secp160r2 = {
	/* Field modulus :  GF_Modulus = P = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73*/
	{0xFFFFAC73,0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF},
	/* EC equation parameters a, b  */
	/* a = -3 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70 = 0  - big end  from SEC2 */
	{0xFFFFAC70,0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF},
	/* b = B4E134D3FB59EB8BAB57274904664D5AF50388BA  - big end  from SEC2 */
	{0xF50388BA,0x04664D5A,0xAB572749,0xFB59EB8B,0xB4E134D3},
	/* Order of generator: 100000000000000000000351EE786A818F3A1A16B  - big end  from SEC2 */
	{0xF3A1A16B,0xE786A818,0x0000351E,0x00000000,0x00000000,0x00000001},

	/* Generator  coordinates in affine form: EC_Gener_X, EC_Gener_Y (in ordinary representation) */
	/* X: 52DCB034293A117E1F4FF11B30F7199D3144CE6D - big end  from SEC2 */
	{0x3144CE6D,0x30F7199D,0x1F4FF11B,0x293A117E,0x52DCB034},
	/* Y: FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E   Y - big end  from SEC2 */
	{0xA7D43F2E,0xF9982CFE,0xE071FA0D,0xE331F296,0xFEAFFEF2},

	1, /* EC cofactor K */

	/* Barrett tags NP,RP */
	#ifdef CC_SUPPORT_PKA_128_32
	{0x00000080,0x00000000,0x00000000,0x00000000,0x00000080,
		0x7957E70C, 0xFFCAE118, 0xFFFFFFFF, 0xFFFFFFFF, 0x000000FF},
	#else  // CC_SUPPORT_PKA_64_16
	{0x00000000,0x00000000,0x00000080,0x00000000, 0x00000000,
		0xFFFFFFFF,0xFFFFFFFF,0x000000FF,0x00000000,0x00000000},
	#endif

	160, /* Size of field modulus in bits */
	161, /* Size of generator in bits */
	5,   /* Size of each inserted Barret tag in words; 0 - if not inserted */

	CC_ECPKI_DomainID_secp160r2,	/* EC Domain identifier - enum */
	"SECG_PRIME_160R2"
};




/**
 @brief    the function returns the domain pointer id the domain is supported for the product;
		otherwise return NULL
 @return   return domain pointer or NULL

*/
const CCEcpkiDomain_t *CC_EcpkiGetSecp160r2DomainP(void)
{
	return &ecpki_domain_secp160r2;
}

