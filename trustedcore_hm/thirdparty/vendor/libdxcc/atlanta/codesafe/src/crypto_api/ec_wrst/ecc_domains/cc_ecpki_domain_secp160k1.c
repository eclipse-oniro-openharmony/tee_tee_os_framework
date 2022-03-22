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
 *   Data base of CC_ECPKI_DomainID_secp160k1: structure of type  CCEcpkiDomain_t    *
 *       All data is given in little endian order of words in arrays               *
 ***********************************************************************************/
static const CCEcpkiDomain_t ecpki_domain_secp160k1 = {

	/* Field modulus :  GF_Modulus = P = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73*/
	{0xFFFFAC73,0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF},
	/* EC equation parameters a, b  */
	/* a =  0  - big end  from SEC2 */
	{0x00000000},
	/* b = 7  - big end  from SEC2 */
	{0x00000007},
	/* Order of generator: 100000000000000000001B8FA16DFAB9ACA16B6B3  - big end  from SEC2 */
	{0xCA16B6B3,0x16DFAB9A,0x0001B8FA,0x00000000,0x00000000,0x00000001},

	/* Generator  coordinates in affine form: EC_Gener_X, EC_Gener_Y (in ordinary representation) */
	/* X: 3B4C382CE37AA192A4019E763036F4F5DD4D7EBB - big end  from SEC2 */
	{0xDD4D7EBB,0x3036F4F5,0xA4019E76,0xE37AA192,0x3B4C382C},
	/* Y: 938CF935318FDCED6BC28286531733C3F03C4FEE   Y - big end  from SEC2 */
	{0xF03C4FEE,0x531733C3,0x6BC28286,0x318FDCED,0x938CF935},

	1, /* EC cofactor H */

	/* Barrett tags NP,RP */
	#ifdef CC_SUPPORT_PKA_128_32
	{0x00000080,0x00000000,0x00000000,0x00000000,0x00000080,
		//FF FFFFFFFF FFFFFFFF FE4705E9 20546535
		0x20546535,0xFE4705E9,0xFFFFFFFF,0xFFFFFFFF,0x000000FF},
	#else  // CC_SUPPORT_PKA_64_16
	{0x00000000,0x00000000,0x00000080,0x00000000, 0x00000000,
		0xFFFFFFFF,0xFFFFFFFF,0x000000FF,0x00000000,0x00000000},
	#endif


	160, /* Size of field modulus in bits */
	161, /* Size of generator in bits */
	5,   /* Size of each inserted Barret tag in words; 0 - if not inserted */

	CC_ECPKI_DomainID_secp160k1,	/* EC Domain identifier - enum */
	"SECG_PRIME_160K1"
};


/**
 @brief    the function returns the domain pointer id the domain is supported for the product;
		otherwise return NULL
 @return   return domain pointer or NULL

*/
const CCEcpkiDomain_t *CC_EcpkiGetSecp160k1DomainP(void)
{
	return &ecpki_domain_secp160k1;
}

