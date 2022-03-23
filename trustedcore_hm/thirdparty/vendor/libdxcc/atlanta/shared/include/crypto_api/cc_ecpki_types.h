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


#ifndef _CC_ECPKI_TYPES_H
#define _CC_ECPKI_TYPES_H

/*!
@file
@brief This file contains all of the enums and definitions that are used for the CryptoCell ECPKI APIs.
*/

#include "cc_pal_types_plat.h"
#include "cc_hash.h"
#include "cc_pka_defs_hw.h"
#include "cc_pal_compiler.h"

#ifdef __cplusplus
extern "C"
{
#endif


/************************ Defines ******************************/

#define CC_PKA_DOMAIN_LLF_BUFF_SIZE_IN_WORDS (10 + 3*CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS)

/* The type defines integer array of lengths of maximum lengths of EC modulus */
typedef  uint32_t  CCEcpkiArray_t[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];

/**************************************************************************************
 *	              Enumerators
 ***************************************************************************************/

/*------------------------------------------------------------------*/
/*! Enumerator for the EC Domain idetifier
   References: [13] - SEC 2: Recommended elliptic curve domain parameters.
                      Version 1.0. Certicom 2000.
               [8]  - WAP-261-WTLS-20010406-a, Version 06-April-2001.     */

typedef enum
{
	/* For prime field */
	CC_ECPKI_DomainID_secp160k1,   /*!< EC secp160r1 */
	CC_ECPKI_DomainID_secp160r1,   /*!< EC secp160k1 */
	CC_ECPKI_DomainID_secp160r2,   /*!< EC secp160r2 */
	CC_ECPKI_DomainID_secp192k1,   /*!< EC secp192k1 */
	CC_ECPKI_DomainID_secp192r1,   /*!< EC secp192r1 */
	CC_ECPKI_DomainID_secp224k1,   /*!< EC secp224k1 */
	CC_ECPKI_DomainID_secp224r1,   /*!< EC secp224r1 */
	CC_ECPKI_DomainID_secp256k1,   /*!< EC secp256k1 */
	CC_ECPKI_DomainID_secp256r1,   /*!< EC secp256r1 */
	CC_ECPKI_DomainID_secp384r1,   /*!< EC secp384r1 */
	CC_ECPKI_DomainID_secp521r1,   /*!< EC secp521r1 */

	CC_ECPKI_DomainID_Builded,     /*!< User given, not identified. */
	CC_ECPKI_DomainID_OffMode,

	CC_ECPKI_DomainIDLast      = 0x7FFFFFFF,

}CCEcpkiDomainID_t;


/*------------------------------------------------------------------*/
/*! Defines the enum for the HASH operation mode.
 *  The enumerator defines 6 HASH modes according to IEEE 1363.
 *
 */
typedef enum
{
	CC_ECPKI_HASH_SHA1_mode    = 0,		/*!< HASH SHA1 mode. */
	CC_ECPKI_HASH_SHA224_mode  = 1,		/*!< HASH SHA224 mode. */
	CC_ECPKI_HASH_SHA256_mode  = 2,		/*!< HASH SHA256 mode. */
	CC_ECPKI_HASH_SHA384_mode  = 3,		/*!< HASH SHA384 mode. */
	CC_ECPKI_HASH_SHA512_mode  = 4,		/*!< HASH SHA512 mode. */

	CC_ECPKI_AFTER_HASH_SHA1_mode    = 5, 	/*!< After HASH SHA1 mode (message was already hashed). */
	CC_ECPKI_AFTER_HASH_SHA224_mode  = 6,	/*!< After HASH SHA224 mode (message was already hashed). */
	CC_ECPKI_AFTER_HASH_SHA256_mode  = 7,	/*!< After HASH SHA256 mode (message was already hashed). */
	CC_ECPKI_AFTER_HASH_SHA384_mode  = 8,	/*!< After HASH SHA384 mode (message was already hashed). */
	CC_ECPKI_AFTER_HASH_SHA512_mode  = 9,	/*!< After HASH SHA512 mode (message was already hashed). */


	CC_ECPKI_HASH_NumOfModes,
	CC_ECPKI_HASH_OpModeLast        = 0x7FFFFFFF,

}CCEcpkiHashOpMode_t;


/*---------------------------------------------------*/
/*! Enumerator for the EC point compression idetifier. */
typedef enum
{
	CC_EC_PointCompressed     = 2,
	CC_EC_PointUncompressed   = 4,
	CC_EC_PointContWrong      = 5, /* wrong Point Control value */
	CC_EC_PointHybrid         = 6,

	CC_EC_PointCompresOffMode = 8,

	CC_ECPKI_PointCompressionLast= 0x7FFFFFFF,

}CCEcpkiPointCompression_t;

/*----------------------------------------------------*/
/*  Enumerator for compatibility of the DHC
   with cofactor multiplication to DH ordinary */
typedef enum
{
	CC_ECPKI_SVDP_DHC_CompatibleDH         = 0,   /* Requested compatiblity of SVDP_DHC with cofactor to SVDP_DH */
	CC_ECPKI_SVDP_DHC_NonCompatibleDH	    = 1,   /* Compatiblity of SVDP_DHC with cofactor to SVDP_DH is not requested */

	CC_ECPKI_SVDP_DHC_OffMode,

	CC_ECPKI_SVDP_DHC_OpModeLast         = 0x7FFFFFFF,

}CCEcpkiSvdpDhcOpMode_t;

/*----------------------------------------------------*/
/* Enumerator for indication what checking of EC public key must be performed */
typedef enum {
	CheckPointersAndSizesOnly = 0,   /* Only preliminary input parameters checking */
	ECpublKeyPartlyCheck      = 1,   /* In addition check that EC PubKey is point on curve */
	ECpublKeyFullCheck        = 2,   /* In addition check that EC_GeneratorOrder*PubKey = O */

	PublKeyChecingOffMode,
	EC_PublKeyCheckModeLast  = 0x7FFFFFFF,
}ECPublKeyCheckMode_t;

/*----------------------------------------------------*/
/* This SCAP is related to included SCA_PROTECTION measures in   *
*  SW part of algoritthms but not in HW itself 			 */
typedef enum {
	SCAP_Inactive,
	SCAP_Active,
	SCAP_OFF_MODE,
	SCAP_LAST = 0x7FFFFFFF
}CCEcpkiScaProtection_t;


/**************************************************************************************
 *	             EC  Domain structure definition
 ***************************************************************************************/

/*! The structure containing the EC domain parameters in little-endian form
    EC equation: Y^2 = X^3 + A*X + B over prime fild GFp. */
typedef  struct {

	/*! EC modulus: P. */
	uint32_t	ecP [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	/*! EC equation parameters a, b. */
	uint32_t	ecA [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	uint32_t	ecB [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	/*! Order of generator. */
	uint32_t	ecR [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1];
	/*! EC cofactor EC_Cofactor_K
	    Generator (EC base point) coordinates in projective form. */
	uint32_t	ecGx [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	uint32_t	ecGy [CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	uint32_t  	ecH;
	/*! include the specific fields that are used by the low level.*/
	uint32_t      llfBuff[CC_PKA_DOMAIN_LLF_BUFF_SIZE_IN_WORDS];
	/*! Size of fields in bits. */
	uint32_t  	modSizeInBits;
	uint32_t  	ordSizeInBits;
	/*! Size of each inserted Barret tag in words; 0 - if not inserted.*/
	uint32_t 	barrTagSizeInWords;
	/*! EC Domain identifier.*/
	CCEcpkiDomainID_t	DomainID;
	int8_t name[20];

}CCEcpkiDomain_t;



/**************************************************************************************
 *	             EC  point structures definitions
 ***************************************************************************************/

/*! The structure containing the EC point in affine coordinates
   and little endian form. */
typedef  struct
{
	/*! Point coordinates. */
	uint32_t x[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	uint32_t y[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];

}CCEcpkiPointAffine_t;


/**************************************************************************************
 *	              ECPKI public and private key  Structures
 ***************************************************************************************/

/* --------------------------------------------------------------------- */
/* .................. The public key structures definitions ............ */
/* --------------------------------------------------------------------- */

/*! The structure containing the Public Key in affine coordinates.*/

/*   Size = 2*CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1 +
   ( sizeof(LLF_ECPKI_publ_key_db_def.h) = 0 ).          */

typedef  struct
{
	/*! Public Key coordinates. */
	uint32_t x[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	uint32_t y[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
	CCEcpkiDomain_t  domain;
	uint32_t pointType;
} CCEcpkiPublKey_t;


/*! The user structure containing EC public key data base form.*/

/*   Size = 2*CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 2 +
   ( sizeof(LLF_ECPKI_publ_key_db_def.h) = 0 ).          */

typedef struct   CCEcpkiUserPublKey_t
{
	uint32_t 	valid_tag;
	uint32_t  	PublKeyDbBuff[(sizeof(CCEcpkiPublKey_t)+3)/4];

} CCEcpkiUserPublKey_t;


/* --------------------------------------------------------------------- */
/* .................. The private key structures definitions ........... */
/* --------------------------------------------------------------------- */

/*! The EC private key structure in little endian form.*/

/*   Size = CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 2 +
   ( sizeof(LLF_ECPKI_priv_key_db_def.h) = 0 ).        */
typedef  struct
{
	/*! Private Key data. */
	uint32_t  PrivKey[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1];
	CCEcpkiDomain_t  domain;
	CCEcpkiScaProtection_t  scaProtection;

}CCEcpkiPrivKey_t;


/*! The user structure containing EC private key data base in little endian form. */

/*   Size = CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 3 +
   ( sizeof(LLF_ECPKI_priv_key_db_def.h) = 0 )          */
typedef struct   CCEcpkiUserPrivKey_t
{
	uint32_t    valid_tag;
	uint32_t    PrivKeyDbBuff[(sizeof(CCEcpkiPrivKey_t)+3)/4];

}  CCEcpkiUserPrivKey_t;

/*!  The ECDH temporary data type  */
typedef struct CCEcdhTempData_t
{
	uint32_t ccEcdhIntBuff[CC_PKA_ECDH_BUFF_MAX_LENGTH_IN_WORDS];
}CCEcdhTempData_t;

typedef struct CCEcpkiBuildTempData_t
{
	uint32_t  ccBuildTmpIntBuff[CC_PKA_ECPKI_BUILD_TMP_BUFF_MAX_LENGTH_IN_WORDS];
}CCEcpkiBuildTempData_t;



/**************************************************************************
 *	              CryptoCell ECDSA context structures
 **************************************************************************/

/* --------------------------------------------------------------------- */
/*                CryptoCell ECDSA Signing context structure                   */
/* --------------------------------------------------------------------- */

typedef uint32_t CCEcdsaSignIntBuff_t[CC_PKA_ECDSA_SIGN_BUFF_MAX_LENGTH_IN_WORDS];
typedef  struct
{
	/* A user's buffer for the Private Key Object -*/
	CCEcpkiUserPrivKey_t     ECDSA_SignerPrivKey;

	/*HASH specific data and buffers */
	CCHashUserContext_t      hashUserCtxBuff;
	CCHashResultBuf_t        hashResult;
	uint32_t             	 hashResultSizeWords;
	CCEcpkiHashOpMode_t	 hashMode;

	CCEcdsaSignIntBuff_t 	 ecdsaSignIntBuff;
}EcdsaSignContext_t;


/* --------------------------------------------------------------------- */
/*                ECDSA  Signing User context database              */
/* --------------------------------------------------------------------- */


typedef struct  CCEcdsaSignUserContext_t
{
	uint32_t  context_buff [(sizeof(EcdsaSignContext_t)+3)/4];
	uint32_t  valid_tag;
} CCEcdsaSignUserContext_t;



/****************************************************************************/

/* --------------------------------------------------------------------- */
/*                ECDSA Verifying context structure                 */
/* --------------------------------------------------------------------- */

typedef uint32_t CCEcdsaVerifyIntBuff_t[CC_PKA_ECDSA_VERIFY_BUFF_MAX_LENGTH_IN_WORDS];

typedef  struct
{
	/* A user's buffer for the Private Key Object -*/
	CCEcpkiUserPublKey_t        ECDSA_SignerPublKey;

	/*HASH specific data and buffers */
	CCHashUserContext_t         hashUserCtxBuff;
	CCHashResultBuf_t           hashResult;
	uint32_t                    hashResultSizeWords;
	CCEcpkiHashOpMode_t    	    hashMode;

	CCEcdsaVerifyIntBuff_t 	    ccEcdsaVerIntBuff;

}EcdsaVerifyContext_t;


/* --------------------------------------------------------------------- */
/*                ECDSA Verifying User context database             */
/* --------------------------------------------------------------------- */

typedef struct  CCEcdsaVerifyUserContext_t
{
	uint32_t  	context_buff[(sizeof(EcdsaVerifyContext_t)+3)/4];
	uint32_t 	valid_tag;
}CCEcdsaVerifyUserContext_t;


/* --------------------------------------------------------------------- */
/* .................. key generation temp buffer   ........... */
/* --------------------------------------------------------------------- */

/*! The ECPKI KG temporary data type */
typedef struct CCEcpkiKgTempData_t
{
	uint32_t ccKGIntBuff[CC_PKA_KG_BUFF_MAX_LENGTH_IN_WORDS];
}CCEcpkiKgTempData_t;


typedef struct CCEciesTempData_t {

	CCEcpkiUserPrivKey_t   PrivKey;
	CCEcpkiUserPublKey_t   PublKey;
	uint32_t  zz[3*CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1];
	union {
		CCEcpkiBuildTempData_t buildTempbuff;
		CCEcpkiKgTempData_t    KgTempBuff;
		CCEcdhTempData_t       DhTempBuff;
	} tmp;

}CCEciesTempData_t;


/* --------------------------------------------------------------------- */
/* .................. defines for FIPS      ........... */
/* --------------------------------------------------------------------- */

#define CC_ECPKI_FIPS_ORDER_LENGTH (256/CC_BITS_IN_BYTE)  // the order of secp256r1 in bytes

/*! Required for internal FIPS verification for ECPKI key generation. */
typedef struct CCEcpkiKgFipsContext_t
{
	union {
		CCEcdsaSignUserContext_t	signCtx;
		CCEcdsaVerifyUserContext_t  verifyCtx;
	}operationCtx;
	uint32_t	signBuff[2*CC_ECPKI_ORDER_MAX_LENGTH_IN_WORDS];
}CCEcpkiKgFipsContext_t;



/*! Required for internal FIPS verification for ECDSA KAT.      *
*  The ECDSA KAT tests defined for domain 256r1.     */
typedef struct CCEcdsaFipsKatContext_t{
	union {
		struct {
			CCEcpkiUserPrivKey_t   	PrivKey;
			CCEcdsaSignUserContext_t	signCtx;
		}userSignData;
		struct {
			CCEcpkiUserPublKey_t   	PublKey;
			union {
				CCEcdsaVerifyUserContext_t  verifyCtx;
				CCEcpkiBuildTempData_t	tempData;
			}buildOrVerify;
		}userVerifyData;
	}keyContextData;

	uint8_t			signBuff[2*CC_ECPKI_FIPS_ORDER_LENGTH];
}CCEcdsaFipsKatContext_t;

/*! Required for internal FIPS verification for ECDH KAT. */
typedef struct CCEcdhFipsKatContext_t{
	CCEcpkiUserPublKey_t  pubKey;
	CCEcpkiUserPrivKey_t  privKey;
	union {
		CCEcpkiBuildTempData_t  ecpkiTempData;
		CCEcdhTempData_t      ecdhTempBuff;
	}tmpData;
	uint8_t			  secretBuff[CC_ECPKI_FIPS_ORDER_LENGTH];
}CCEcdhFipsKatContext_t;

#ifdef __cplusplus
}
#endif

#endif
