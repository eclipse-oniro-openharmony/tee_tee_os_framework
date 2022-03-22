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

#ifndef _CC_RSA_TYPES_H
#define _CC_RSA_TYPES_H

#include "cc_hash.h"
#include "cc_pka_defs_hw.h"
#include "cc_pal_types.h"
#include "cc_pal_compiler.h"

#ifdef CC_SOFT_KEYGEN
#include "ccsw_rsa_shared_types.h"
#endif


#ifdef __cplusplus
extern "C"
{
#endif
/*!
@file
@brief This file contains all of the enums and definitions that are used for the CryptoCell RSA APIs.
*/

/************************ Defines ******************************/

/* Adjust the context size to the HAH context size in TEE */
#define CC_PKA_RSA_HASH_CTX_SIZE_IN_WORDS CC_HASH_USER_CTX_SIZE_IN_WORDS

/* maximal allowed key size in words */
#define CC_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES    (CC_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS / CC_BITS_IN_BYTE)

#define CC_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS              512
#define CC_RSA_VALID_KEY_SIZE_MULTIPLE_VALUE_IN_BITS         256


#define CC_RSA_MAX_KEY_GENERATION_SIZE_BITS   CC_RSA_MAX_KEY_GENERATION_HW_SIZE_BITS

/* FIPS 184-4 definitions for allowed RSA and FFC DH key sizes */
#define CC_RSA_FIPS_KEY_SIZE_1024_BITS   1024
#define CC_RSA_FIPS_KEY_SIZE_2048_BITS   2048
#define CC_RSA_FIPS_KEY_SIZE_3072_BITS   3072
#define CC_RSA_FIPS_MODULUS_SIZE_BITS    CC_RSA_FIPS_KEY_SIZE_2048_BITS

#define CC_DH_FIPS_KEY_SIZE_1024_BITS    1024
#define CC_DH_FIPS_KEY_SIZE_2048_BITS    2048


/* If the salt length is not available in verify than the user can use this define and the algorithm will */
/* calculate the salt length alone*/
/* Security Note: it is recommended not to use this flag and to support the Salt length on each verify*/
#define CC_RSA_VERIFY_SALT_LENGTH_UNKNOWN                     0xFFFF

/* The minimum exponents values */
#define CC_RSA_MIN_PUB_EXP_VALUE  3
#define CC_RSA_MIN_PRIV_EXP_VALUE 1

/* The maximum buffer size for the 'H' value */

#define CC_RSA_TMP_BUFF_SIZE (CC_RSA_OAEP_ENCODE_MAX_MASKDB_SIZE + CC_RSA_OAEP_ENCODE_MAX_SEEDMASK_SIZE + CC_PKA_RSA_HASH_CTX_SIZE_IN_WORDS*sizeof(uint32_t) + sizeof(CCHashResultBuf_t))

#define CCPkcs1HashFunc_t CCHashOperationMode_t


#define CC_RSA_OAEP_MAX_HLEN							CC_HASH_SHA512_DIGEST_SIZE_IN_BYTES

/* MGF1 declarations */
#define CC_RSA_MGF_2_POWER_32              			65535 /*!< \internal 0xFFFF This is the 2^32 of the 2^32*hLen boundary check */
#define CC_RSA_SIZE_OF_T_STRING_BYTES	    			(CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS*sizeof(uint32_t))

/***********************************************************
 *
 * RSA PKCS#1 v2.1 DEFINES
 *
 ***********************************************************/
#define CC_RSA_OAEP_ENCODE_MAX_SEEDMASK_SIZE 			CC_RSA_OAEP_MAX_HLEN
#define CC_RSA_PSS_SALT_LENGTH 					CC_RSA_OAEP_MAX_HLEN
#define CC_RSA_PSS_PAD1_LEN					8

#define CC_RSA_OAEP_ENCODE_MAX_MASKDB_SIZE  			(CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS*sizeof(uint32_t)) /*!< \internal For OAEP Encode; the max size is emLen */
#define CC_RSA_OAEP_DECODE_MAX_DBMASK_SIZE  			(CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS*sizeof(uint32_t)) /*!< \internal For OAEP Decode; the max size is emLen */

/************************ Enums ********************************/

/*! Defines the enum for the HASH operation mode. */
typedef enum
{
	CC_RSA_HASH_MD5_mode  = 0,	/*!< MD5 mode for PKCS1 v1.5 only. */
	CC_RSA_HASH_SHA1_mode = 1,	/*!< HASH SHA1. */
	CC_RSA_HASH_SHA224_mode = 2,    /*!< HASH SHA224. */
	CC_RSA_HASH_SHA256_mode = 3,    /*!< HASH SHA256. */
	CC_RSA_HASH_SHA384_mode = 4,    /*!< HASH SHA384. */
	CC_RSA_HASH_SHA512_mode = 5,	/*!< HASH SHA512. */
	CC_RSA_After_MD5_mode = 6,		/*!< For PKCS1 v1.5 only when the data is already hashed with MD5. */
	CC_RSA_After_SHA1_mode = 7,	/*!< To be used when the data is already hashed with SHA1. */
	CC_RSA_After_SHA224_mode = 8,	/*!< To be used when the data is already hashed with SHA224. */
	CC_RSA_After_SHA256_mode = 9,	/*!< To be used when the data is already hashed with SHA256. */
	CC_RSA_After_SHA384_mode = 10,	/*!< To be used when the data is already hashed with SHA384. */
	CC_RSA_After_SHA512_mode = 11,	/*!< To be used when the data is already hashed with SHA512. */
	CC_RSA_After_HASH_NOT_KNOWN_mode = 12,    /*!< \internal used only for PKCS#1 Ver 1.5 - possible to perform verify operation without hash mode input,
						the hash mode is derived from the signature.*/
	CC_RSA_HASH_NO_HASH_mode = 13,	/*!< Used for PKCS1 v1.5 Encrypt and Decrypt.*/
	CC_RSA_HASH_NumOfModes,

	CC_RSA_HASH_OpModeLast  = 0x7FFFFFFF,

}CCRsaHashOpMode_t;


/*! Defines the enum of the RSA decryption mode. */
typedef enum
{
	CC_RSA_NoCrt = 10,
	CC_RSA_Crt   = 11,

	CC_RSADecryptionNumOfOptions,

	CC_RSA_DecryptionModeLast= 0x7FFFFFFF,

}CCRsaDecryptionMode_t;

/* the Key source enum */
typedef enum
{
	CC_RSA_ExternalKey = 1,
	CC_RSA_InternalKey = 2,

	CC_RSA_KeySourceLast= 0x7FFFFFFF,

}CCRsaKeySource_t;

/*! MGF values. */
typedef enum
{
	CC_PKCS1_MGF1 = 0,
	CC_PKCS1_NO_MGF = 1,
	CC_RSA_NumOfMGFFunctions,

	CC_PKCS1_MGFLast= 0x7FFFFFFF,

}CCPkcs1Mgf_t;

/*! Defines the enum of the various PKCS1 versions. */
typedef enum
{
	CC_PKCS1_VER15 = 0,
	CC_PKCS1_VER21 = 1,

	CC_RSA_NumOf_PKCS1_versions,

	CC_PKCS1_versionLast= 0x7FFFFFFF,

}CCPkcs1Version_t;


/* enum defining primality testing mode in Rabin-Miller
   and Lucas-Lehmer tests */
typedef enum
{
        /* P and Q primes */
	CC_RSA_PRIME_TEST_MODE     = 0,

        /* FFC (DH, DSA) primes */
	CC_DH_PRIME_TEST_MODE      = 1,

	CC_RSA_DH_PRIME_TEST_OFF_MODE

}CCRsaDhPrimeTestMode_t;

/************************ Public and private key database Structs ******************************/

/* .................. The public key definitions ...................... */
/* --------------------------------------------------------------------- */

/* The public key data structure */
typedef struct
{
	/* The RSA modulus buffer and its size in bits */
	uint32_t n[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
	uint32_t nSizeInBits;

	/* The RSA public exponent buffer and its size in bits */
	uint32_t e[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
	uint32_t eSizeInBits;

	/* #include the specific fields that are used by the low level */
	uint32_t ccRSAIntBuff[CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS];

}CCRsaPubKey_t;

/*! The public key's user structure prototype. */
typedef struct CCRsaUserPubKey_t
{
	uint32_t valid_tag;
	uint32_t  PublicKeyDbBuff[ sizeof(CCRsaPubKey_t)/sizeof(uint32_t) + 1 ];


}CCRsaUserPubKey_t;

/* .................. The private key definitions ...................... */
/* --------------------------------------------------------------------- */

/* The private key on non-CRT mode data structure */
typedef struct
{
	/* The RSA private exponent buffer and its size in bits */
	uint32_t d[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
	uint32_t dSizeInBits;

	/* The RSA public exponent buffer and its size in bits */
	uint32_t e[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
	uint32_t eSizeInBits;

}CCRsaPrivNonCrtKey_t;

/* The private key on CRT mode data structure */
/* use small CRT buffers */
typedef struct
{
	/* The first factor buffer and size in bits */
	uint32_t P[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS/2];
	uint32_t PSizeInBits;

	/* The second factor buffer and its size in bits */
	uint32_t Q[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS/2];
	uint32_t QSizeInBits;

	/* The first CRT exponent buffer and its size in bits */
	uint32_t dP[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS/2];
	uint32_t dPSizeInBits;

	/* The second CRT exponent buffer and its size in bits */
	uint32_t dQ[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS/2];
	uint32_t dQSizeInBits;

	/* The first CRT coefficient buffer and its size in bits */
	uint32_t qInv[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS/2];
	uint32_t qInvSizeInBits;

}CCRsaPrivCrtKey_t;


/* The private key data structure */
typedef struct
{
	/* The RSA modulus buffer and its size in bits */
	uint32_t n[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
	uint32_t nSizeInBits;

	/* The decryption operation mode */
	CCRsaDecryptionMode_t OperationMode;

	/* the source ( Import or Keygen ) */
	CCRsaKeySource_t KeySource;


	/* The union between the CRT and non-CRT data structures */
	union
	{
		CCRsaPrivNonCrtKey_t NonCrt;
		CCRsaPrivCrtKey_t    Crt;
	}PriveKeyDb;

	/* #include specific fields that are used by the low level */
	uint32_t ccRSAPrivKeyIntBuff[CC_PKA_PRIV_KEY_BUFF_SIZE_IN_WORDS];

}CCRsaPrivKey_t;

/*! The private key's user structure prototype. */
typedef struct CCRsaUserPrivKey_t
{
   uint32_t valid_tag;
   uint32_t  PrivateKeyDbBuff[ sizeof(CCRsaPrivKey_t)/sizeof(uint32_t) + 1 ] ;

}CCRsaUserPrivKey_t;

/*! Temporary buffers for RSA usage. */
typedef struct CCRsaPrimeData_t
{
   /* The aligned input and output data buffers */
	uint32_t DataIn[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
	uint32_t DataOut[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];

	uint8_t  InternalBuff[CC_RSA_TMP_BUFF_SIZE] CC_PAL_COMPILER_ALIGN (4);

}CCRsaPrimeData_t;

/* the KG data type */
typedef union CCRsaKgData_t
{
	struct
	{
		/* The aligned input and output data buffers */
		uint32_t p[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
		uint32_t q[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
		union {
			/* #include specific fields that are used by the low level */
			uint32_t ccRSAKGDataIntBuff[CC_PKA_KGDATA_BUFF_SIZE_IN_WORDS];
			#ifdef CC_SOFT_KEYGEN
			/* # added for compatibility with size of KGData SW type */
			uint32_t TempbuffExp[PKI_KEY_GEN_TEMP_BUFF_SIZE_WORDS];
			#endif
		}kg_buf;
	}KGData;

	union {
	        struct {
			CCRsaPrimeData_t   	PrimData;
		}primExt;
		#ifdef CC_SOFT_KEYGEN
		/* # added for compatibility with size of SW CCRsaPrivKey_t type */
	        SwSharedRSAPrimeData_t SW_Shared_PrimData;
		#endif
	}prim;
}CCRsaKgData_t;

 /*************
 *	RSA contexts
 **************/
/************************ CryptoCell RSA struct for Private Key ******************************/



typedef struct
{

	/* A union for the Key Object - there is no need for the Private
	key and the Public key to be in the memory at the same time */
	CCRsaUserPrivKey_t PrivUserKey;

	/* RSA PKCS#1 Version 1.5/2.1 */
	uint8_t   PKCS1_Version;

	/* MGF 2 use for the PKCS1 Ver 2.1 Sign/Verify operation */
	uint8_t MGF_2use;

	/*The Salt random intended length for PKCS#1 PSS Ver 2.1*/
	uint16_t SaltLen;

	/*Struct for the Exp evaluation*/
	CCRsaPrimeData_t  PrimeData;

	/* User Context of the Hash Context - Hash functions get as input a CCHashUserContext_t */
	//CCHashUserContext_t  HashUserContext;
	uint32_t RsaHashCtxBuff[CC_PKA_RSA_HASH_CTX_SIZE_IN_WORDS];
	CCHashResultBuf_t        HASH_Result;
	uint16_t                  HASH_Result_Size;     /*in words*/
	CCRsaHashOpMode_t    RsaHashOperationMode; /*RSA HASH enum. */
	CCHashOperationMode_t HashOperationMode;    /* HASH enum. */
	uint16_t                  HashBlockSize;        /*in words*/
	bool doHash;

	/* Used for sensitive data manipulation in the context space, which is safer and which saves stack space */
	uint32_t EBD[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
	uint32_t EBDSizeInBits;

	/* Used for sensitive data manipulation in the context space, which is safer and which saves stack space */
	uint8_t  T_Buf[CC_RSA_SIZE_OF_T_STRING_BYTES];
	uint16_t T_BufSize;

	/*Buffer for the use of the Ber encoder in the case of PKCS#1 Ver 1.5 - in Private context only*/
	uint32_t  BER[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
	uint16_t  BERSize;

	/* This Buffer is added for encrypting the context. Note: This block must be
	at the end of the context. */
	uint8_t DummyBufAESBlockSize[16];

}RSAPrivContext_t;

/* Temporary buffers for the RSA usage */
typedef struct CCRsaPrivUserContext_t
{
	uint32_t valid_tag;
	uint32_t AES_iv; /* For the use of the AES CBC mode of Encryption and Decryption of the context in CCM */
	uint8_t  context_buff[ sizeof(RSAPrivContext_t) + sizeof(uint32_t)] CC_PAL_COMPILER_ALIGN (4);  /* must be aligned to 4 */

}CCRsaPrivUserContext_t;


/************************ CryptoCell RSA struct for Public Key ******************************/


typedef struct
{

	/* A union for the Key Object - there is no need for the Private
	key and the Public key to be in the memory in the same time */
	CCRsaUserPubKey_t PubUserKey;

	/* public key size in bytes */
	uint32_t nSizeInBytes;

	/* RSA PKCS#1 Version 1.5/2.1 */
	uint8_t   PKCS1_Version;

	/* MGF 2 use for the PKCS1 Ver 2.1 Sign/Verify operation */
	uint8_t MGF_2use;

	/*The Salt random intended length for PKCS#1 PSS Ver 2.1*/
	uint16_t SaltLen;

	/*Struct for the Exp evaluation*/
	CCRsaPrimeData_t  PrimeData;

	/* User Context of the Hash Context - Hash functions get as input a CCHashUserContext_t */
	uint32_t RsaHashCtxBuff[CC_PKA_RSA_HASH_CTX_SIZE_IN_WORDS];

	CCHashResultBuf_t        HASH_Result;
	uint16_t                  HASH_Result_Size; /* denotes the length, in words, of the hash function output */
	CCRsaHashOpMode_t    RsaHashOperationMode; /*RSA HASH enum. */
	CCHashOperationMode_t HashOperationMode;    /* HASH enum. */
	uint16_t                  HashBlockSize; /*in words*/
	bool doHash;

	/* Used for sensitive data manipulation in the context space, which is safer and which saves stack space */
	uint32_t EBD[CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
	uint32_t EBDSizeInBits;

	/* Used for sensitive data manipulation in the context space, which is safer and which saves stack space */
	uint8_t T_Buf[CC_RSA_SIZE_OF_T_STRING_BYTES];
	uint16_t T_BufSize;

	/* This Buffer is added for encrypting the context ( encrypted part's size must be 0 modulo 16).
	* Note: This block must be at the end of the context.
	*/
	uint8_t DummyBufAESBlockSize[16];

}RSAPubContext_t;

/*! Temporary buffers for the RSA usage. */
typedef struct CCRsaPubUserContext_t
{
   uint32_t valid_tag;
   uint32_t AES_iv; /* For the use of the AES CBC mode of Encryption and Decryption of the context in CCM */
   uint32_t  context_buff[ sizeof(RSAPubContext_t)/sizeof(uint32_t) + 1] ;

}CCRsaPubUserContext_t;



/*! Required for internal FIPS verification for RSA key generation. */
typedef struct CCRsaKgFipsContext_t{
	CCRsaPrimeData_t 	primData;
	uint8_t			decBuff[((CC_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS/CC_BITS_IN_BYTE) - 2*(CC_HASH_SHA1_DIGEST_SIZE_IN_BYTES) -2)];
	uint8_t			encBuff[CC_RSA_FIPS_MODULUS_SIZE_BITS/CC_BITS_IN_BYTE];
}CCRsaKgFipsContext_t;

/*! Required for internal FIPS verification for RSA KAT.
    The RSA KAT tests are defined for Public-Key Cryptography Standards (PKCS) #1 RSA Cryptography Specifications Version 2.1
    with modulus key size of 2048.      */
typedef struct CCRsaFipsKatContext_t{
	union {
		CCRsaUserPubKey_t 	userPubKey; 	// used for RsaEnc and RsaVerify
		CCRsaUserPrivKey_t   userPrivKey;  // used for RsaDec and RsaSign
	}userKey;
	union {
		CCRsaPrivUserContext_t userPrivContext;  // used for RsaSign
		CCRsaPubUserContext_t userPubContext;  // used for RsaVerify
		CCRsaPrimeData_t 	primData;  // used for RsaEnc and RsaDec
	}userContext;
	union {
		struct {   // used for RsaEnc and RsaDec
			uint8_t		encBuff[CC_RSA_FIPS_MODULUS_SIZE_BITS/CC_BITS_IN_BYTE];
			uint8_t		decBuff[((CC_RSA_FIPS_MODULUS_SIZE_BITS/CC_BITS_IN_BYTE) - 2*(CC_HASH_SHA1_DIGEST_SIZE_IN_BYTES) -2)];
		}userOaepData;
		uint8_t			signBuff[CC_RSA_FIPS_MODULUS_SIZE_BITS/CC_BITS_IN_BYTE]; // used for RsaSign and RsaVerify
	}userData;
}CCRsaFipsKatContext_t;


#ifdef __cplusplus
}
#endif

#endif
