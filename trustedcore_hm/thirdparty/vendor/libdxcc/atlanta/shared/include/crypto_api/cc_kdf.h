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

#ifndef _CC_KDF_H
#define _CC_KDF_H


#include "cc_hash.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file defines the API that supports Key derivation function in modes
       as defined in Public-Key Cryptography Standards (PKCS) #3: Diffie-Hellman Key Agreement Standard,
       ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography,
       and ANSI X9.63-2011: Public Key Cryptography for the Financial Services Industry - Key Agreement and Key Transport Using Elliptic Curve
       Cryptography.
*/

#include "cc_hash.h"

/************************ Defines ******************************/

/* Shared secret value max size in bytes: must be defined according to      *
*  DH max. modulus size definition!     				    */
#define  CC_KDF_MAX_SIZE_OF_SHARED_SECRET_VALUE  1024 /*!< Size is in bytes*/

/* Count and max. sizeof OtherInfo entries (pointers to data buffers) */
#define  CC_KDF_COUNT_OF_OTHER_INFO_ENTRIES   5

/* Max size of keying data in bytes to generate */
#define  CC_KDF_MAX_SIZE_OF_KEYING_DATA  2048
/* Size of KDF counter in bytes */
#define CC_KDF_COUNTER_SIZE_IN_BYTES  4

/************************ Enums ********************************/

/* KDF Hash mode enumerator */
typedef enum
{
	CC_KDF_HASH_SHA1_mode    = 0,
	CC_KDF_HASH_SHA224_mode	 = 1,
	CC_KDF_HASH_SHA256_mode	 = 2,
	CC_KDF_HASH_SHA384_mode	 = 3,
	CC_KDF_HASH_SHA512_mode	 = 4,

	CC_KDF_HASH_NumOfModes,
	CC_KDF_HASH_OpModeLast = 0x7FFFFFFF,

}CCKdfHashOpMode_t;

/* KDF derivation modes enumerator */
typedef enum
{
	CC_KDF_ASN1_DerivMode    = 0,
	CC_KDF_ConcatDerivMode   = 1,
	CC_KDF_X963_DerivMode    = CC_KDF_ConcatDerivMode,
	CC_KDF_ISO18033_KDF1_DerivMode = 3,
	CC_KDF_ISO18033_KDF2_DerivMode = 4,

	CC_KDF_DerivFunc_NumOfModes = 5,
	CC_KDF_DerivFuncModeLast= 0x7FFFFFFF,

}CCKdfDerivFuncMode_t;

/* KDF enumerator of Symmetric Algorithmsm for which intended
   the key to be derivated */
typedef enum
{
	CC_KDF_ALGORITHM_ID     = 0, /* An identifier (OID), indicating algorithm for which the keying data is used */
	CC_KDF_PARTY_U_INFO     = 1, /* Optional data of party U */
	CC_KDF_PARTY_V_INFO     = 2, /* Optional data of party V */
	CC_KDF_SUPP_PRIV_INFO   = 3, /* Optional supplied private shared data */
	CC_KDF_SUPP_PUB_INFO    = 4, /* Optional supplied public shared data */

	CC_KDF_MAX_COUNT_OF_ENTRIES,  /* Max. allowed count of entries in Other Info */

	CC_KDF_ENTRYS_MAX_VAL  = 0x7FFFFFFF,

}CCKdfOtherInfoEntries_t;
/************************ Typedefs  ****************************/

/*! KDF used structure, containing the pointers to OtherInfo data entries and sizes.

   The structure containing two arrays: for data pointers and for sizes, placed according
   to order given in the the ANSI X9.42-2003: Public Key Cryptography for the Financial Services
   Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography standard
   and defined in CCKdfOtherInfoEntries_t enumerator.
   On KDF ASN1 mode this order is mandatory.   On other KDF modes the user may insert
   optional OtherInfo simply in one (prferably first) or in some entries
   If any data entry is not used, then the pointer value and the size must be set to NULL. */
typedef struct
{
        /* pointers to data entries */
        uint8_t  *dataPointers[CC_KDF_MAX_COUNT_OF_ENTRIES];
        /* sizes of data entries */
        uint32_t  dataSizes[CC_KDF_MAX_COUNT_OF_ENTRIES];
}CCKdfOtherInfo_t;


/************************ Structs  ******************************/

/************************ Public Variables **********************/

/************************ Public Functions **********************/

/****************************************************************/

/*********************************************************************************************************/
/*!
 @brief CC_KdfKeyDerivFunc performs key derivation according to one of the modes defined in standards:
	ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography,
	ANSI X9.63-2011: Public Key Cryptography for the Financial Services Industry - Key Agreement and Key Transport Using Elliptic Curve Cryptography,
	ISO/IEC 18033-2:2006: Information technology -- Security techniques -- Encryption algorithms -- Part 2: Asymmetric ciphers.

The present implementation of the function allows the following operation modes:
<ul><li> CC_KDF_ASN1_DerivMode - mode based on  ASN.1 DER encoding; </li>
<li> CC_KDF_ConcatDerivMode - mode based on concatenation;</li>
<li> CC_KDF_X963_DerivMode = CC_KDF_ConcatDerivMode;</li>
<li> CC_KDF_ISO18033_KDF1_DerivMode, CC_KDF_ISO18033_KDF2_DerivMode - specific modes according to
ISO/IEC 18033-2 standard.</li></ul>

The purpose of this function is to derive a keying data from the shared secret value and some
other optional shared information, included in OtherInfo (SharedInfo).

\note All buffers arguments are represented in Big-Endian format.

@return CC_OK on success.
@return A non-zero value on failure as defined cc_kdf_error.h.
*/
CCError_t  CC_KdfKeyDerivFunc(
                    uint8_t              *pZzSecret,            /*!< [in]  A pointer to shared secret value octet string. */
                    size_t                zzSecretSize,         /*!< [in]  The size of the shared secret value in bytes.
                                                                           The maximal size is defined as: ::CC_KDF_MAX_SIZE_OF_SHARED_SECRET_VALUE. */
                    CCKdfOtherInfo_t     *pOtherInfo,           /*!< [in]  A pointer to the structure, containing pointers to the data, shared by
									   two entities of agreement, depending on KDF mode:
                                                                           <ul><li> In KDF ASN1 mode OtherInfo includes ASN1 DER encoding of AlgorithmID (mandatory),
                                                                             and some optional data entries as described in section 7.7.1 of the ANSI X9.42-2003:
									     Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using
									     Discrete Logarithm Cryptography standard.</li>
                                                                           <li> In both ISO/IEC 18033-2:2006: Information technology -- Security techniques -- Encryption algorithms -- Part 2:
										Asymmetric ciphers standard: KDF1 and KDF2 modes this parameter is ignored and may be set to NULL. </li>
                                                                           <li> In other modes it is optional and may be set to NULL. </li></ul>*/
                    CCKdfHashOpMode_t     kdfHashMode,          /*!< [in]  The KDF identifier of hash function to be used. The hash function output
									   must be at least 160 bits. */
                    CCKdfDerivFuncMode_t  derivMode,            /*!< [in]  The enum value, specifies one of above described derivation modes. */
                    uint8_t              *pKeyingData,          /*!< [out] A pointer to the buffer for derived keying data. */
                    size_t                keyingDataSize        /*!< [in]  The size in bytes of the keying data to be derived.
                                                                           The maximal size is defined as :: CC_KDF_MAX_SIZE_OF_KEYING_DATA. */ );

/*********************************************************************************************************/
/*!
 CC_KdfAsn1KeyDerivFunc is a macro that performs key derivation according to ASN1 DER encoding method defined
 in section 7.2.1 of ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography standard.
 For a description of the parameters see ::CC_KdfKeyDerivFunc.
*/
#define CC_KdfAsn1KeyDerivFunc(ZZSecret_ptr,ZZSecretSize,OtherInfo_ptr,kdfHashMode,KeyingData_ptr,KeyLenInBytes)\
		CC_KdfKeyDerivFunc((ZZSecret_ptr),(ZZSecretSize),(OtherInfo_ptr),(kdfHashMode),CC_KDF_ASN1_DerivMode,(KeyingData_ptr),(KeyLenInBytes))


/*********************************************************************************************************/
/*!
 CC_KdfConcatKeyDerivFunc is a macro that performs key derivation according to concatenation mode defined
 in section 7.2.2 of ANSI X9.42-2003: Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography
 standard and also meets ANSI X9.63-2011: Public Key Cryptography for the Financial Services Industry - Key Agreement and Key Transport Using Elliptic Curve
 Cryptography standard. For a description of the parameters see ::CC_KdfKeyDerivFunc.
*/
#define CC_KdfConcatKeyDerivFunc(ZZSecret_ptr,ZZSecretSize,OtherInfo_ptr,kdfHashMode,KeyingData_ptr,KeyLenInBytes)\
		CC_KdfKeyDerivFunc((ZZSecret_ptr),(ZZSecretSize),(OtherInfo_ptr),(kdfHashMode),CC_KDF_ConcatDerivMode,(KeyingData_ptr),(KeyLenInBytes))


#ifdef __cplusplus
}
#endif

#endif

