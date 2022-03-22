/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_RSA_LOCAL_H
#define SaSi_RSA_LOCAL_H

#include "sasi_error.h"
#include "sasi_rsa_types.h"
#include "sasi_rnd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines **************************** */

/* the RSA public key user validity TAG */
#define SaSi_RSA_PUB_KEY_VALIDATION_TAG 0x13579BDF

/* the RSA private key user validity TAG */
#define SaSi_RSA_PRIV_KEY_VALIDATION_TAG 0x2468ACE0

/* the RSA sign Context user validity TAG */
#define SaSi_RSA_SIGN_CONTEXT_VALIDATION_TAG   0x98765432
#define SaSi_RSA_VERIFY_CONTEXT_VALIDATION_TAG 0x45678901

/* For testing the SaSi_RSA_SEP_InvModWord function the
SaSi_RSA_SEP_InvModWord_MeasuprePerform definition must be undefined.
For measuring performance of SaSi_RSA_SEP_InvModWord function
with SEP set the SaSi_RSA_SEP_InvModWord_MeasuprePerform definition */

/* #define SaSi_RSA_SEP_InvModWord_MeasuprePerform */

typedef struct {
    uint16_t hashResultSize;
    SaSi_HASH_OperationMode_t hashMode;
} rsa_hash_t;

extern const rsa_hash_t rsa_hash_info[SaSi_RSA_HASH_NumOfModes];
extern const uint8_t rsa_supported_hash_modes[SaSi_RSA_HASH_NumOfModes];

/* **************

  ASN1 types - for BER Parser - used for PKCS#1 Ver 1.5

* ************ */

#define ASN1_BOOLEAN           1
#define ASN1_INTEGER           2
#define ASN1_BIT_STRING        3
#define ASN1_OCTET_STRING      4
#define ASN1_NULL              5
#define ASN1_OBJECT_IDENTIFIER 6
#define ASN1_SEQUENCE          16 /* 0x10 */
#define ASN1_SET               17 /* 0x11 */
#define ASN1_PRINTABLE_STRING  19 /* 0x13 */
#define ASN1_TELETEX_STRING    20 /* 0x14 */
#define ASN1_IA5STRING         22 /* 0x16 */
#define ASN1_UTC_TIME          23 /* 0x17 */

/* *********************
 structures definition
 * ******************* */
#define TEST_MSB_BIT 0x80

/* Hash algorithm ID (DER code) structure type */
#define HASH_DER_CODE_MAX_SIZE_BYTES 24
typedef struct HashDerCode_t {
    uint32_t algIdSizeBytes;
    SaSi_HASH_OperationMode_t hashMode;
    uint8_t algId[HASH_DER_CODE_MAX_SIZE_BYTES];
} HashDerCode_t;

/* For security goal the padding string PS in EME-PKCS1-v1_5 encodding method
   must be at least eight octets long */
#define PS_MIN_LEN 8

/* *********************** macros ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */
typedef struct SaSi_OAEP_Data_t {
    uint8_t MaskDB[SaSi_RSA_OAEP_ENCODE_MAX_MASKDB_SIZE];
    uint8_t SeedMask[SaSi_RSA_OAEP_ENCODE_MAX_SEEDMASK_SIZE];
    SaSi_HASHUserContext_t HashUsercontext;
    SaSi_HASH_Result_t HashResultBuff;
} SASI_PAL_COMPILER_TYPE_MAY_ALIAS SaSi_OAEP_Data_t;

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

/* ****************************************************************************** */
/*
 * @brief The function implements PKCS#1 v1.5 (9.2) EMSA Encoding
 *        algorithm used in Sign/Verify operations.
 *
 * @author reuvenl (9/14/2014)
 *
 * @param K - The size of encoded message in octets.
 * @param hashMode - Sasi hash mode ID (enum).
 * @param pM - The Pointer to the Message M. In case of Sign it is a hash (H).
 * @param MSize - Denotes the Message size: for Sig/Ver = hashSize,
 *                  for Enc/Dec <= K-hashAlgIdSize-PSS_MIN_LEN-3.
 * @param pOut - The pointer to a buffer which is at least K octets long.
 *
 * @return SaSiError_t
 */
SaSiError_t SaSi_RsaEmsaPkcs1v15Encode(uint32_t K, SaSi_HASH_OperationMode_t hashMode, uint8_t *pM, /* mess.digest */
                                       uint32_t MSize, uint8_t *pOut);

/* ******************************************************************************************************* */

SaSiError_t SaSi_RSA_OAEPMGF1(uint16_t hLen,                  /* size in Bytes */
                              uint8_t *Z_ptr, uint16_t ZSize, /* size in Bytes */
                              uint32_t L, uint8_t *Mask_ptr, SaSi_PKCS1_HashFunc_t hashFunc,
                              uint8_t *T_Buf, /* T_Buf is a buffer used for data manipulation for the function to use
                                                 instead of allocating the space on stack */
                              uint8_t *T_TMP_Buf); /* T_TMP_Buf is a buffer used for data manipulation for the function
                                                      to use instead of allocating the space on stack */

/* ******************************************************************************************************* */
/*
   @brief
   SaSi_RSA_PSS_OAEPEncode implements the the Encoding operation according to the PKCS#1 as defined
   in PKCS#1 v2.1 7.1.1 (2) and PKCS#1 v2.0
*/
SaSiError_t SaSi_RSA_PSS_OAEPEncode(SaSi_RND_Context_t *rndContext_ptr, /* random functions context */
                                    SaSi_PKCS1_HashFunc_t hashFunc,     /* PKCS1 hash mode enum */
                                    SaSi_PKCS1_MGF_t MGF,               /* MGF function type enum */
                                    uint8_t *M_ptr,                     /* a pointer to the message to be encoded */
                                    uint16_t MSize,                     /* the message size in bytes */
                                    uint8_t *P_ptr, /* a pointer to the label; can be empty string */
                                    uint32_t PSize, /* the size of the label in bytes */
                                    uint16_t emLen, /* The value is set before the call */
                                    SaSi_RSAPrimeData_t *PrimeData_ptr, /* temp buffer */
                                    uint8_t *EMInput_ptr,               /* encoded message output */
                                    SaSi_PKCS1_version PKCS1_ver);

/* ******************************************************************************************************* */
/*
   @brief
   SaSi_RSA_PSS_OAEPDecode implements the the De operation according to the PKCS#1 as defined
   in PKCS#1 v2.1 7.1.1 (2) and PKCS#1 v2.0
*/
SaSiError_t SaSi_RSA_PSS_OAEPDecode(SaSi_PKCS1_HashFunc_t hashFunc, SaSi_PKCS1_MGF_t MGF, uint8_t *EM_ptr,
                                    uint16_t EMSize, uint8_t *P_ptr, uint32_t PSize,
                                    SaSi_RSAPrimeData_t *PrimeData_ptr, /* Only for stack memory save */
                                    uint8_t *M_ptr, uint16_t *MSize_ptr);

/* ******************************************************************************************************* */
/*
 * @brief
 * This function does implements the functionality of PKCS1 Ver 2.1 Sign
 *    operation after the Hash operation
 *
 * Before using that function a Hash must be completed on the Data.
 * The function is called after the call to Hash_Finish
 *
 * @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
 * @param[in] Context_ptr - Pointer to a valid context as
 *                           given from SaSi_RSA_SIGN
 *
 * @param[out] Output_ptr - A buffer allocated for the output which is at least the size of the MOdulus N
 *
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
SaSiError_t SaSi_RSA_PSS_Sign21(SaSi_RND_Context_t *rndContext_ptr, RSAPrivContext_t *Context_ptr, uint8_t *Output_ptr);

/* ******************************************************************************************************* */
/*
     Function Name: SaSi_RSA_PSS_Verify21
     Date:   06-12-2004
     Author:    Ohad Shperling


    \brief SaSi_RSA_PSS_Verify21 implements EMSA-PSS-Verify algorithm
   as defined in PKCS#1 v2.1 Sec 9.1.2

   @param[in] Context_ptr - Pointer to a valid context as
                            given from the VerifyFinish function.

   The field HASH_Result inside the Context_ptr is initialized with the Hashed digested message.
   The field HASH_Result_Size inside the Context_ptr is initialized with the Hash digested message size

   @return SaSiError_t - SaSi_OK,
                         SaSi_BAD_PARAM, SaSi_OUT_OF_RANGE
*/
SaSiError_t SaSi_RSA_PSS_Verify21(RSAPubContext_t *Context_ptr);

/* ******************************************************************************************************* */
/*
 * @brief The SaSi_RSA_GenerateVectorInRangeX931 function generates a random vector in range:
 *            MinVect < RandVect < MaxVect, where:
 *            MinVect = sqwRoot(2) * 2^(RndSizeInBits-1),  MaxVect = 2^RndSizeInBits.
 *
 *            Note: 1. MSBit of RandVect must be set to 1.
 *                  2. Words order of output vector is set from LS word to MS
 *                 word.
 *
 *        This function is used in PKI RSA for random generation according to ANS X9.31 standard.
 *        If PKI_RSA is not supported, the function does nothing.
 *
 *        Functions algorithm::
 *
 *        1.  Calls the SaSi_RND_GenerateVector_MTK() function for generating random vector
 *            RndVect of size RndSizeInWords, rounded up to bytes. Set index i
 *            to high word i = SizeInWords-1.
 *        2.  Check and adust candidate for msWord inside the random vector
 *            starting from msWord himselv, if msWord > high word of MinVect,
 *            goto step 3, else try next word i--; if no words to try, then goto
 *            step 1.
 *        3.  Set the found msWord to high position in array and generate new
 *            random words instead all checked and rejected words.
 *
 * @rndContext_ptr[in/out]  - Pointer to the RND context buffer.
 * @rndSizeWords[in]  - The size of random vectore that is required.
 * @rnd_ptr[out]      - The output buffer of size not less, than rndSizeWords.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                       value MODULE_* as defined in ...
 */
SaSiError_t SaSi_RSA_GenerateVectorInRangeX931(SaSi_RND_Context_t *rndContext_ptr, uint32_t rndSizeWords,
                                               uint32_t *rnd_ptr);

/* ************************************************************************** */
/*
 * The function generates vector of non zero octets.
 *
 * @author reuvenl (9/14/2014)
 *
 * @param [in/out] rndContext_ptr  - Pointer to the RND context buffer.
 * @param pVect - The pointer to output buffer.
 * @param size  - The size of vector in bytes.
 *
 * @return SaSiError_t
 */
SaSiError_t RsaGenRndNonZeroVect(SaSi_RND_Context_t *rndContext_ptr, uint8_t *pVect, uint32_t size);

/* ******************************************************************************************************* */
/* !
@brief RSA_SignInit initializes the Signing multi-call algorithm as defined in PKCS#1 2.1 standard, including v1.5.

NOTE:
-# In PSS_Sign v2.1 MD5 is not supported, since it is not recommended by the PKCS#1 v2.1.
-# According to the said standard, implementation of the function for version v1.5 is based on DER encoding of the
algorithm info.

This function does not do cryptographic processing. Rather, it
prepares a context that is used by the Update and Finish functions.

@return SaSi_OK on success.
@return SaSi_RSA error on failure:\n
                    SaSi_BAD_PARAM
*/
CIMPORT_C SaSiError_t SaSi_RsaSignInit(
    SaSi_RSAPrivUserContext_t *UserContext_ptr, /* !< [in/out] A pointer to a Context. The value returned here must be
                                                   passed to the Update and Finish functions. */
    SaSi_RSAUserPrivKey_t
        *UserPrivKey_ptr,               /* !< [in]  A pointer to the private key data structure.
                                                   \note The representation (pair or quintuple) and hence the algorithm (CRT or not)
                                           is determined by the Private Key data structure.               Using of the SaSi_Build_PrivKey or
                                           SaSi_Build_PrivKeyCRT determines which algorithm is used. */
    SaSi_RSA_HASH_OpMode_t rsaHashMode, /* !< [in]  The enumerator value, defining the hash function to be used:
                                           SHA-1,SHA224/256/384/512, MD5 (MD5 allowed only in v1.5).
                                                    The hash functions recommended by PKCS#1 v2.1 are: 256/384/512. Also
                                           allowed "After" HASH modes for said functions. */
    SaSi_PKCS1_MGF_t MGF, /* !< [in]  The mask generation function. PKCS#1 v2.1 defines MGF1, so the only value allowed
                             here is SaSi_PKCS1_MGF1. */
    uint16_t SaltLen, /* !< [in]  The Length of the Salt buffer (relevant for PKCS#1 Ver 2.1 only, typically lengths is 0
                         or hLen). FIPS 186-4 requires, that SaltLen <= hlen. If SaltLen > KeySize - hLen - 2, the
                         function returns an error. */
    SaSi_PKCS1_version PKCS1_ver /* !< [in]  Ver 1.5 or 2.1, according to the functionality required. */
);

/* ******************************************************************************************************* */
/* !
@brief SaSi_RsaSignUpdate processes the data to be signed in a given context.

@note SaSi_RsaSignUpdate can be called multiple times with data

@return SaSi_OK on success.
@return SaSi_RSA error on failure:\n
SaSi_BAD_PARAM
*/
CIMPORT_C SaSiError_t SaSi_RsaSignUpdate(
    SaSi_RSAPrivUserContext_t
        *UserContext_ptr, /* !< [in] A pointer to a valid context, as returned by SaSi_RsaSignInit. */
    uint8_t *DataIn_ptr,  /* !< [in] A pointer to the data to sign. */
    uint32_t DataInSize   /* !< [in] The size, in bytes, of the data to sign. */
);

/* ******************************************************************************************************* */
/* !
@brief SaSi_RsaSignFinish calculates the signature on the data passed to one or more calls to SaSi_RsaSignUpdate,
and releases the context.

@return SaSi_OK on success.
@return SaSi_RSA error on failure:\n
            SaSi_RSA_INVALID_USER_CONTEXT_POINTER_ERROR,\n
            SaSi_RSA_USER_CONTEXT_VALIDATION_TAG_ERROR,\n
            SaSi_RSA_INVALID_OUTPUT_POINTER_ERROR,\n
            SaSi_RSA_INVALID_SIGNATURE_BUFFER_SIZE,\n
            SaSi_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR,\n
            SaSi_RSA_PKCS1_VER_ARG_ERROR
*/

CIMPORT_C
    SaSiError_t
    SaSi_RsaSignFinish(
        SaSi_RND_Context_t *rndContext_ptr,         /* !< [in/out] Pointer to the RND context buffer. */
        SaSi_RSAPrivUserContext_t *UserContext_ptr, /* !< [in/out] A pointer to the Context initialized by the SignInit
                                                       function and used by the SignUpdate function. */
        uint8_t *Output_ptr,                        /* !< [out] A pointer to the signature.
                                                                The buffer must be at least PrivKey_ptr->N.len bytes long (that is, the size of
                                                       the modulus, in bytes). */
        uint16_t *OutputSize_ptr                    /* !< [in/out] A pointer to the Signature Size value -
                                                                    the input value is the signature buffer size allocated, the output
                                                       value is the signature size used.                    The buffer must be at least PrivKey_ptr->N.len
                                                       bytes long (that is, the size of the modulus, in bytes). */
    );

/* ******************************************************************************************************* */
/* !
@brief  RSA_VerifyInit initializes the Verify multi-call algorithm as defined in PKCS#1 v1.5 and 2.1

note:
-# In PSS_Sign v2.1 MD5 is not supported, since it is not recommended by the PKCS#1 v2.1.
-# According to the said standard, implementation of the function for version v1.5 is based on DER encoding of the
algorithm info.

@return SaSi_OK on success.
@return SaSi_RSA error on failure:\n
                SaSi_INVALID_SIGNATURE, \n
                SaSi_BAD_PARAM, \n
                SaSi_OUT_OF_RANGE
*/
CIMPORT_C SaSiError_t SaSi_RsaVerifyInit(
    SaSi_RSAPubUserContext_t *UserContext_ptr, /* !< [in]  A pointer to the public Context structure of the User. */
    SaSi_RSAUserPubKey_t *UserPubKey_ptr,      /* !< [in]  A pointer to the public key data structure. */
    SaSi_RSA_HASH_OpMode_t rsaHashMode, /* !< [in]  The hash function to be used. Currently available HASH functions:
                                           SHA1/SHA-256/384/512/MD5 (MD5 - allowed only for PKCS#1 v1.5). Also allowed
                                           "After HASH" modes for said functions. */
    SaSi_PKCS1_MGF_t MGF, /* !< [in]  The mask generation function, relevant only for PKCS#1 v2.1. The currently allowed
                             value for v2.1 is SaSi_PKCS1_MGF1. */
    uint16_t SaltLen, /* !< [in]  The Length of the Salt buffer. Relevant for PKCS#1 Ver 2.1 only. Typical lengths are 0
                         and hashLen (20 for SHA1). The maximum length allowed is NSize - hLen - 2. If the salt length
                         is not available in this process, the user can use the define:
                         SaSi_RSA_VERIFY_SALT_LENGTH_UNKNOWN. Security Note: This mode is not FIPS approved and it is
                         recommended not to use this flag and provide the Salt length on each verification. */
    SaSi_PKCS1_version PKCS1_ver /* !< [in]  Ver 1.5 or 2.1, according to the functionality required. */
);

/* ******************************************************************************************************* */
/* !
@brief RSA_VerifyUpdate processes the data to be verified in a given context, according to PKCS1 v1.5 and 2.1
@brief RSA_VerifyUpdate can be called multiple times with data

@return SaSi_OK on success.
@return SaSi_RSA error on failure:\n
                SaSi_INVALID_SIGNATURE, \n
                SaSi_BAD_PARAM, \n
                SaSi_OUT_OF_RANGE
*/

CIMPORT_C SaSiError_t SaSi_RsaVerifyUpdate(
    SaSi_RSAPubUserContext_t *UserContext_ptr, /* !< [in]  A pointer to the public Context structure of the User. */
    uint8_t *DataIn_ptr,                       /* !< [in]  A pointer to the data whose signature is to be verified. */
    uint32_t DataInSize /* !< [in]  The size, in bytes, of the data whose signature is to be verified. */
);

/* ******************************************************************************************************* */
/* !
@brief RSA_VerifyFinish implements the Finish Phase of the Verify algorithm as defined in PKCS#1 v2.1 or PKCS#1 v1.5

@return SaSi_OK on success.
@return SaSi_RSA error on failure:\n
                SaSi_INVALID_SIGNATURE, \n
                SaSi_BAD_PARAM, \n
                SaSi_OUT_OF_RANGE
*/

CIMPORT_C SaSiError_t SaSi_RsaVerifyFinish(
    SaSi_RSAPubUserContext_t *UserContext_ptr, /* !< [in]  A pointer to the public Context structure of the User. */
    uint8_t *Sig_ptr                           /* !< [in]  A pointer to the signature to be verified.
                                                           The length of the signature is PubKey_ptr->N.len bytes (that is, the size of the
                                                  modulus, in bytes). */
);

#ifdef __cplusplus
}
#endif

#endif
