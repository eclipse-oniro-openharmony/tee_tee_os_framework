/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_RSA_TYPES_H
#define SaSi_RSA_TYPES_H

#include "sasi_hash.h"
#include "sasi_pka_defs_hw.h"
#include "ssi_pal_types.h"
#include "ssi_pal_compiler.h"

#ifdef DX_SOFT_KEYGEN
#include "ccsw_sasi_rsa_shared_types.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif
/* !
@file
@brief This file contains all of the enums and definitions that are used for the SaSi RSA APIs.
*/

/* *********************** Defines **************************** */

/* Adjust the context size to the HAH context size in TEE */
#define SaSi_PKA_RSA_HASH_CTX_SIZE_IN_WORDS SaSi_HASH_USER_CTX_SIZE_IN_WORDS

/* maximal allowed key size in words */
#define SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES (SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS / SASI_BITS_IN_BYTE)

#define SaSi_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS      512
#define SaSi_RSA_VALID_KEY_SIZE_MULTIPLE_VALUE_IN_BITS 256

#define SaSi_RSA_MAX_KEY_GENERATION_SIZE_BITS SaSi_RSA_MAX_KEY_GENERATION_HW_SIZE_BITS

/* FIPS 184-4 definitions for allowed RSA and FFC DH key sizes */
#define SaSi_RSA_FIPS_KEY_SIZE_1024_BITS 1024
#define SaSi_RSA_FIPS_KEY_SIZE_2048_BITS 2048
#define SaSi_RSA_FIPS_KEY_SIZE_3072_BITS 3072
#define SaSi_RSA_FIPS_MODULUS_SIZE_BITS  SaSi_RSA_FIPS_KEY_SIZE_2048_BITS

#define SaSi_DH_FIPS_KEY_SIZE_1024_BITS 1024
#define SaSi_DH_FIPS_KEY_SIZE_2048_BITS 2048

/* If the salt length is not available in verify than the user can use this define and the algorithm will */
/* calculate the salt length alone */
/* Security Note: it is recommended not to use this flag and to support the Salt length on each verify */
#define SaSi_RSA_VERIFY_SALT_LENGTH_UNKNOWN 0xFFFF

/* The minimum exponents values */
#define SaSi_RSA_MIN_PUB_EXP_VALUE  3
#define SaSi_RSA_MIN_PRIV_EXP_VALUE 1

/* The maximum buffer size for the 'H' value */

#define SaSi_RSA_TMP_BUFF_SIZE                                                       \
    (SaSi_RSA_OAEP_ENCODE_MAX_MASKDB_SIZE + SaSi_RSA_OAEP_ENCODE_MAX_SEEDMASK_SIZE + \
     SaSi_PKA_RSA_HASH_CTX_SIZE_IN_WORDS * sizeof(uint32_t) + sizeof(SaSi_HASH_Result_t))

#define SaSi_PKCS1_HashFunc_t SaSi_HASH_OperationMode_t

#define SaSi_RSA_OAEP_MAX_HLEN SaSi_HASH_SHA512_DIGEST_SIZE_IN_BYTES

/* MGF1 declarations */
#define SaSi_RSA_MGF_2_POWER_32         65535 /* !< \internal 0xFFFF This is the 2^32 of the 2^32*hLen boundary check */
#define SaSi_RSA_SIZE_OF_T_STRING_BYTES (SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * sizeof(uint32_t))

/* **********************************************************
 *
 * RSA PKCS#1 v2.1 DEFINES
 *
 * ******************************************************** */
#define SaSi_RSA_OAEP_ENCODE_MAX_SEEDMASK_SIZE SaSi_RSA_OAEP_MAX_HLEN
#define SaSi_RSA_PSS_SALT_LENGTH               SaSi_RSA_OAEP_MAX_HLEN
#define SaSi_RSA_PSS_PAD1_LEN                  8

#define SaSi_RSA_OAEP_ENCODE_MAX_MASKDB_SIZE     \
    (SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * \
     sizeof(uint32_t)) /* !< \internal For OAEP Encode; the max size is emLen */
#define SaSi_RSA_OAEP_DECODE_MAX_DBMASK_SIZE     \
    (SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * \
     sizeof(uint32_t)) /* !< \internal For OAEP Decode; the max size is emLen */

/* *********************** Enums ****************************** */

/* ! Defines the enum for the HASH operation mode. */
typedef enum {
    SaSi_RSA_HASH_MD5_mode             = 0,  /* !< MD5 mode for PKCS1 v1.5 only. */
    SaSi_RSA_HASH_SHA1_mode            = 1,  /* !< HASH SHA1. */
    SaSi_RSA_HASH_SHA224_mode          = 2,  /* !< HASH SHA224. */
    SaSi_RSA_HASH_SHA256_mode          = 3,  /* !< HASH SHA256. */
    SaSi_RSA_HASH_SHA384_mode          = 4,  /* !< HASH SHA384. */
    SaSi_RSA_HASH_SHA512_mode          = 5,  /* !< HASH SHA512. */
    SaSi_RSA_After_MD5_mode            = 6,  /* !< For PKCS1 v1.5 only when the data is already hashed with MD5. */
    SaSi_RSA_After_SHA1_mode           = 7,  /* !< To be used when the data is already hashed with SHA1. */
    SaSi_RSA_After_SHA224_mode         = 8,  /* !< To be used when the data is already hashed with SHA224. */
    SaSi_RSA_After_SHA256_mode         = 9,  /* !< To be used when the data is already hashed with SHA256. */
    SaSi_RSA_After_SHA384_mode         = 10, /* !< To be used when the data is already hashed with SHA384. */
    SaSi_RSA_After_SHA512_mode         = 11, /* !< To be used when the data is already hashed with SHA512. */
    SaSi_RSA_After_HASH_NOT_KNOWN_mode = 12, /* !< \internal used only for PKCS#1 Ver 1.5 - possible to perform verify
                     operation without hash mode input, the hash mode is derived from the signature. */
    SaSi_RSA_HASH_NO_HASH_mode = 13,         /* !< Used for PKCS1 v1.5 Encrypt and Decrypt. */
    SaSi_RSA_HASH_NumOfModes,

    SaSi_RSA_HASH_OpModeLast = 0x7FFFFFFF,

} SaSi_RSA_HASH_OpMode_t;

/* ! Defines the enum of the RSA decryption mode. */
typedef enum {
    SaSi_RSA_NoCrt = 10,
    SaSi_RSA_Crt   = 11,

    SaSi_RSADecryptionNumOfOptions,

    SaSi_RSA_DecryptionModeLast = 0x7FFFFFFF,

} SaSi_RSA_DecryptionMode_t;

/* the Key source enum */
typedef enum {
    SaSi_RSA_ExternalKey = 1,
    SaSi_RSA_InternalKey = 2,

    SaSi_RSA_KeySourceLast = 0x7FFFFFFF,

} SaSi_RSA_KeySource_t;

/* ! MGF values. */
typedef enum {
    SaSi_PKCS1_MGF1   = 0,
    SaSi_PKCS1_NO_MGF = 1,
    SaSi_RSA_NumOfMGFFunctions,

    SaSi_PKCS1_MGFLast = 0x7FFFFFFF,

} SaSi_PKCS1_MGF_t;

/* ! Defines the enum of the various PKCS1 versions. */
typedef enum {
    SaSi_PKCS1_VER15 = 0,
    SaSi_PKCS1_VER21 = 1,

    SaSi_RSA_NumOf_PKCS1_versions,

    SaSi_PKCS1_versionLast = 0x7FFFFFFF,

} SaSi_PKCS1_version;

/* enum defining primality testing mode in Rabin-Miller
   and Lucas-Lehmer tests */
typedef enum {
    /* P and Q primes */
    SaSi_RSA_PRIME_TEST_MODE = 0,
    /* auxiliary primes */
    //        SaSi_RSA_AUX_PRIME_TEST_MODE = 1,
    /* FFC (DH, DSA) primes */
    SaSi_DH_PRIME_TEST_MODE = 1,

    SaSi_RSA_DH_PRIME_TEST_OFF_MODE

} SaSi_RSA_DH_PrimeTestMode_t;

/* *********************** Public and private key database Structs **************************** */

/* .................. The public key definitions ...................... */
/* --------------------------------------------------------------------- */

/* The public key data structure */
typedef struct {
    /* The RSA modulus buffer and its size in bits */
    uint32_t n[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t nSizeInBits;

    /* The RSA public exponent buffer and its size in bits */
    uint32_t e[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t eSizeInBits;

    /* #include the specific fields that are used by the low level */
    uint32_t sasiRSAIntBuff[SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS];

} SaSiRSAPubKey_t;

/* ! The public key's user structure prototype. */
typedef struct SaSi_RSAUserPubKey_t {
    uint32_t valid_tag;
    uint32_t PublicKeyDbBuff[sizeof(SaSiRSAPubKey_t) / sizeof(uint32_t) + 1];

} SaSi_RSAUserPubKey_t;

/* .................. The private key definitions ...................... */
/* --------------------------------------------------------------------- */

/* The private key on non-CRT mode data structure */
typedef struct {
    /* The RSA private exponent buffer and its size in bits */
    uint32_t d[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t dSizeInBits;

    /* The RSA public exponent buffer and its size in bits */
    uint32_t e[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t eSizeInBits;

} SaSiRSAPrivNonCRTKey_t;

/* The private key on CRT mode data structure */
#ifndef SaSi_NO_RSA_SMALL_CRT_BUFFERS_SUPPORT
/* use small CRT buffers */
typedef struct {
    /* The first factor buffer and size in bits */
    uint32_t P[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
    uint32_t PSizeInBits;

    /* The second factor buffer and its size in bits */
    uint32_t Q[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
    uint32_t QSizeInBits;

    /* The first CRT exponent buffer and its size in bits */
    uint32_t dP[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
    uint32_t dPSizeInBits;

    /* The second CRT exponent buffer and its size in bits */
    uint32_t dQ[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
    uint32_t dQSizeInBits;

    /* The first CRT coefficient buffer and its size in bits */
    uint32_t qInv[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
    uint32_t qInvSizeInBits;

} SaSiRSAPrivCRTKey_t;

/* size of SaSiRSAPrivCRTKey_t structure in words (used for temp buffers allocation) */
#define SaSi_RSA_SIZE_IN_WORDS_OF_SaSiRSAPrivCRTKey_t (SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * 7 / 2 + 5)

#else /* use large CRT buffers */
typedef struct {
    /* The first factor buffer and size in bits */
    uint32_t P[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t PSizeInBits;

    /* The second factor buffer and its size in bits */
    uint32_t Q[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t QSizeInBits;

    /* The first CRT exponent buffer and its size in bits */
    uint32_t dP[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t dPSizeInBits;

    /* The second CRT exponent buffer and its size in bits */
    uint32_t dQ[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t dQSizeInBits;

    /* The first CRT coefficient buffer and its size in bits */
    uint32_t qInv[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t qInvSizeInBits;

} SaSiRSAPrivCRTKey_t;

/* size of SaSiRSAPrivCRTKey_t structure in words (used for temp buffers allocation) */
#define SaSi_RSA_SIZE_IN_WORDS_OF_SaSiRSAPrivCRTKey_t (SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * 5 + 5)

#endif

/* The private key data structure */
typedef struct {
    /* The RSA modulus buffer and its size in bits */
    uint32_t n[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t nSizeInBits;

    /* The decryption operation mode */
    SaSi_RSA_DecryptionMode_t OperationMode;

    /* the source ( Import or Keygen ) */
    SaSi_RSA_KeySource_t KeySource;

    /* The union between the CRT and non-CRT data structures */
    union {
        SaSiRSAPrivNonCRTKey_t NonCrt;
        SaSiRSAPrivCRTKey_t Crt;
    } PriveKeyDb;

    /* #include specific fields that are used by the low level */
    uint32_t sasiRSAPrivKeyIntBuff[SaSi_PKA_PRIV_KEY_BUFF_SIZE_IN_WORDS];

} SaSiRSAPrivKey_t;

/* ! The private key's user structure prototype. */
typedef struct SaSi_RSAUserPrivKey_t {
    uint32_t valid_tag;
    uint32_t PrivateKeyDbBuff[sizeof(SaSiRSAPrivKey_t) / sizeof(uint32_t) + 1];

} SaSi_RSAUserPrivKey_t;

/* ! Temporary buffers for RSA usage. */
typedef struct SaSi_RSAPrimeData_t {
    /* The aligned input and output data buffers */
    uint32_t DataIn[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t DataOut[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];

    uint8_t InternalBuff[SaSi_RSA_TMP_BUFF_SIZE] SASI_PAL_COMPILER_ALIGN(4);

} SaSi_RSAPrimeData_t;

/* the KG data type */
typedef union SaSi_RSAKGData_t {
    struct {
        /* The aligned input and output data buffers */
        uint32_t p[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
        uint32_t q[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
        union {
            /* #include specific fields that are used by the low level */
            uint32_t sasiRSAKGDataIntBuff[SaSi_PKA_KGDATA_BUFF_SIZE_IN_WORDS];
#ifdef DX_SOFT_KEYGEN
            /* # added for compatibility with size of KGData SW type */
            uint32_t TempbuffExp[PKI_KEY_GEN_TEMP_BUFF_SIZE_WORDS];
#endif
        } kg_buf;
    } KGData;

    union {
        struct {
            SaSi_RSAPrimeData_t PrimData;
        } primExt;
#ifdef DX_SOFT_KEYGEN
        /* # added for compatibility with size of SW SaSiRSAPrivKey_t type */
        SW_Shared_SaSi_RSAPrimeData_t SW_Shared_PrimData;
#endif
    } prim;
} SaSi_RSAKGData_t;

/* ************
 *    RSA contexts
 * *********** */
/* *********************** SaSi RSA struct for Private Key **************************** */

typedef struct {
    /* A union for the Key Object - there is no need for the Private
    key and the Public key to be in the memory at the same time */
    SaSi_RSAUserPrivKey_t PrivUserKey;

    /* RSA PKCS#1 Version 1.5/2.1 */
    uint8_t PKCS1_Version;

    /* MGF 2 use for the PKCS1 Ver 2.1 Sign/Verify operation */
    uint8_t MGF_2use;

    /* The Salt random intended length for PKCS#1 PSS Ver 2.1 */
    uint16_t SaltLen;

    /* Struct for the Exp evaluation */
    SaSi_RSAPrimeData_t PrimeData;

    /* User Context of the Hash Context - Hash functions get as input a SaSi_HASHUserContext_t */
    // SaSi_HASHUserContext_t  HashUserContext;
    uint32_t SaSiPKAHashCtxBuff[SaSi_PKA_RSA_HASH_CTX_SIZE_IN_WORDS];
    SaSi_HASH_Result_t HASH_Result;
    uint16_t HASH_Result_Size;                   /* in words */
    SaSi_RSA_HASH_OpMode_t RsaHashOperationMode; /* RSA HASH enum. */
    SaSi_HASH_OperationMode_t HashOperationMode; /* SaSi HASH enum. */
    uint16_t HashBlockSize;                      /* in words */
    bool doHash;

    /* Used for sensitive data manipulation in the context space, which is safer and which saves stack space */
    uint32_t EBD[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t EBDSizeInBits;

    /* Used for sensitive data manipulation in the context space, which is safer and which saves stack space */
    uint8_t T_Buf[SaSi_RSA_SIZE_OF_T_STRING_BYTES];
    uint16_t T_BufSize;

    /* Buffer for the use of the Ber encoder in the case of PKCS#1 Ver 1.5 - in Private context only */
    uint32_t BER[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint16_t BERSize;

    /* This Buffer is added for encrypting the context. Note: This block must be
    at the end of the context. */
    uint8_t DummyBufAESBlockSize[16];

} RSAPrivContext_t;

/* Temporary buffers for the RSA usage */
typedef struct SaSi_RSAPrivUserContext_t {
    uint32_t valid_tag;
    uint32_t AES_iv; /* For the use of the AES CBC mode of Encryption and Decryption of the context in CCM */
    uint8_t
        context_buff[sizeof(RSAPrivContext_t) + sizeof(uint32_t)] SASI_PAL_COMPILER_ALIGN(4); /* must be aligned to 4 */

} SaSi_RSAPrivUserContext_t;

/* *********************** SaSi RSA struct for Public Key **************************** */

typedef struct {
    /* A union for the Key Object - there is no need for the Private
    key and the Public key to be in the memory in the same time */
    SaSi_RSAUserPubKey_t PubUserKey;

    /* public key size in bytes */
    uint32_t nSizeInBytes;

    /* RSA PKCS#1 Version 1.5/2.1 */
    uint8_t PKCS1_Version;

    /* MGF 2 use for the PKCS1 Ver 2.1 Sign/Verify operation */
    uint8_t MGF_2use;

    /* The Salt random intended length for PKCS#1 PSS Ver 2.1 */
    uint16_t SaltLen;

    /* Struct for the Exp evaluation */
    SaSi_RSAPrimeData_t PrimeData;

    /* User Context of the Hash Context - Hash functions get as input a SaSi_HASHUserContext_t */
    uint32_t SaSiPKAHashCtxBuff[SaSi_PKA_RSA_HASH_CTX_SIZE_IN_WORDS];

    SaSi_HASH_Result_t HASH_Result;
    uint16_t HASH_Result_Size;                   /* denotes the length, in words, of the hash function output */
    SaSi_RSA_HASH_OpMode_t RsaHashOperationMode; /* RSA HASH enum. */
    SaSi_HASH_OperationMode_t HashOperationMode; /* SaSi HASH enum. */
    uint16_t HashBlockSize;                      /* in words */
    bool doHash;

    /* Used for sensitive data manipulation in the context space, which is safer and which saves stack space */
    uint32_t EBD[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t EBDSizeInBits;

    /* Used for sensitive data manipulation in the context space, which is safer and which saves stack space */
    uint8_t T_Buf[SaSi_RSA_SIZE_OF_T_STRING_BYTES];
    uint16_t T_BufSize;

    /* This Buffer is added for encrypting the context ( encrypted part's size must be 0 modulo 16).
     * Note: This block must be at the end of the context.
     */
    uint8_t DummyBufAESBlockSize[16];

} RSAPubContext_t;

/* ! Temporary buffers for the RSA usage. */
typedef struct SaSi_RSAPubUserContext_t {
    uint32_t valid_tag;
    uint32_t AES_iv; /* For the use of the AES CBC mode of Encryption and Decryption of the context in CCM */
    uint32_t context_buff[sizeof(RSAPubContext_t) / sizeof(uint32_t) + 1];

} SaSi_RSAPubUserContext_t;

/* ! Required for internal FIPS verification for RSA key generation. */
typedef struct SaSi_RSAKGFipsContext_t {
    SaSi_RSAPrimeData_t primData;
    uint8_t decBuff[((SaSi_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS / SASI_BITS_IN_BYTE) -
                     2 * (SaSi_HASH_SHA1_DIGEST_SIZE_IN_BYTES)-2)];
    uint8_t encBuff[SaSi_RSA_FIPS_MODULUS_SIZE_BITS / SASI_BITS_IN_BYTE];
} SaSi_RSAKGFipsContext_t;

/* ! Required for internal FIPS verification for RSA KAT.      *
 *  The RSA KAT tests defined for scheme 2.1 with modulus key size of 2048.      */
typedef struct SaSi_RSAFipsKatContext_t {
    union {
        SaSi_RSAUserPubKey_t userPubKey;   // used for RsaEnc and RsaVerify
        SaSi_RSAUserPrivKey_t userPrivKey; // used for RsaDec and RsaSign
    } userKey;
    union {
        SaSi_RSAPrivUserContext_t userPrivContext; // used for RsaSign
        SaSi_RSAPubUserContext_t userPubContext;   // used for RsaVerify
        SaSi_RSAPrimeData_t primData;              // used for RsaEnc and RsaDec
    } userContext;
    union {
        struct { // used for RsaEnc and RsaDec
            uint8_t encBuff[SaSi_RSA_FIPS_MODULUS_SIZE_BITS / SASI_BITS_IN_BYTE];
            uint8_t decBuff[((SaSi_RSA_FIPS_MODULUS_SIZE_BITS / SASI_BITS_IN_BYTE) -
                             2 * (SaSi_HASH_SHA1_DIGEST_SIZE_IN_BYTES)-2)];
        } userOaepData;
        uint8_t signBuff[SaSi_RSA_FIPS_MODULUS_SIZE_BITS / SASI_BITS_IN_BYTE]; // used for RsaSign and RsaVerify
    } userData;
} SaSi_RSAFipsKatContext_t;

#ifdef __cplusplus
}
#endif

#endif
