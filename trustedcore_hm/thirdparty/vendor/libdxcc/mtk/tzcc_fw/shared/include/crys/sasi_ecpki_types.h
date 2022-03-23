/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_ECPKI_TYPES_H
#define SaSi_ECPKI_TYPES_H

/* !
@file
@brief Contains all of the enums and definitions that are used for the SaSi ECPKI APIs.
*/

#include "ssi_pal_types_plat.h"
#include "sasi_hash.h"
#include "sasi_pka_defs_hw.h"
#include "ssi_pal_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines **************************** */

#define SaSi_PKA_DOMAIN_LLF_BUFF_SIZE_IN_WORDS (10 + 3 * SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS)

/* The type defines integer array of lengths of maximum lengths of EC modulus */
typedef uint32_t SaSi_ECPKI_ARRAY_t[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];

/* *************************************************************************************
 *                  Enumerators
 * ************************************************************************************ */

/* ------------------------------------------------------------------ */
/* ! Enumerator for the EC Domain idetifier
   References: [13] - SEC 2: Recommended elliptic curve domain parameters.
                      Version 1.0. Certicom 2000.
               [8]  - WAP-261-WTLS-20010406-a, Version 06-April-2001.     */

typedef enum {
    /* For prime field */
    SaSi_ECPKI_DomainID_secp160k1, /* !< EC secp160r1 */
    SaSi_ECPKI_DomainID_secp160r1, /* !< EC secp160k1 */
    SaSi_ECPKI_DomainID_secp160r2, /* !< EC secp160r2 */
    SaSi_ECPKI_DomainID_secp192k1, /* !< EC secp192k1 */
    SaSi_ECPKI_DomainID_secp192r1, /* !< EC secp192r1 */
    SaSi_ECPKI_DomainID_secp224k1, /* !< EC secp224k1 */
    SaSi_ECPKI_DomainID_secp224r1, /* !< EC secp224r1 */
    SaSi_ECPKI_DomainID_secp256k1, /* !< EC secp256k1 */
    SaSi_ECPKI_DomainID_secp256r1, /* !< EC secp256r1 */
    SaSi_ECPKI_DomainID_secp384r1, /* !< EC secp384r1 */
    SaSi_ECPKI_DomainID_secp521r1, /* !< EC secp521r1 */

    SaSi_ECPKI_DomainID_Builded, /* !< User given, not identified. */
    SaSi_ECPKI_DomainID_OffMode,

    SaSi_ECPKI_DomainIDLast = 0x7FFFFFFF,

} SaSi_ECPKI_DomainID_t;

/* ------------------------------------------------------------------ */
/* ! Defines the enum for the HASH operation mode.
 *  The enumerator defines 6 HASH modes according to IEEE 1363.
 *
 */
typedef enum {
    SaSi_ECPKI_HASH_SHA1_mode   = 0, /* !< HASH SHA1 mode. */
    SaSi_ECPKI_HASH_SHA224_mode = 1, /* !< HASH SHA224 mode. */
    SaSi_ECPKI_HASH_SHA256_mode = 2, /* !< HASH SHA256 mode. */
    SaSi_ECPKI_HASH_SHA384_mode = 3, /* !< HASH SHA384 mode. */
    SaSi_ECPKI_HASH_SHA512_mode = 4, /* !< HASH SHA512 mode. */

    SaSi_ECPKI_AFTER_HASH_SHA1_mode   = 5, /* !< After HASH SHA1 mode (message was already hashed). */
    SaSi_ECPKI_AFTER_HASH_SHA224_mode = 6, /* !< After HASH SHA224 mode (message was already hashed). */
    SaSi_ECPKI_AFTER_HASH_SHA256_mode = 7, /* !< After HASH SHA256 mode (message was already hashed). */
    SaSi_ECPKI_AFTER_HASH_SHA384_mode = 8, /* !< After HASH SHA384 mode (message was already hashed). */
    SaSi_ECPKI_AFTER_HASH_SHA512_mode = 9, /* !< After HASH SHA512 mode (message was already hashed). */

    SaSi_ECPKI_HASH_NumOfModes,
    SaSi_ECPKI_HASH_OpModeLast = 0x7FFFFFFF,

} SaSi_ECPKI_HASH_OpMode_t;

/* --------------------------------------------------- */
/* ! Enumerator for the EC point compression idetifier. */
typedef enum {
    SaSi_EC_PointCompressed   = 2,
    SaSi_EC_PointUncompressed = 4,
    SaSi_EC_PointContWrong    = 5, /* wrong Point Control value */
    SaSi_EC_PointHybrid       = 6,

    SaSi_EC_PointCompresOffMode = 8,

    SaSi_ECPKI_PointCompressionLast = 0x7FFFFFFF,

} SaSi_ECPKI_PointCompression_t;

/* ---------------------------------------------------- */
/*  Enumerator for compatibility of the DHC
   with cofactor multiplication to DH ordinary */
typedef enum {
    SaSi_ECPKI_SVDP_DHC_CompatibleDH    = 0, /* Requested compatiblity of SVDP_DHC with cofactor to SVDP_DH */
    SaSi_ECPKI_SVDP_DHC_NonCompatibleDH = 1, /* Compatiblity of SVDP_DHC with cofactor to SVDP_DH is not requested */

    SaSi_ECPKI_SVDP_DHC_OffMode,

    SaSi_ECPKI_SVDP_DHC_OpModeLast = 0x7FFFFFFF,

} SaSi_ECPKI_SVDP_DHC_OpMode_t;

/* ---------------------------------------------------- */
/* Enumerator for indication what checking of EC public key must be performed */
typedef enum {
    CheckPointersAndSizesOnly = 0, /* Only preliminary input parameters checking */
    ECpublKeyPartlyCheck      = 1, /* In addition check that EC PubKey is point on curve */
    ECpublKeyFullCheck        = 2, /* In addition check that EC_GeneratorOrder*PubKey = O */

    PublKeyChecingOffMode,
    EC_PublKeyCheckModeLast = 0x7FFFFFFF,
} EC_PublKeyCheckMode_t;

/* ---------------------------------------------------- */
/* This SCAP is related to included SCA_PROTECTION measures in   *
 *  SW part of algoritthms but not in HW itself              */
typedef enum { SCAP_Inactive, SCAP_Active, SCAP_OFF_MODE, SCAP_LAST = 0x7FFFFFFF } SaSi_ECPKI_ScaProtection_t;

/* *************************************************************************************
 *                 EC  Domain structure definition
 * ************************************************************************************ */

/* ! The structure containing the EC domain parameters in little-endian form
    EC equation: Y^2 = X^3 + A*X + B over prime fild GFp. */
typedef struct {
    /* ! EC modulus: P. */
    uint32_t ecP[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    /* ! EC equation parameters a, b. */
    uint32_t ecA[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t ecB[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    /* ! Order of generator. */
    uint32_t ecR[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1];
    /* ! EC cofactor EC_Cofactor_K
        Generator (EC base point) coordinates in projective form. */
    uint32_t ecGx[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t ecGy[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t ecH;
    /* ! include the specific fields that are used by the low level. */
    uint32_t llfBuff[SaSi_PKA_DOMAIN_LLF_BUFF_SIZE_IN_WORDS];
    /* ! Size of fields in bits. */
    uint32_t modSizeInBits;
    uint32_t ordSizeInBits;
    /* ! Size of each inserted Barret tag in words; 0 - if not inserted. */
    uint32_t barrTagSizeInWords;
    /* ! EC Domain identifier. */
    SaSi_ECPKI_DomainID_t DomainID;
    int8_t name[20];

} SaSi_ECPKI_Domain_t;

/* *************************************************************************************
 *                 EC  point structures definitions
 * ************************************************************************************ */

/* ! The structure containing the EC point in affine coordinates
   and little endian form. */
typedef struct {
    /* ! Point coordinates. */
    uint32_t x[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t y[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];

} SaSi_ECPKI_PointAffine_t;

/* *************************************************************************************
 *                  ECPKI public and private key  Structures
 * ************************************************************************************ */

/* --------------------------------------------------------------------- */
/* .................. The public key structures definitions ............ */
/* --------------------------------------------------------------------- */

/* ! The structure containing the Public Key in affine coordinates. */

/*   Size = 2*SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1 +
   ( sizeof(LLF_ECPKI_publ_key_db_def.h) = 0 ).          */

struct SaSi_ECPKI_PublKey_t {
    /* ! Public Key coordinates. */
    uint32_t x[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t y[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    SaSi_ECPKI_Domain_t domain;
    uint32_t pointType;
};

/* ! The user structure containing EC public key data base form. */

/*   Size = 2*SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 2 +
   ( sizeof(LLF_ECPKI_publ_key_db_def.h) = 0 ).          */

typedef struct SaSi_ECPKI_UserPublKey_t {
    uint32_t valid_tag;
    uint32_t PublKeyDbBuff[(sizeof(struct SaSi_ECPKI_PublKey_t) + 3) / 4];

} SaSi_ECPKI_UserPublKey_t;

/* --------------------------------------------------------------------- */
/* .................. The private key structures definitions ........... */
/* --------------------------------------------------------------------- */

/* ! The EC private key structure in little endian form. */

/*   Size = SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 2 +
   ( sizeof(LLF_ECPKI_priv_key_db_def.h) = 0 ).        */
typedef struct {
    /* ! Private Key data. */
    uint32_t PrivKey[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1];
    SaSi_ECPKI_Domain_t domain;
    SaSi_ECPKI_ScaProtection_t scaProtection;

} SaSi_ECPKI_PrivKey_t;

/* ! The user structure containing EC private key data base in little endian form. */

/*   Size = SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 3 +
   ( sizeof(LLF_ECPKI_priv_key_db_def.h) = 0 )          */
typedef struct SaSi_ECPKI_UserPrivKey_t {
    uint32_t valid_tag;
    uint32_t PrivKeyDbBuff[(sizeof(SaSi_ECPKI_PrivKey_t) + 3) / 4];

} SaSi_ECPKI_UserPrivKey_t;

/* !  The ECDH temporary data type  */
typedef struct SaSi_ECDH_TempData_t {
    uint32_t sasiEcdhIntBuff[SaSi_PKA_ECDH_BUFF_MAX_LENGTH_IN_WORDS];
} SaSi_ECDH_TempData_t;

typedef struct SaSi_ECPKI_BUILD_TempData_t {
    uint32_t sasiBuildTmpIntBuff[SaSi_PKA_ECPKI_BUILD_TMP_BUFF_MAX_LENGTH_IN_WORDS];
} SaSi_ECPKI_BUILD_TempData_t;

/* *************************************************************************
 *                  SaSi ECDSA context structures
 * *********************************************************************** */

/* --------------------------------------------------------------------- */
/*                SaSi ECDSA Signing context structure                   */
/* --------------------------------------------------------------------- */

typedef struct {
    /* A user's buffer for the Private Key Object - */
    SaSi_ECPKI_UserPrivKey_t ECDSA_SignerPrivKey;

    /* HASH specific data and buffers */
    uint32_t hashUserCtxBuff[sizeof(SaSi_HASHUserContext_t)];
    SaSi_HASH_Result_t hashResult;
    uint32_t hashResultSizeWords;
    SaSi_ECPKI_HASH_OpMode_t hashMode;

    uint32_t sasiEcdsaSignIntBuff[SaSi_PKA_ECDSA_SIGN_BUFF_MAX_LENGTH_IN_WORDS];
} ECDSA_SignContext_t;

/* --------------------------------------------------------------------- */
/*                SaSi ECDSA  Signing User context database              */
/* --------------------------------------------------------------------- */

typedef struct SaSi_ECDSA_SignUserContext_t {
    uint32_t context_buff[(sizeof(ECDSA_SignContext_t) + 3) / 4];
    uint32_t valid_tag;
} SaSi_ECDSA_SignUserContext_t;

/* ************************************************************************* */

/* --------------------------------------------------------------------- */
/*                SaSi ECDSA Verifying context structure                 */
/* --------------------------------------------------------------------- */
typedef struct {
    /* A user's buffer for the Private Key Object - */
    SaSi_ECPKI_UserPublKey_t ECDSA_SignerPublKey;

    /* HASH specific data and buffers */
    uint32_t hashUserCtxBuff[sizeof(SaSi_HASHUserContext_t)];
    SaSi_HASH_Result_t hashResult;
    uint32_t hashResultSizeWords;
    SaSi_ECPKI_HASH_OpMode_t hashMode;

    uint32_t sasiEcdsaVerIntBuff[SaSi_PKA_ECDSA_VERIFY_BUFF_MAX_LENGTH_IN_WORDS];

} ECDSA_VerifyContext_t;

/* --------------------------------------------------------------------- */
/*                SaSi ECDSA Verifying User context database             */
/* --------------------------------------------------------------------- */

typedef struct SaSi_ECDSA_VerifyUserContext_t {
    uint32_t context_buff[(sizeof(ECDSA_VerifyContext_t) + 3) / 4];
    uint32_t valid_tag;
} SaSi_ECDSA_VerifyUserContext_t;

/* --------------------------------------------------------------------- */
/* .................. key generation temp buffer   ........... */
/* --------------------------------------------------------------------- */

/* ! The ECPKI KG temporary data type */
typedef struct SaSi_ECPKI_KG_TempData_t {
    uint32_t sasiKGIntBuff[SaSi_PKA_KG_BUFF_MAX_LENGTH_IN_WORDS];
} SaSi_ECPKI_KG_TempData_t;

typedef struct SaSi_ECIES_TempData_t {
    SaSi_ECPKI_UserPrivKey_t PrivKey;
    SaSi_ECPKI_UserPublKey_t PublKey;
    uint32_t zz[3 * SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1];
    union {
        SaSi_ECPKI_BUILD_TempData_t buildTempbuff;
        SaSi_ECPKI_KG_TempData_t KgTempBuff;
        SaSi_ECDH_TempData_t DhTempBuff;
    } tmp;

} SaSi_ECIES_TempData_t;

/* --------------------------------------------------------------------- */
/* .................. defines for FIPS      ........... */
/* --------------------------------------------------------------------- */

#define SaSi_ECPKI_FIPS_ORDER_LENGTH (256 / SASI_BITS_IN_BYTE) // the order of secp256r1 in bytes

/* ! Required for internal FIPS verification for ECPKI key generation. */
typedef struct SaSi_ECPKI_KG_FipsContext_t {
    union {
        SaSi_ECDSA_SignUserContext_t signCtx;
        SaSi_ECDSA_VerifyUserContext_t verifyCtx;
    } operationCtx;
    uint32_t signBuff[2 * SaSi_ECPKI_ORDER_MAX_LENGTH_IN_WORDS];
} SaSi_ECPKI_KG_FipsContext_t;

/* ! Required for internal FIPS verification for ECDSA KAT.      *
 *  The ECDSA KAT tests defined for domain 256r1.     */
typedef struct SaSi_ECDSAFipsKatContext_t {
    union {
        struct {
            SaSi_ECPKI_UserPrivKey_t PrivKey;
            SaSi_ECDSA_SignUserContext_t signCtx;
        } userSignData;
        struct {
            SaSi_ECPKI_UserPublKey_t PublKey;
            union {
                SaSi_ECDSA_VerifyUserContext_t verifyCtx;
                SaSi_ECPKI_BUILD_TempData_t tempData;
            } buildOrVerify;
        } userVerifyData;
    } keyContextData;

    uint8_t signBuff[2 * SaSi_ECPKI_FIPS_ORDER_LENGTH];
} SaSi_ECDSAFipsKatContext_t;

/* ! Required for internal FIPS verification for ECDH KAT. */
typedef struct SaSi_ECDHFipsKatContext_t {
    SaSi_ECPKI_UserPublKey_t pubKey;
    SaSi_ECPKI_UserPrivKey_t privKey;
    union {
        SaSi_ECPKI_BUILD_TempData_t ecpkiTempData;
        SaSi_ECDH_TempData_t ecdhTempBuff;
    } tmpData;
    uint8_t secretBuff[SaSi_ECPKI_FIPS_ORDER_LENGTH];
} SaSi_ECDHFipsKatContext_t;

#ifdef __cplusplus
}
#endif

#endif
