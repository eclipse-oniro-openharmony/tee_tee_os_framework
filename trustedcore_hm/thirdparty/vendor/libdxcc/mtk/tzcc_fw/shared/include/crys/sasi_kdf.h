/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_KDF_H
#define SaSi_KDF_H

#include "sasi_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/* !
@file
@brief This module defines the API that supports Key derivation function in modes
as defined in PKCS#3, ANSI X9.42-2001, and ANSI X9.63-1999.
*/

#include "sasi_hash.h"

/* *********************** Defines **************************** */

/* Shared secret value max size in bytes: must be defined according to      *
 *  DH max. modulus size definition!                         */
#define SaSi_KDF_MAX_SIZE_OF_SHARED_SECRET_VALUE 1024 /* !< Size is in bytes */

/* Count and max. sizeof OtherInfo entries (pointers to data buffers) */
#define SaSi_KDF_COUNT_OF_OTHER_INFO_ENTRIES  5
#define SaSi_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY 64 /* !< Size is in bytes */
/* Max size of keying data in bytes to generate */
#define SaSi_KDF_MAX_SIZE_OF_KEYING_DATA 2048

/* *********************** Enums ****************************** */

typedef enum {
    SaSi_KDF_HASH_SHA1_mode   = 0,
    SaSi_KDF_HASH_SHA224_mode = 1,
    SaSi_KDF_HASH_SHA256_mode = 2,
    SaSi_KDF_HASH_SHA384_mode = 3,
    SaSi_KDF_HASH_SHA512_mode = 4,

    SaSi_KDF_HASH_NumOfModes,

    SaSi_KDF_HASH_OpModeLast = 0x7FFFFFFF,

} SaSi_KDF_HASH_OpMode_t;

typedef enum {
    SaSi_KDF_ASN1_DerivMode          = 0,
    SaSi_KDF_ConcatDerivMode         = 1,
    SaSi_KDF_X963_DerivMode          = SaSi_KDF_ConcatDerivMode,
    SaSi_KDF_ISO18033_KDF1_DerivMode = 3,
    SaSi_KDF_ISO18033_KDF2_DerivMode = 4,

    SaSi_KDF_DerivFunc_NumOfModes = 5,

    SaSi_KDF_DerivFuncModeLast = 0x7FFFFFFF,

} SaSi_KDF_DerivFuncMode_t;

/* *********************** Typedefs  ************************** */

/* Structure, containing the optional data for KDF,
   if any data is not needed, then the pointer value and
   the size must be set to NULL */
typedef struct {
    /* a unique object identifier (OID), indicating algorithm(s)
    for which the keying data is used */
    uint8_t AlgorithmID[SaSi_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY];
    uint32_t SizeOfAlgorithmID;
    /* Public information contributed by the initiator */
    uint8_t PartyUInfo[SaSi_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY];
    uint32_t SizeOfPartyUInfo;
    /* Public information contributed by the responder */
    uint8_t PartyVInfo[SaSi_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY];
    uint32_t SizeOfPartyVInfo;
    /* Mutually-known private information, e.g. shared information
    communicated throgh a separate channel */
    uint8_t SuppPrivInfo[SaSi_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY];
    uint32_t SizeOfSuppPrivInfo;
    /* Mutually-known public information, */
    uint8_t SuppPubInfo[SaSi_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY];
    uint32_t SizeOfSuppPubInfo;

} SaSi_KDF_OtherInfo_t;

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

/* ************************************************************* */

/* ****************************************************************************************************** */
/* !
 @brief SaSi_KDF_KeyDerivFunc_MTK performs key derivation according to one of the modes defined in standards:
        ANS X9.42-2001, ANS X9.63, ISO/IEC 18033-2.

The present implementation of the function allows the following operation modes:
<ul><li> SaSi_KDF_ASN1_DerivMode - mode based on  ASN.1 DER encoding; </li>
<li> SaSi_KDF_ConcatDerivMode - mode based on concatenation;</li>
<li> SaSi_KDF_X963_DerivMode = SaSi_KDF_ConcatDerivMode;</li>
<li> SaSi_KDF_ISO18033_KDF1_DerivMode - specific mode according to ECIES-KEM algorithm (ISO/IEC 18033-2).</li></ul>

The purpose of this function is to derive a keying data from the shared secret value and some
other optional shared information (SharedInfo).

\note
<ul id="noteb"><li> The length in Bytes of the hash result buffer is denoted by "hashlen".</li>
<li> All buffers arguments are represented in Big-Endian format.</li>

@return SaSi_OK on success.
@return A non-zero value on failure as defined sasi_kdf_error.h.
*/
CIMPORT_C SaSiError_t SaSi_KDF_KeyDerivFunc_MTK(
    uint8_t *ZZSecret_ptr, /* !< [in]  A pointer to shared secret value octet string. */
    uint32_t ZZSecretSize, /* !< [in]  The size of the shared secret value in bytes.
                                      The maximal size is defined as: SaSi_KDF_MAX_SIZE_OF_SHARED_SECRET_VALUE. */
    SaSi_KDF_OtherInfo_t
        *OtherInfo_ptr, /* !< [in]  The pointer to structure, containing the data, shared by two entities of
agreement and the data sizes. This argument may be optional in several modes
(if it is not needed - set NULL).
                                   On two ISO/IEC 18033-2 modes - set NULL.
                                   On KDF ASN1 mode the OtherInfo and its AlgorithmID entry are mandatory. */
    SaSi_KDF_HASH_OpMode_t KDFhashMode, /* !< [in]  The KDF identifier of hash function to be used. The hash function
               output must be at least 160 bits. */
    SaSi_KDF_DerivFuncMode_t derivation_mode, /* !< [in]  Specifies one of above described derivation modes. */
    uint8_t *KeyingData_ptr,                  /* !< [out] A pointer to the buffer for derived keying data. */
    uint32_t KeyingDataSizeBytes              /* !< [in]  The size in bytes of the keying data to be derived.
                                                         The maximal size is defined as: SaSi_KDF_MAX_SIZE_OF_KEYING_DATA. */
);

/* alias for backward compatibility */
#define _DX_KDF_KeyDerivFunc SaSi_KDF_KeyDerivFunc_MTK

/* ****************************************************************************************************** */
/* !
 SaSi_KDF_ASN1_KeyDerivFunc is a macro that performs key derivation according to ASN1 DER encoding method defined
 in standard  ANS X9.42-2001, 7.2.1. For a description of the parameters see ::SaSi_KDF_KeyDerivFunc_MTK.
*/
#define SaSi_KDF_ASN1_KeyDerivFunc(ZZSecret_ptr, ZZSecretSize, OtherInfo_ptr, KDFhashMode, KeyingData_ptr,             \
                                   KeyLenInBytes)                                                                      \
    SaSi_KDF_KeyDerivFunc_MTK((ZZSecret_ptr), (ZZSecretSize), (OtherInfo_ptr), (KDFhashMode), SaSi_KDF_ASN1_DerivMode, \
                              (KeyingData_ptr), (KeyLenInBytes))

/* ****************************************************************************************************** */
/* !
 SaSi_KDF_ConcatKeyDerivFunc is a macro that performs key derivation according to concatenation mode defined
 in standard  ANS X9.42-2001, 7.2.2. For a description of the parameters see
 ::SaSi_KDF_KeyDerivFunc_MTK.
*/
#define SaSi_KDF_ConcatKeyDerivFunc(ZZSecret_ptr, ZZSecretSize, OtherInfo_ptr, KDFhashMode, KeyingData_ptr, \
                                    KeyLenInBytes)                                                          \
    SaSi_KDF_KeyDerivFunc_MTK((ZZSecret_ptr), (ZZSecretSize), (OtherInfo_ptr), (KDFhashMode),               \
                              SaSi_KDF_ConcatDerivMode, (KeyingData_ptr), (KeyLenInBytes))

#ifdef __cplusplus
}
#endif

#endif
