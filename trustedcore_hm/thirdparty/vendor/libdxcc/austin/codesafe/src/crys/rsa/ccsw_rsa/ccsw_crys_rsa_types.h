/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

#ifndef SW_CRYS_RSA_TYPES_H
#define SW_CRYS_RSA_TYPES_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */
#include "dx_pal_types.h"
#include "crys_hash.h"
#include "crys_rsa_types.h"
#include "ccsw_crys_rsa_shared_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Object % ccsw_crys_rsa_types.h    : %
 *  State           :  %state%
 *  Creation date   :  Wed Nov 17 16:42:30 2004
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief This file contains all of the enums and definitions
 *         that are used for the CRYS AES APIs, as well as the APIs themselves.
 *
 *  \version ccsw_crys_rsa_types.h#1:incl:13
 *  \author adams
 */

/* *********************** Defines **************************** */

#define PLS_FALSE 0UL
#define PLS_TRUE  1UL

/* ********************************************************************* */
/* the following defintions are only relevant for RSA code on SW */
/* ********************************************************************* */
/* Define the maximal allowed width of the exponentiation sliding window
in range 2...6. This define is actual for projects on soft platform.
To minimize code size use the minimum value. To optimize performance
choose the maximum value */
/* Define the size of the exponentiation temp buffer, used in LLF_PKI and NON DEPENDED on
width of the sliding window. The size defined in units equaled to maximal RSA modulus size */
#define PKI_CONV_CRT_CONST_TEMP_BUFF_SIZE_IN_MODULUS_UNITS 16

/* *************  Calculation of buffers sizes in words ***************************** */

/* Define the size of the temp buffer, used in LLF_PKI_CONVERT_TO_CRT and DEPENDED on
   width of the sliding window in words */
#if (PKI_CONV_CRT_CONST_TEMP_BUFF_SIZE_IN_MODULUS_UNITS > PKI_EXP_WINDOW_TEMP_BUFFER_SIZE_IN_MODULUS_UNITS)
#define PKI_CONV_CRT_TEMP_BUFFER_SIZE_IN_WORDS \
    (PKI_CONV_CRT_CONST_TEMP_BUFF_SIZE_IN_MODULUS_UNITS * SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS + 2)
#else
#define PKI_CONV_CRT_TEMP_BUFFER_SIZE_IN_WORDS \
    (PKI_EXP_WINDOW_TEMP_BUFFER_SIZE_IN_MODULUS_UNITS * SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS + 2)
#endif

#define SW_CRYS_RSA_VALID_KEY_SIZE_MULTIPLE_VALUE_IN_BITS 256

/* maximal allowed key size in words */
#define SW_CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES (SW_CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS / 8)

/* *********************** Public and private key database Structs **************************** */

/* .................. The public key definitions ...................... */
/* --------------------------------------------------------------------- */

/* The public key data structure */
typedef struct {
    /* The RSA modulus buffer and its size in bits */
    uint32_t n[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t nSizeInBits;

    /* The RSA public exponent buffer and its size in bits */
    uint32_t e[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t eSizeInBits;
    /* # added for compatibility with size of CC CRYSRSAPubKey_t type */
    uint32_t crysRSAIntBuff[CRYS_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS];

} SW_CRYSRSAPubKey_t;

/* The user structure prototype used as an input to the CRYS_RSA_PRIM_Encrypt */
typedef struct SW_CRYS_RSAUserPubKey_t {
    uint32_t valid_tag;
    uint32_t PublicKeyDbBuff[sizeof(SW_CRYSRSAPubKey_t) / sizeof(uint32_t) + 1];
} SW_CRYS_RSAUserPubKey_t;

/* .................. The private key definitions ...................... */
/* --------------------------------------------------------------------- */

/* The private key on non-CRT mode data structure */
typedef struct {
    /* The RSA private exponent buffer and its size in bits */
    uint32_t d[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t dSizeInBits;

    /* The RSA public exponent buffer and its size in bits */
    uint32_t e[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t eSizeInBits;

} SW_CRYSRSAPrivNonCRTKey_t;

/* The private key on CRT mode data structure */
#ifndef CRYS_NO_RSA_SMALL_CRT_BUFFERS_SUPPORT
/* use small CRT buffers */
typedef struct {
    /* The first factor buffer and size in bits */
    uint32_t P[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
    uint32_t PSizeInBits;

    /* The second factor buffer and its size in bits */
    uint32_t Q[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
    uint32_t QSizeInBits;

    /* The first CRT exponent buffer and its size in bits */
    uint32_t dP[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
    uint32_t dPSizeInBits;

    /* The second CRT exponent buffer and its size in bits */
    uint32_t dQ[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
    uint32_t dQSizeInBits;

    /* The first CRT coefficient buffer and its size in bits */
    uint32_t qInv[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
    uint32_t qInvSizeInBits;

} SW_CRYSRSAPrivCRTKey_t;

#else /* use large CRT buffers */
typedef struct {
    /* The first factor buffer and size in bits */
    uint32_t P[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t PSizeInBits;

    /* The second factor buffer and its size in bits */
    uint32_t Q[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t QSizeInBits;

    /* The first CRT exponent buffer and its size in bits */
    uint32_t dP[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t dPSizeInBits;

    /* The second CRT exponent buffer and its size in bits */
    uint32_t dQ[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t dQSizeInBits;

    /* The first CRT coefficient buffer and its size in bits */
    uint32_t qInv[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t qInvSizeInBits;

} SW_CRYSRSAPrivCRTKey_t;

#endif

/* The private key data structure: */
typedef struct {
    /* The RSA modulus buffer and its size in bits */
    uint32_t n[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t nSizeInBits;

    /* The decryption operation mode */
    CRYS_RSA_DecryptionMode_t OperationMode;

    /* the source flag: 1 - External;  2 - Internal generation */
    CRYS_RSA_KeySource_t KeySource;

    /* The union between the CRT and non-CRT data structures */
    union {
        SW_CRYSRSAPrivNonCRTKey_t NonCrt;
        SW_CRYSRSAPrivCRTKey_t Crt;
    } PriveKeyDb;

    /* # added for compatibility with size of CC CRYSRSAPrivKey_t type */
    uint32_t crysRSAPrivKeyIntBuff[CRYS_PKA_PRIV_KEY_BUFF_SIZE_IN_WORDS];

} SW_CRYSRSAPrivKey_t;

/* Define the size of SW_CRYSRSAPrivKey_t structure for using in temp buffers allocation */

/* The users Key structure prototype, used as an input to the
CRYS_RSA_PRIM_Decrypt or CRYS_RSA_PRIM_DecryptCRT */
typedef struct SW_CRYS_RSAUserPrivKey_t {
    uint32_t valid_tag;
    uint32_t PrivateKeyDbBuff[sizeof(SW_CRYSRSAPrivKey_t) / sizeof(uint32_t) + 1];
} SW_CRYS_RSAUserPrivKey_t;

/* the RSA data type */
typedef struct SW_CRYS_RSAPrimeData_t {
    /* The aligned input and output data buffers */
    uint32_t DataIn[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t DataOut[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];

    /* #include specific fields that are used by the low level */
    struct {
        union {
            struct { /* Temporary buffers used for the exponent calculation */
                uint32_t Tempbuff1[PKI_EXP_TEMP_BUFFER_SIZE_IN_WORDS];
                uint32_t Tempbuff2[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * 2];
                /* Temporary buffer for self-test support */
                uint32_t TempBuffer[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
            } NonCrt;

            struct { /* Temporary buffers used for the exponent calculation */
                uint32_t Tempbuff1[PKI_EXP_TEMP_BUFFER_SIZE_IN_WORDS];
                uint32_t Tempbuff2[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * 2];
            } Crt;
        } Data;
    } LLF;

} SW_CRYS_RSAPrimeData_t;

/* the KG data type */
typedef union SW_CRYS_RSAKGData_t {
    struct {
        /* The aligned input and output data buffers */
        uint32_t p[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
        uint32_t q[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2];
        /* Temporary buffers used for the exponent calculation */
        uint32_t TempbuffExp[PKI_KEY_GEN_TEMP_BUFF_SIZE_WORDS];

    } KGData;

    SW_CRYS_RSAPrimeData_t PrimData;

} SW_CRYS_RSAKGData_t;

/* .......................... Temp buff definition  ........................ */
/* ------------------------------------------------------------------------- */

/* the RSA Convert Key to CRT data type */
typedef struct SW_CRYS_RSAConvertKeyToCrtBuffers_t {
    /* #include specific fields that are used by the low level */
    struct {
        uint32_t TempBuffers[7 * SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS + PKI_EXP_TEMP_BUFFER_SIZE_IN_WORDS];

    } LLF;
} SW_CRYS_RSAConvertKeyToCrtBuffers_t;

#ifdef __cplusplus
}
#endif
#endif
