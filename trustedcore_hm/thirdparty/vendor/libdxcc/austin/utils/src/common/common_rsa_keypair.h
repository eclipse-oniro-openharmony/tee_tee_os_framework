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

#ifndef _COMMON_RSA_KEYPAIR_H
#define _COMMON_RSA_KEYPAIR_H

#include <openssl/objects.h>
#include <openssl/pem.h>

#ifdef WIN32
#define SBUEXPORT_C __declspec(dllexport)
#else
#define SBUEXPORT_C
#endif

typedef enum NP_RESULT_TYPE { NP_BIN = 0, NP_HEX = 1 } NP_RESULT_TYPE_t;

/* Global defines */
#define RSA_MOD_SIZE_IN_BITS  2048UL
#define RSA_MOD_SIZE_IN_BYTES (RSA_MOD_SIZE_IN_BITS / 8)
#define RSA_PRIVATE_KEY_SIZE  2048
#define NP_SIZE_IN_BYTES      20
#define SNP                   RSA_MOD_SIZE_IN_BITS + 132

/*
 * @brief The DX_Common_GetKeyPair reads RSA private key from the file, along with retrieving the private key,
 *       it also retrieves the public key.
 *
 * The function
 * 1. Build RSA public key structure
 * @param[out] pRsaPrivKey - the private key
 * @param[in] PemEncryptedFileName_ptr - private key file
 * @param[in] Key_ptr - passphrase string
 *
 */
/* ****************************************************** */
int DX_Common_GetKeyPair(RSA **pRsaKeyPair, char *PemEncryptedFileName_ptr, char *Key_ptr);

/*
 * @brief The DX_Common_GetPubKey reads RSA public key from the file.
 *
 * The function
 * 1. Build RSA public key structure
 * @param[out] pRsaPrivKey - the rsa key
 * @param[in] PemEncryptedFileName_ptr - public key file name
 *
 */
/* ****************************************************** */
int DX_Common_GetPubKey(RSA **pRsaKeyPair, char *PemEncryptedFileName_ptr);

/*
 * @brief The function calculates Np when given N as hex data.
 *
 * @param[in] n - modulus as hex data
 * @param[out] NP_ptr - the Np
 *
 */
/* ****************************************************** */
SBUEXPORT_C int DX_Common_RSA_CalculateNp(const char *N_ptr, char *NP_ptr);

/*
 * @brief The function calculates Np when given N as BIGNUM.
 *
 * @param[in] n - modulus as BIGNUM ptr
 * @param[out] NP_ptr - the Np
 *
 */
/* ****************************************************** */
SBUEXPORT_C int DX_Common_RSA_CalculateNpInt(BIGNUM *n, unsigned char *NP_ptr, NP_RESULT_TYPE_t resultType);

#endif
