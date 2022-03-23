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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include "common_rsa_keypair.h"
#include "common_util_log.h"

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
int DX_Common_GetKeyPair(RSA **pRsaKeyPair, char *PemEncryptedFileName_ptr, char *Key_ptr)
{
    FILE *fp = NULL;

    if (PemEncryptedFileName_ptr == NULL) {
        UTIL_LOG_ERR("Illegal RSA key pair or pwd file name\n");
        return -1;
    }

    fp = fopen(PemEncryptedFileName_ptr, "r");
    if (fp == NULL) {
        UTIL_LOG_ERR("Cannot open RSA file %s\n", PemEncryptedFileName_ptr);
        return -1;
    }

    if ((PEM_read_RSAPrivateKey(fp, pRsaKeyPair, NULL, Key_ptr)) == NULL) {
        UTIL_LOG_ERR("Cannot read RSA private key\n");
        ERR_print_errors_fp(stderr);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

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
int DX_Common_GetPubKey(RSA **pRsaKeyPair, char *PemEncryptedFileName_ptr)
{
    FILE *fp = NULL;

    if (PemEncryptedFileName_ptr == NULL) {
        UTIL_LOG_ERR("Illegal RSA file name\n");
        return -1;
    }

    fp = fopen(PemEncryptedFileName_ptr, "r");
    if (fp == NULL) {
        UTIL_LOG_ERR("Cannot open RSA file %s\n", PemEncryptedFileName_ptr);
        return -1;
    }

    if ((PEM_read_RSA_PUBKEY(fp, pRsaKeyPair, NULL, NULL)) == NULL) {
        UTIL_LOG_ERR("Cannot read RSA public key\n");
        ERR_print_errors_fp(stderr);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

/*
 * @brief The function SBU_RSA_Calculate calculates the Np it returns it as array of ascii's
 *
 * @param[in] N_ptr - public key N, represented as array of ascii's (0xbc is translated
 *                    to 0x62 0x63)
 * @param[out] NP_ptr - The NP result. NP size is NP_SIZE_IN_BYTES*2 + 1
 *
 */
/* ****************************************************** */
SBUEXPORT_C int DX_Common_RSA_CalculateNp(const char *N_ptr, char *NP_ptr)
{
    char *N_Temp = NULL;
    int status   = -1;
    BIGNUM *bn_n = BN_new();

    if ((N_ptr == NULL) || (NP_ptr == NULL)) {
        UTIL_LOG_ERR("Illegal input\n");
        goto calcNp_end;
    }

    /* Copy the N to temporary N, allocate temporary N in N size + 2 */
    N_Temp = (char *)malloc((RSA_MOD_SIZE_IN_BYTES * 2 + 2) * sizeof(char));
    if (N_Temp == NULL) {
        UTIL_LOG_ERR("failed to malloc.\n");
        goto calcNp_end;
    }

    if (bn_n == NULL) {
        UTIL_LOG_ERR("failed to BN_new.\n");
        goto calcNp_end;
    }

    /* set the temporary N to 0 */
    memset(N_Temp, 0, (RSA_MOD_SIZE_IN_BYTES * 2 + 2));

    /* Copy the N to temp N */
    memcpy(N_Temp, N_ptr, RSA_MOD_SIZE_IN_BYTES * 2);

    if (!BN_hex2bn(&bn_n, N_Temp)) {
        UTIL_LOG_ERR("BN_hex2bn failed.\n");
        goto calcNp_end;
    }

    if (DX_Common_RSA_CalculateNpInt(bn_n, NP_ptr, NP_HEX) != 0) {
        UTIL_LOG_ERR("DX_Common_RSA_CalculateNpInt failed.\n");
        goto calcNp_end;
    }

    status = 0;

calcNp_end:
    if (N_Temp != NULL) {
        free(N_Temp);
    }
    if (bn_n != NULL) {
        BN_free(bn_n);
    }
    return (status);
}

/*
 * @brief The function calculates Np when given N as BIGNUM.
 *
 * @param[in] n - modulus as BIGNUM ptr
 * @param[out] NP_ptr - the Np
 *
 */
/* ****************************************************** */
SBUEXPORT_C int DX_Common_RSA_CalculateNpInt(BIGNUM *n, unsigned char *NP_ptr, NP_RESULT_TYPE_t resultType)
{
    int len;
    unsigned char *NP_res = NULL, *NP_resTemp = NULL;
    int status     = -1;
    BN_CTX *bn_ctx = BN_CTX_new();

    BIGNUM *bn_r   = BN_new();
    BIGNUM *bn_a   = BN_new();
    BIGNUM *bn_p   = BN_new();
    BIGNUM *bn_n   = BN_new();
    BIGNUM *bn_quo = BN_new();
    BIGNUM *bn_rem = BN_new();

    if ((n == NULL) || (NP_ptr == NULL)) {
        UTIL_LOG_ERR("Illegal input parameters.\n");
        goto calcNpInt_end;
    }

    NP_res = (char *)malloc(NP_SIZE_IN_BYTES);
    if (NP_res == NULL) {
        UTIL_LOG_ERR("failed to malloc.\n");
        goto calcNpInt_end;
    }
    if ((bn_r == NULL) || (bn_a == NULL) || (bn_p == NULL) || (bn_n == NULL) || (bn_quo == NULL) || (bn_rem == NULL) ||
        (bn_ctx == NULL)) {
        UTIL_LOG_ERR("failed to BN_new or BN_CTX_new.\n");
        goto calcNpInt_end;
    }

    /* computes a = 2^SNP */
    BN_set_word(bn_a, 2);
    BN_set_word(bn_p, SNP);
    if (!BN_exp(bn_r, bn_a, bn_p, bn_ctx)) {
        UTIL_LOG_ERR("failed to BN_exp.\n");
        goto calcNpInt_end;
    }
    if (!BN_div(bn_quo, bn_rem, bn_r, n, bn_ctx)) {
        UTIL_LOG_ERR("failed to BN_div.\n");
        goto calcNpInt_end;
    }

    if (resultType == NP_BIN) {
        len = BN_bn2bin(bn_quo, NP_res);

        /* Set the output with 0 and than copy the result */
        memset(NP_ptr, 0, NP_SIZE_IN_BYTES);
        memcpy((unsigned char *)(NP_ptr + (NP_SIZE_IN_BYTES - len)), (char *)NP_res, len);
    } else { /* resultType == HEX */
        NP_resTemp = BN_bn2hex(bn_quo);
        if (NP_resTemp == NULL) {
            UTIL_LOG_ERR("BN_bn2hex failed\n");
            goto calcNpInt_end;
        }
        if (NP_resTemp[0] == '-') {
            UTIL_LOG_ERR("BN_bn2hex returned negative values\n");
            goto calcNpInt_end;
        }
        len = (int)strlen(NP_resTemp);
        memcpy(NP_res, NP_resTemp, len);

        /* Set the output with 0 and than copy the result */
        memset(NP_ptr, 0, (NP_SIZE_IN_BYTES * 2 + 2));
        memcpy((char *)(NP_ptr + (NP_SIZE_IN_BYTES * 2 + 2 - len)), (char *)NP_res, len);
    }

    status = 0;

calcNpInt_end:
    if (NP_res != NULL) {
        free(NP_res);
    }
    if (bn_r != NULL) {
        BN_free(bn_r);
    }
    if (bn_a != NULL) {
        BN_free(bn_a);
    }
    if (bn_p != NULL) {
        BN_free(bn_p);
    }
    if (bn_n != NULL) {
        BN_free(bn_n);
    }
    if (bn_quo != NULL) {
        BN_free(bn_quo);
    }
    if (bn_rem != NULL) {
        BN_free(bn_rem);
    }
    if (bn_ctx != NULL) {
        BN_CTX_free(bn_ctx);
    }
    if (NP_resTemp != NULL) {
        OPENSSL_free(NP_resTemp);
    }
    return (status);
}
