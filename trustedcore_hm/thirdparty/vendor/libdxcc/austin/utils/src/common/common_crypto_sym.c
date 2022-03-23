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
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/cmac.h>
#include "common_crypto_sym.h"
#include "common_util_log.h"

/*
 * @brief Encrypts (AES CTR) a given data and returns it.
 *
 * @param[in] pDataIn - the data to encrypt
 * @param[in] dataInSize - the data size
 * @param[in] pKey - the AES key
 * @param[in] keySize - AES key size (must be one of the allowed AES key sizes)
 * @param[in] pIV - IV (AES IV size is constant)
 * @param[out] pEncBuff - the encrypted buffer
 */
/* ****************************************************** */
int DX_Common_AES_CTR_Encrypt(char *pDataIn, int dataInSize, char *pKey, int keySize, char *pIV, char *pEncBuff)
{
    AES_KEY key;
    unsigned char m_iv[AES_BLOCK_SIZE];
    unsigned char m_ecount_buf[AES_BLOCK_SIZE];
    unsigned int m_num = 0;
    int ret            = (-1);

    if ((pDataIn == NULL) || (pKey == NULL) || (pIV == NULL) || (pEncBuff == NULL)) {
        UTIL_LOG_ERR("ilegal input\n");
        return -1;
    }
    memcpy(m_iv, pIV, sizeof(m_iv));
    memset(m_ecount_buf, 0, sizeof(m_ecount_buf));

    /* Initialize an AES_KEY from raw key bytes */
    ret = AES_set_encrypt_key(pKey, keySize * 8, &key);
    if (ret != 0) {
        UTIL_LOG_ERR("\n AES_set_encrypt_key failed");
        return -1;
    }
    /* Encrypting data and sending it to the destination */
    AES_ctr128_encrypt(pDataIn, pEncBuff, dataInSize, &key, m_iv, m_ecount_buf, &m_num);

    return 0;
}

/*
 * @brief The DX_Common_AES_CBC_Decrypt decrypts (AES CBC) a given data
 *               and returns the decrypted buffer.
 *
 * @param[in] pwdFileName - file name for passsword to generate key and IV from
 * @param[in] pEncBuff - the encrypted buffer- input buffer
 * @param[in] encBuffSize - the encrypted buffer size
 * @param[out] pDecBuff -the decrypted buffer.
 *
 * NOTE: pDecBuff - alocated size must be multiple of 16 bytes. same as encBuffSize
 */
/* ****************************************************** */
int DX_Common_AES_CBC_Decrypt(char *pwdFileName, char *pEncBuff, int encBuffSize, char *pDecBuff)
{
    unsigned char *pwdBuff           = NULL;
    int pwdBuffLen                   = 0;
    const EVP_CIPHER *cipher         = NULL;
    const EVP_MD *dgst               = NULL;
    char keyBuff[EVP_MAX_KEY_LENGTH] = { 0x0 };
    char ivBuff[EVP_MAX_KEY_LENGTH]  = { 0x0 };
    AES_KEY aesKey;
    int status = 1;

    if ((pEncBuff == NULL) || (pDecBuff == NULL)) {
        UTIL_LOG_ERR("ilegal input\n");
        return 1;
    }

    /* parse the passphrase for a given file */
    if ((pwdFileName != NULL)) {
        if (DX_Common_GetPassphrase(pwdFileName, &pwdBuff)) {
            UTIL_LOG_ERR("Failed to retrieve pwd\n");
            status = 1;
            goto END;
        }
        pwdBuffLen = strlen(pwdBuff);
    }

    /* get the IV and key from pwd */
    cipher = EVP_get_cipherbyname("aes-128-cbc");
    if (cipher == NULL) {
        UTIL_LOG_ERR("EVP_get_cipherbyname failed\n");
        status = 1;
        goto END;
    }

    dgst = EVP_get_digestbyname("md5");
    if (dgst == NULL) {
        UTIL_LOG_ERR("EVP_get_digestbyname failed\n");
        status = 1;
        goto END;
    }

    UTIL_LOG_BYTE_BUFF("pwdBuff", pwdBuff, strlen(pwdBuff));
    status = EVP_BytesToKey(cipher, dgst, NULL, (unsigned char *)pwdBuff, pwdBuffLen, 1, keyBuff, ivBuff);
    if (status == 0) {
        UTIL_LOG_ERR("EVP_BytesToKey failed\n");
        status = 1;
        goto END;
    }

    UTIL_LOG_BYTE_BUFF("keyBuff", keyBuff, sizeof(keyBuff));
    UTIL_LOG_BYTE_BUFF("ivBuff", ivBuff, sizeof(ivBuff));

    /* key and IV are ready, start decryption */
    memset(pDecBuff, 0, encBuffSize); /* encBuffSize is multiple of 16 bytes */

    /* Initialize an AES_KEY from raw key bytes */
    status = AES_set_decrypt_key(keyBuff, 128, &aesKey);
    if (status != 0) {
        UTIL_LOG_ERR("\n AES_set_encrypt_key failed");
        status = 1;
        goto END;
    }
    /* Encrypting data and sending it to the destination */
    AES_cbc_encrypt(pEncBuff, pDecBuff, encBuffSize, &aesKey, ivBuff, AES_DECRYPT);

    status = 0;
END:
    if (pwdBuff != NULL) {
        free(pwdBuff);
    }
    return status;
}

/*
 * @brief Encrypts AES CBC-MAC a given data
 *               and returns the encrypted buffer.
 *
 * @param[in] pKey - key buffer
 * @param[in] pIv - iv buffer
 * @param[in] pBuff - the plaintext buffer
 * @param[in] encBuffSize - the plaintext buffer size
 * @param[in] pEncMacBuff -the encrypted - ciphertext buffer.
 * @param[out] pEncMacBuff -the encrypted - ciphertext buffer.
 *
 */
/* ****************************************************** */
int DX_Common_AES_CBC_MAC_Encrypt(char *pKey, char *pIv, char *pBuff, unsigned int buffSize, unsigned int macSize,
                                  char *pEncMacBuff)
{
    AES_KEY aesKey;
    int status              = 1;
    unsigned char *pOutBuff = NULL;

    if ((pKey == NULL) || (pIv == NULL) || (pBuff == NULL) || (pEncMacBuff == NULL) || (buffSize == 0)) {
        UTIL_LOG_ERR("ilegal input\n");
        return 1;
    }

    memset(pEncMacBuff, 0, macSize); /* buffSize is multiple of 16 bytes */

    pOutBuff = malloc(buffSize);
    if (pOutBuff == NULL) {
        UTIL_LOG_ERR("malloc failed\n");
        return 1;
    }

    /* Initialize an AES_KEY from raw key bytes */
    status = AES_set_encrypt_key(pKey, 128, &aesKey);
    if (status != 0) {
        UTIL_LOG_ERR("\n AES_set_encrypt_key failed");
        status = 1;
        goto END;
    }
    /* Encrypting data and sending it to the destination */
    AES_cbc_encrypt(pBuff, pOutBuff, buffSize, &aesKey, pIv, AES_ENCRYPT);
    memcpy(pEncMacBuff, pOutBuff, macSize);

    status = 0;
END:
    if (pOutBuff != NULL) {
        free(pOutBuff);
    }
    return status;
}

/*
 * @brief Encrypts (AES CCM) a given data and returns it.
 *
 * @param[in] pDataIn - the data to encrypt
 * @param[in] dataInSize - the data size
 * @param[in] pKey - the AES key
 * @param[in] keySize - AES key size (must be one of the allowed AES key sizes)
 * @param[out] pOutput - Output buffer
 */
/* ****************************************************** */
int DX_Common_AES_CCM_Encrypt(unsigned char *keyBuf, unsigned char *nonce, unsigned int nonceLen, unsigned char *aData,
                              unsigned int aDatalen, unsigned char *plainTxt, unsigned int plainTxtLen,
                              unsigned char *enBuff, unsigned int *enBuffLen, unsigned char *tagBuff,
                              unsigned int tagBuffLen)
{
#if 0
    int rc  = 0;
    if ((keyBuf == NULL) ||
        (nonce == NULL) ||
        (plainTxt == NULL) ||
        (enBuff == NULL) ||
        (enBuffLen == NULL) ||
        (tagBuff == NULL)) {
        UTIL_LOG_ERR( "invalid input pointers\n");
        return 1;
    }
    /* check legth validity */
    memset(enBuff, 0, plainTxtLen);
    memset(tagBuff, 0, tagBuffLen);
    rc = DX_Common_AES_CBC_MAC_Encrypt(keyBuf, nonce, plainTxt, plainTxtLen, tagBuffLen, tagBuff);
    if (rc != 0) {
        UTIL_LOG_ERR( "failed to DX_Common_AES_CBC_MAC_Encrypt()\n");
        return 1;
    }

    rc = DX_Common_AES_CTR_Encrypt(plainTxt, plainTxtLen, keyBuf, 128/8, nonce, enBuff);
    if (rc != 0) {
        UTIL_LOG_ERR( "failed to DX_Common_AES_CTR_Encrypt()\n");
        return 1;
    }

#else
    EVP_CIPHER_CTX ccm_ctx;
    int outlen = 0;
    int rc     = 0;

    if ((keyBuf == NULL) || (nonce == NULL) || (plainTxt == NULL) || (enBuff == NULL) || (enBuffLen == NULL) ||
        (tagBuff == NULL)) {
        UTIL_LOG_ERR("invalid input pointers\n");
        return 1;
    }
    /* check legth validity */
    memset(enBuff, 0, plainTxtLen);
    memset(tagBuff, 0, tagBuffLen);

    EVP_CIPHER_CTX_init(&ccm_ctx);

    /* Set cipher type and mode */
    rc = EVP_EncryptInit_ex(&ccm_ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
    if (rc != 1) {
        UTIL_LOG_ERR("failed to EVP_EncryptInit_ex() for CCM cipher\n");
        rc = 1;
        goto ccmEnd;
    }
    /* Set nonce length if default 96 bits is not appropriate */
    rc = EVP_CIPHER_CTX_ctrl(&ccm_ctx, EVP_CTRL_CCM_SET_IVLEN, nonceLen, NULL);
    if (rc != 1) {
        UTIL_LOG_ERR("failed to EVP_CIPHER_CTX_ctrl() for nonce length\n");
        rc = 1;
        goto ccmEnd;
    }
    /* Set tag length */
    rc = EVP_CIPHER_CTX_ctrl(&ccm_ctx, EVP_CTRL_CCM_SET_TAG, tagBuffLen, NULL);
    if (rc != 1) {
        UTIL_LOG_ERR("failed to EVP_CIPHER_CTX_ctrl() for tag length\n");
        rc = 1;
        goto ccmEnd;
    }
    /* Initialise key and IV */
    UTIL_LOG_BYTE_BUFF("nonce", nonce, nonceLen);
    UTIL_LOG_BYTE_BUFF("keyBuf", keyBuf, 16);
    rc = EVP_EncryptInit_ex(&ccm_ctx, NULL, NULL, keyBuf, nonce);
    if (rc != 1) {
        UTIL_LOG_ERR("failed to EVP_EncryptInit_ex() for key and IV\n");
        rc = 1;
        goto ccmEnd;
    }
    if ((aDatalen > 0) && (aData != NULL)) {
        /* Set plaintext length: only needed if AAD is used */
        rc = EVP_EncryptUpdate(&ccm_ctx, NULL, &outlen, NULL, plainTxtLen);
        if (rc != 1) {
            UTIL_LOG_ERR("failed to EVP_EncryptUpdate() for plaintext length\n");
            rc = 1;
            goto ccmEnd;
        }
        /* Zero or one call to specify any AAD */
        UTIL_LOG_BYTE_BUFF("aData", aData, aDatalen);
        rc = EVP_EncryptUpdate(&ccm_ctx, NULL, &outlen, aData, aDatalen);
        if (rc != 1) {
            UTIL_LOG_ERR("failed to EVP_EncryptUpdate() for AAD\n");
            rc = 1;
            goto ccmEnd;
        }
    }

    /* Encrypt plaintext: can only be called once */
    UTIL_LOG_BYTE_BUFF("plainTxt", plainTxt, plainTxtLen);
    rc = EVP_EncryptUpdate(&ccm_ctx, enBuff, &outlen, plainTxt, plainTxtLen);
    if (rc != 1) {
        UTIL_LOG_ERR("failed to EVP_EncryptUpdate() for plaintext\n");
        rc = 1;
        goto ccmEnd;
    }
    if (outlen != plainTxtLen) {
        UTIL_LOG_ERR("ccm encrypt size(%d) != palin text size(%d)\n", outlen, plainTxtLen);
        rc = 1;
        goto ccmEnd;
    }
    UTIL_LOG_BYTE_BUFF("enBuff", enBuff, outlen);
    /* Finalise: note get no output for CCM */
    rc = EVP_EncryptFinal_ex(&ccm_ctx, &enBuff[outlen], &outlen);
    if (rc != 1) {
        UTIL_LOG_ERR("failed to EVP_EncryptFinal_ex()\n");
        rc = 1;
        goto ccmEnd;
    }
    /* Get tag */
    rc = EVP_CIPHER_CTX_ctrl(&ccm_ctx, EVP_CTRL_CCM_GET_TAG, tagBuffLen, tagBuff);
    if (rc != 1) {
        UTIL_LOG_ERR("failed to EVP_CIPHER_CTX_ctrl() to get the tag\n");
        rc = 1;
        goto ccmEnd;
    }
    UTIL_LOG_BYTE_BUFF("tagBuff", tagBuff, tagBuffLen);
    rc = 0;

ccmEnd:

    EVP_CIPHER_CTX_cleanup(&ccm_ctx);
    return rc;
#endif
}

/*
 * @brief Encrypts (AES CMAC) a given data and returns it.
 *
 * @param[in] pDataIn - the data to encrypt
 * @param[in] dataInSize - the data size
 * @param[in] pKey - the AES key
 * @param[in] keySize - the key size in bytes
 * @param[in] pOutput - Output buffer
 */
/* ****************************************************** */
int DX_Common_AES_CMAC_Encrypt(char *pDataIn, int dataInSize, char *pKey, int keySize, char *pOutput)
{
    CMAC_CTX *cmac_ctx = NULL;
    int rc             = 0;
    size_t tempOutSize = 0;

    if ((pKey == NULL) || (pDataIn == NULL) || (pOutput == NULL) ||
        ((keySize != AES_BLOCK_SIZE) && (keySize != (AES_BLOCK_SIZE * 2)))) {
        UTIL_LOG_ERR("Ilegal parameters\n");
        return 1;
    }
    cmac_ctx = CMAC_CTX_new();
    if (cmac_ctx == NULL) {
        UTIL_LOG_ERR("failed to CMAC_CTX_new\n");
        return 1;
    }
    memset(pOutput, 0, AES_BLOCK_SIZE);
    if (keySize == AES_BLOCK_SIZE) {
        rc = CMAC_Init(cmac_ctx, pKey, AES_BLOCK_SIZE, EVP_aes_128_cbc(), 0);
    } else {
        rc = CMAC_Init(cmac_ctx, pKey, AES_BLOCK_SIZE * 2, EVP_aes_256_cbc(), 0);
    }
    if (rc != 1) {
        UTIL_LOG_ERR("failed to CMAC_Init\n");
        rc = 2;
        goto cmacEnd;
    }
    rc = CMAC_Update(cmac_ctx, pDataIn, dataInSize);
    if (rc != 1) {
        UTIL_LOG_ERR("failed to CMAC_Update\n");
        rc = 3;
        goto cmacEnd;
    }
    rc = CMAC_Final(cmac_ctx, pOutput, &tempOutSize);
    if (rc != 1) {
        UTIL_LOG_ERR("failed to CMAC_Final\n");
        rc = 4;
        goto cmacEnd;
    }
    rc = 0;
cmacEnd:
    if (cmac_ctx != NULL) {
        CMAC_CTX_free(cmac_ctx);
    }
    return rc;
}

/*
 * @brief Calculates HASH on a given buffer, and returns the digest
 *
 * @param[in] pPemDecryted - the decrypted public key (input data for HASH)
 * @param[out] pHash - the HASH SHA 256 calculated on the data
 *
 */
/* ****************************************************** */
int DX_Common_CalcHash(unsigned char *pPemDecryted, int pemDecryptedSize, unsigned char *pHash, int hashSize)
{
    unsigned char hash[DIGEST_LENGTH];
    int i;

    /* Verify no NULL pointers */
    if ((pPemDecryted == NULL) || (pHash == NULL)) {
        UTIL_LOG_ERR("Illegal parameters \n");
        return -1;
    }

    /* verify the size is correct */
    if ((hashSize != DIGEST_LENGTH) && (hashSize != DIGEST_LENGTH / 2)) {
        UTIL_LOG_ERR("The digest size is incorrect it can either be %d or %d, given digest size is %d\n", DIGEST_LENGTH,
                     DIGEST_LENGTH / 2, hashSize);
        return -1;
    }

    /* Calculate the hash */
    SHA256(pPemDecryted, pemDecryptedSize, hash);

    /* copy the hash according to requested size */
    memcpy(pHash, hash, hashSize);
    return 0;
}

/*
 * @brief Calculates HASH on a given buffer, and returns the digest
 *
 * @param[in] pPemDecryted - the decrypted public key (input data for HASH)
 * @param[out] pHash - the HASH SHA 256 calculated on the data
 *
 */
/* ****************************************************** */
int DX_Common_CalcSha1(unsigned char *pDataIn, int dataInSize, unsigned char *pHash)
{
    unsigned char hash[SHA1_DIGEST_LENGTH];
    int i;

    /* Verify no NULL pointers */
    if ((pDataIn == NULL) || (pHash == NULL)) {
        UTIL_LOG_ERR("Illegal parameters \n");
        return -1;
    }

    /* Calculate the hash */
    SHA1(pDataIn, dataInSize, hash);

    /* copy the hash according to requested size */
    memcpy(pHash, hash, SHA1_DIGEST_LENGTH);
    return 0;
}
