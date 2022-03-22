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

#ifndef _COMMON_CRYPTO_ASYM_H
#define _COMMON_CRYPTO_ASYM_H

#define RSA_USE_PKCS_21_VERSION 0x01
#define RSA_USE_PKCS_15_VERSION 0x02

/*
 * @brief Verifies RSA signature.
 *
 * The function follows the steps:
 * 1. Read RSA private key structure
 * 2. Call function according to PKCS version to create RSA signature
 *
 * @param[in] pkcsVersion - the version used (according to global definitions of available versions)
 * @param[in] pDataIn - the data to sign on
 * @param[in] dataInSize - the data size
 * @param[in] pPemEncryptedFileName - the private key file
 * @param[in] pKeyPwd - the passphrase string
 * @param[out] pSignature - the RSA signature
 *
 */
/* ****************************************************** */
int DX_Common_RSA_Verify(int pkcsVersion, char *pPubKey, char *pDataIn, int dataInSize, char *pSignature);

/*
 * @brief The DX_Common_RSA_Sign generates RSA signature and returns it.
 *
 * The function follows the steps:
 * 1. Read RSA private key structure
 * 2. Call function according to PKCS version to create RSA signature
 *
 * @param[in] pkcsVersion - the version used (according to global definitions of available versions)
 * @param[in] DataIn_ptr - the data to sign on
 * @param[in] DataInSize - the data size
 * @param[in] PemEncryptedFileName_ptr - the private key file
 * @param[in] Key_ptr - the passphrase string
 * @param[out] Signature_ptr - the RSA signature
 *
 */
/* ****************************************************** */
int DX_Common_RSA_Sign(int pkcsVersion, char *DataIn_ptr, unsigned int DataInSize, char *PemEncryptedFileName_ptr,
                       char *Key_ptr, char *Signature_ptr);

/*
 * @brief Encrypts data using RSA.
 *
 * The function follows the steps:
 * 1. Read RSA private key structure
 * 2. Call function according to PKCS version to create RSA signature
 *
 * @param[in] pkcsVersion - the version used (according to global definitions of available versions)
 * @param[in] pPemEncryptedFileName - the private key file
 * @param[in] pKeyPwd - the passphrase string
 * @param[in] pDataIn - the data to encrypt
 * @param[in] dataInSize - the data size
 * @param[out] pEncData - the encrypted data
 *
 */
/* ****************************************************** */
int DX_Common_RSA_Encrypt(int pkcsVersion, char *pPubKey, char *pDataIn, int dataInSize, char *pEncData);

/*
 * @brief Decrypts data using RSA.
 *
 * The function follows the steps:
 * 1. Read RSA private key structure
 * 2. Call function according to PKCS version to create RSA signature
 *
 * @param[in] pkcsVersion - the version used (according to global definitions of available versions)
 * @param[in] pPemEncryptedFileName - the private key file
 * @param[in] pKeyPwd - the passphrase string
 * @param[in] pEnDataIn - the data to decrypt
 * @param[in] enDataInSize - the encrypted data size
 * @param[out] pData - the decrypted data
 *
 */
/* ****************************************************** */
int DX_Common_RSA_Decrypt(int pkcsVersion, char *pPemEncryptedFileName, char *pKeyPwd, char *pEnDataIn,
                          int enDataInSize, char *pData);

/*
 * @brief The function DX_Common_RSA_CalculateH calculates the H it returns it as binary string
 *
 * @param[in] N_ptr - public key N, represented as array of ascii's (0xbc is translated
 *                    to 0x62 0x63)
 * @param[out] H_ptr - The H result. H size is N_SIZE_IN_BYTES*2 + 1
 *
 */
/* ****************************************************** */
int DX_Common_RSA_CalculateH(const char *N_ptr, char *H_ptr);

/*
 * @brief The DX_Common_RSA_LoadKey reads RSA key from the file using passphrase
 *        and returns its decrypted value.
 *
 * @param[in] PemEncryptedFileName_ptr - file name
 * @param[in] Key_ptr - passphrase
 */
/* ****************************************************** */
int DX_Common_RSA_LoadKey(char *PemEncryptedFileName_ptr, char *Key_ptr, char *PemDecryted);

/*
 * @brief The DX_Common_RAND_Bytes reads RSA key from the file using passphrase
 *        and returns its decrypted value.
 *
 * @param[in] PemEncryptedFileName_ptr - file name
 * @param[in] Key_ptr - passphrase
 */
/* ****************************************************** */
int DX_Common_RAND_Bytes(int numBytes, char *buf);

#endif
