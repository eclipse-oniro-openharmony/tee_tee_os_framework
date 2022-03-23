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

#ifndef _COMMON_CRYPTO_SYM_H
#define _COMMON_CRYPTO_SYM_H

#define DX_COMMON_CALC_CBC_ENCODE_SIZE(size) \
    (AES_BLOCK_SIZE + (((size + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE))
#define DIGEST_LENGTH 32

#define SHA1_DIGEST_LENGTH 20

/*
 * @brief The DX_Common_AES_CTR_Encrypt encrypts (AES CTR) a given data and returns it.
 *
 * @param[in] DataIn_ptr - the data to encrypt
 * @param[in] DataInSize - the data size
 * @param[in] Key_ptr - the AES key
 * @param[in] KeySize - AES key size (must be one of the allowed AES key sizes)
 * @param[in] IV_ptr - IV (AES IV size is constant)
 * @param[in] Output_ptr - Output buffer
 */
/* ****************************************************** */
int DX_Common_AES_CTR_Encrypt(char *DataIn_ptr, int DataInSize, char *Key_ptr, int KeySize, char *IV_ptr,
                              char *Output_ptr);

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
int DX_Common_AES_CBC_Decrypt(char *pwdFileName, char *pEncBuff, int encBuffSize, char *pDecBuff);

/*
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
int DX_Common_AES_CCM_Encrypt(unsigned char *keyBuf, unsigned char *nonce, unsigned int nonceLen, unsigned char *aData,
                              unsigned int aDatalen, unsigned char *plainTxt, unsigned int plainTxtLen,
                              unsigned char *enBuff, unsigned int *enBuffLen, unsigned char *tagBuff,
                              unsigned int tagBuffLen);

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
int DX_Common_AES_CMAC_Encrypt(char *pDataIn, int dataInSize, char *pKey, int keySize, char *pOutput);

/*
 * @brief The Common_CalcHash calculates HASH on the public key and Np using OpenSSL.
 *
 * @param[in] pPemDecryted - the decrypted public key (input data for HASH)
 * @param[out] pHash - the HASH SHA 256 calculated on the data
 *
 */
/* ****************************************************** */
int DX_Common_CalcHash(unsigned char *pPemDecryted, int pemDecryptedSize, unsigned char *pHash, int hashSize);

/*
 * @brief The Common_CalcHash calculates HASH on the public key and Np using OpenSSL.
 *
 * @param[in] pPemDecryted - the decrypted public key (input data for HASH)
 * @param[out] pHash - the HASH SHA 256 calculated on the data
 *
 */
/* ****************************************************** */
int DX_Common_CalcSha1(unsigned char *pDataIn, int dataInSize, unsigned char *pHash);

#endif
