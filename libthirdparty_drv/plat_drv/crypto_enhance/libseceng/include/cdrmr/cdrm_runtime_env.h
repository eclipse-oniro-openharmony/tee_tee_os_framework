/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: cdrm runtime env
 * Create     : 2019/11/04
 */
#ifndef __CDRM_RUNTIME_ENV_H
#define __CDRM_RUNTIME_ENV_H

typedef enum {
    CDRMR_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1   = 0x01,
    CDRMR_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 = 0x02,
    CDRMR_ALG_RSASSA_PKCS1_V1_5_SHA1       = 0x03,
    CDRMR_ALG_RSASSA_PKCS1_V1_5_SHA256     = 0x04,
} CDRMR_RSA_Sign_Algorithm;

typedef enum {
    CDRMR_ALG_RSAES_NOPAD                  = 0x01,
    CDRMR_ALG_RSAES_PKCS1_V1_5             = 0x02,
    CDRMR_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1   = 0x03,
    CDRMR_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256 = 0x04,
} CDRMR_RSA_Crypto_Algorithm;

typedef enum {
    CDRMR_ALG_SM4_CBC_NOPAD      = 0x01,
    CDRMR_ALG_SM4_CTR            = 0x02,
    CDRMR_ALG_AES_128_CBC_NOPAD  = 0x03,
    CDRMR_ALG_AES_128_CTR        = 0x04,
    CDRMR_ALG_AES_256_CBC_NOPAD  = 0x05,
    CDRMR_ALG_AES_256_CTR        = 0x06,
    CDRMR_ALG_SM4_ECB_NOPAD      = 0x07,
    CDRMR_ALG_AES_128_ECB_NOPAD  = 0x08,
    CDRMR_ALG_AES_256_ECB_NOPAD  = 0x09,
    CDRMR_ALG_AES_WRAP           = 0x0a,
    CDRMR_ALG_AES_UNWRAP         = 0x0b,
} CDRMR_Symmetric_Crypto_Algorithm;

typedef enum {
    CDRMR_ALG_SM3    = 0x01,
    CDRMR_ALG_SHA1   = 0x02,
    CDRMR_ALG_SHA256 = 0x03,
} CDRMR_HASH_Algorithm;

typedef enum {
    CDRMR_ALG_HMAC_SM3    = 0x01,
    CDRMR_ALG_HMAC_SHA1   = 0x02,
    CDRMR_ALG_HMAC_SHA256 = 0x03,
} CDRMR_HMAC_Algorithm;

typedef enum {
    CDRMR_ALG_CENC_AES_CTR = 0x01,
    CDRMR_ALG_CENC_AES_CBC = 0x02,
    CDRMR_ALG_CENC_SM4_CTR = 0x03,
    CDRMR_ALG_CENC_SM4_CBC = 0x04,
} CDRMR_Cenc_Algorithm;

typedef enum {
    CDRMR_STORAGE_PRIVATE  = 0x01,
    CDRMR_STORAGE_RESERVED = 0x02,
} CDRMR_Storage_Type;

typedef enum {
    CDRMR_STORAGE_DATA_ACCESS_READ = 0x01,
    CDRMR_STORAGE_DATA_ACCESS_WRITE = 0x02,
    CDRMR_STORAGE_DATA_ACCESS_REMOVE = 0x04,
    CDRMR_STORAGE_DATA_ACCESS_OVERWRITE = 0x08,
    CDRMR_STORAGE_DATA_ACCESS_SHARE_READ = 0x10,
    CDRMR_STORAGE_DATA_ACCESS_SHARE_WRITE = 0x20,
} CDRMR_Storage_Data_Access_Flag;

typedef enum {
    CDRM_KEY_ALG_SM2_256 = 0,
    CDRM_KEY_ALG_SM3_256 = 1,
    CDRM_KEY_ALG_SM4_CBC = 2,
    CDRM_KEY_ALG_SM4_CTR = 3,
    CDRM_KEY_ALG_RSA_1024 = 4,
    CDRM_KEY_ALG_RSA_2048 = 5,
    CDRM_KEY_ALG_SHA1 = 6,
    CDRM_KEY_ALG_SHA256 = 7,
    CDRM_KEY_ALG_AES128_CBC = 8,
    CDRM_KEY_ALG_AES128_CTR = 9,
    CDRM_KEY_ALG_BUTT,
} CDRM_Key_Algorithm;

typedef void* CDRMR_CipherHandle;

typedef void* CDRMR_HashHandle;

typedef void* CDRMR_HMacHandle;

typedef void* CDRMR_SecureStorageObjectHandle;

typedef struct __CDRMR_SubSample {
    unsigned int u32ClearHeaderLen;
    unsigned int u32PayLoadLen;
} CDRMR_SubSample;

typedef struct __CDRMR_Cenc {
    unsigned int u32KeyLen;
    unsigned char *pu8Key;
    unsigned int u32IVLen;
    unsigned char *pu8IV;
    unsigned int u32FirstEncryptOffset;
    CDRMR_SubSample *pstSubSample;
    unsigned int u32SubsampleNum;
} CDRMR_Cenc;

typedef struct __CDRMR_Time {
    unsigned int seconds;
    unsigned int millis;
} CDRMR_Time;

#define RSAref_MAX_BITS 2048
#define RSAref_MAX_LEN ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN ((RSAref_MAX_PBITS + 7) / 8)

typedef struct RSArefPublicKey_st {
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st {
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    unsigned char d[RSAref_MAX_LEN];
    unsigned char prime[2][RSAref_MAX_PLEN];
    unsigned char pexp[2][RSAref_MAX_PLEN];
    unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

#define ECCref_MAX_BITS 512
#define ECCref_MAX_LEN ((ECCref_MAX_BITS + 7) / 8)
typedef struct ECCrefPublicKey_st {
    unsigned int bits;
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st {
    unsigned int bits;
    unsigned char K[ECCref_MAX_LEN];
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
} ECCrefPrivateKey;

typedef struct ECCCipher_st {
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
    unsigned char M[32];
    unsigned int L;
    unsigned char C[1];
} ECCCipher;

typedef struct ECCSignature_st {
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
} ECCSignature;

int CDRMR_Crypto_Sm2Sign(ECCrefPrivateKey *pstECCPrivateKey,
                         unsigned char *pu8InData, unsigned int u32InDataLen,
                         ECCSignature *pstECCSignature);

int CDRMR_Crypto_Sm2Verify(ECCrefPublicKey *pstECCPublicKey,
                           unsigned char *pu8InData, unsigned int u32InDataLen,
                           ECCSignature *pstECCSignature);

int CDRMR_Crypto_Sm2Encrypt(ECCrefPublicKey *pstECCPublicKey,
                            unsigned char *pu8Input, unsigned int u32InLen,
                            ECCCipher *pstECCCipher);

int CDRMR_Crypto_Sm2Decrypt(ECCrefPrivateKey *pstECCPrivateKey,
                            unsigned char *pu8Output, unsigned int *pu32OutLen,
                            ECCCipher *pstECCCipher);

int CDRMR_Crypto_RsaSign(CDRMR_RSA_Sign_Algorithm algo,
                         RSArefPrivateKey *pstRSAPrivateKey,
                         unsigned char *pu8InData, unsigned int u32InDataLen,
                         unsigned char *pu8HashData, unsigned int u32HashDataLen,
                         unsigned char *pu8OutSign, unsigned int *pu32OutSignLen);

int CDRMR_Crypto_RsaVerify(CDRMR_RSA_Sign_Algorithm algo,
                           RSArefPublicKey *pstRSAPublicKey,
                           unsigned char *pu8InData, unsigned int u32InDataLen,
                           unsigned char *pu8HashData, unsigned int u32HashDataLen,
                           unsigned char *pu8InSign, unsigned int u32InSignLen);

int CDRMR_Crypto_RsaEncrypt(CDRMR_RSA_Crypto_Algorithm algo,
                            RSArefPublicKey *pstRSAPublicKey,
                            unsigned char *pu8Input, unsigned int u32InLen,
                            unsigned char *pu8Output, unsigned int *pu32OutLen);

int CDRMR_Crypto_RsaDecrypt(CDRMR_RSA_Crypto_Algorithm algo,
                            RSArefPrivateKey *pstRSAPrivateKey,
                            unsigned char *pu8Input, unsigned int u32InLen,
                            unsigned char *pu8Output, unsigned int *pu32OutLen);

int CDRMR_Crypto_SymmetricEncrypt(CDRMR_Symmetric_Crypto_Algorithm algo,
                                  unsigned char *pu8Key, unsigned int u32KeyLen,
                                  unsigned char *pu8Iv, unsigned int u32IvLen,
                                  unsigned char *pu8Input,
                                  unsigned int u32InLen,
                                  unsigned char *pu8Output,
                                  unsigned int *pu32OutLen);

int CDRMR_Crypto_SymmetricDecrypt(CDRMR_Symmetric_Crypto_Algorithm algo,
                                  unsigned char *pu8Key, unsigned int u32KeyLen,
                                  unsigned char *pu8Iv, unsigned int u32IvLen,
                                  unsigned char *pu8Input,
                                  unsigned int u32InLen,
                                  unsigned char *pu8Output,
                                  unsigned int *pu32OutLen);

int CDRMR_Crypto_HashInit(CDRMR_HASH_Algorithm algo,
                          CDRMR_HashHandle *phHashHandle);

int CDRMR_Crypto_HashUpdate(CDRMR_HashHandle hHashHandle,
                            unsigned char *pu8InputData,
                            unsigned int u32InputDataLen);

int CDRMR_Crypto_HashDoFinal(CDRMR_HashHandle hHashHandle,
                             unsigned char *pu8OutputHash,
                             unsigned int *pu32OutputHashLen);

int CDRMR_Crypto_HmacInit(CDRMR_HMAC_Algorithm algo, unsigned char *pu8Key,
                          unsigned int pu32KeyLen,
                          CDRMR_HMacHandle *phHmacHandle);

int CDRMR_Crypto_HmacUpdate(CDRMR_HMacHandle hHmacHandle,
                            unsigned char *pu8InputData,
                            unsigned int u32InputDataLen);

int CDRMR_Crypto_HmacDoFinal(CDRMR_HMacHandle hHmacHandle,
                             unsigned char *pu8OutputHmac,
                             unsigned int *pu32OutputHmacLen);

int CDRMR_Cipher_Init(void);

int CDRMR_Cipher_DeInit(void);

int CDRMR_Cipher_CreateHandle(CDRMR_CipherHandle *phCipher,
                              void *pCipherReserved);

int CDRMR_Cipher_DestroyHandle(CDRMR_CipherHandle hCipher);

int CDRMR_Cipher_ConfigHandle(CDRMR_CipherHandle hCipher,
                              CDRMR_Symmetric_Crypto_Algorithm algo,
                              unsigned char *pu8Key, unsigned int pu32KeyLen,
                              unsigned char *pu8Iv, unsigned int pu32IvLen);

int CDRMR_Cipher_Copy(CDRMR_CipherHandle hCipher,
                      unsigned int u32NonSecInputPhyAddr,
                      unsigned int u32SecOutputPhyAddr,
                      unsigned int u32ByteLength);

int CDRMR_Cipher_Encrypt(CDRMR_CipherHandle hCipher, unsigned int u32SrcPhyAddr,
                         unsigned int u32DestPhyAddr,
                         unsigned int u32ByteLength);

int CDRMR_Cipher_Decrypt(CDRMR_CipherHandle hCipher, unsigned int u32SrcPhyAddr,
                         unsigned int u32DestPhyAddr,
                         unsigned int u32ByteLength);

int CDRMR_Cipher_CENCDecrypt(CDRMR_CipherHandle hCipher,
                             CDRMR_Cenc_Algorithm algo, CDRMR_Cenc *pstCENC,
                             unsigned char *pu8InputPhyAddr,
                             unsigned int u32InputLen,
                             unsigned char *pu8OutputPhyAddr,
                             unsigned int *pu32OutputLen);

int CDRMR_SecureStorage_CreateObject(
    CDRMR_Storage_Type storageType, CDRMR_Storage_Data_Access_Flag flags,
    unsigned char *pu8ObjectId, unsigned int u32ObjectIdLen,
    CDRMR_SecureStorageObjectHandle *phObjectHandle);

int CDRMR_SecureStorage_OpenObject(
    CDRMR_Storage_Type storageType, CDRMR_Storage_Data_Access_Flag flags,
    unsigned char *pu8ObjectId, unsigned int u32ObjectIdLen,
    CDRMR_SecureStorageObjectHandle *phObjectHandle);

int CDRMR_SecureStorage_ReadObjectData(
    CDRMR_SecureStorageObjectHandle hObjectHandle, unsigned char *pu8Buffer,
    unsigned int *pu32BufferLen);

int CDRMR_SecureStorage_WriteObjectData(
    CDRMR_SecureStorageObjectHandle hObjectHandle, unsigned char *pu8Buffer,
    unsigned int u32BufferLen);

int CDRMR_SecureStorage_GetObjectSize(
    CDRMR_SecureStorageObjectHandle hObjectHandle,
    unsigned int *pu32ObjectDataLen);

int CDRMR_SecureStorage_CloseObject(
    CDRMR_SecureStorageObjectHandle hObjectHandle);

int CDRMR_SecureStorage_CloseAndRemoveObject(
    CDRMR_SecureStorageObjectHandle hObjectHandle);

int CDRMR_SecureStorage_WriteOTP(unsigned char *pu8Data,
                                 unsigned int u32DataLen,
                                 unsigned int u32OTPAddr);

int CDRMR_SecureStorage_LockOTP(unsigned int u32OTPLockAddr);

int CDRMR_SecureStorage_ReadOTP(unsigned char *pu8OutputData,
                                unsigned int u32OutputDataLen,
                                unsigned int u32OTPAddr);

int CDRMR_Random_GetNumber(unsigned int *pu32RandomNumber);

void *CDRMR_SecureMemory_Malloc(unsigned int u32Size);

void CDRMR_SecureMemory_Free(void *buffer);

void *CDRMR_SecureMemory_Memcpy(void *dest, void *src, unsigned int u32Size);

int CDRMR_SecureMemory_Memcmp(void *buffer1, void *buffer2,
                              unsigned int u32Size);

void *CDRMR_SecureMemory_Memset(void *buffer, int s32Value,
                                unsigned int u32Size);

void CDRMR_Time_GetSystemTime(CDRMR_Time *time);

int CDRMR_Time_GetTAPersistentTime(CDRMR_Time *time);

int CDRMR_Time_SetTAPersistentTime(CDRMR_Time *time);

void CDRMR_Time_GetREETime(CDRMR_Time *time);

int CDRMR_OutputControl_GetMaxCapability(unsigned int u32Type, void *caps);

int CDRMR_OutputControl_GetCurrentCapabilityStatus(unsigned int u32Type,
                                                   void *status);

int CDRMR_OutputControl_ConfigCapability(unsigned int u32Type, void *params);

int CDRM_Key_OpenTASession(void);

void CDRM_Key_CloseTASession(void);

int CDRM_Key_Insert_KeySlot(unsigned char* pTransportKey, unsigned int u32TransportKeyLen, int* pKeyIndex,
    unsigned char* pPasswd, unsigned int u32PasswdLen, unsigned char* pPrivateKey, unsigned int u32PrivateKeyLen,
    unsigned char* pCert, unsigned int u32CertLen);

int CDRM_Key_GetCert(unsigned int u32KeyIndex, unsigned char* pPasswd, unsigned int u32PasswdLen, unsigned char* pCert,
    unsigned int* pCertLen);

int CDRM_Key_PrivateKey_Sign(unsigned int u32KeyIndex, CDRM_Key_Algorithm alg, unsigned char* pPasswd,
    unsigned int u32PasswdLen, unsigned char* pInputBuffer, unsigned int u32InputBufferLen,
    unsigned char* pOutputBuffer, unsigned int* pOutputBufferLen);

int CDRM_Key_PrivateKey_Decrypt(unsigned int u32KeyIndex, CDRM_Key_Algorithm alg, unsigned char* pPasswd,
    unsigned int u32PasswdLen, unsigned char* pInputBuffer, unsigned int u32InputBufferLen,
    unsigned char* pOutputBuffer, unsigned int* pOutputBufferLen);

int CDRM_Key_GetNewKeyIndex(unsigned int* pNewKeyIndex);
#endif
