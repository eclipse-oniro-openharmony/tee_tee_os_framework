/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, DX function exported by libtee_shared.so
 * Create: 2019-11-25
 */
#ifndef DX_CCMGR_OPS_EXT_H
#define DX_CCMGR_OPS_EXT_H

#ifdef DX_ENABLE
#include "dx_cclib.h"
#include "crys_hash.h"
#include "crys_hmac.h"
#include "crys_des.h"
#include "crys_aes.h"
#include "crys_aesccm.h"
#include "crys_kdf.h"
#include "dx_util.h"
#include "crys_rnd.h"
#include "crys_rsa_build.h"
#include "crys_rsa_schemes.h"
#include "crys_rsa_prim.h"
#include "crys_dh.h"
#include "crys_ecpki_types.h"
#include "dx_cc_defs.h"
#include "dx_util_oem_asset.h"

CRYSError_t __CC_DX_power_on();
CRYSError_t __CC_DX_power_down();
CRYSError_t __CC_CRYS_HMAC_Init(CRYS_HMACUserContext_t *ContextID_ptr, CRYS_HASH_OperationMode_t OperationMode,
                                DxUint8_t *key_ptr, DxUint16_t keySize);
CRYSError_t __CC_CRYS_HMAC_Update(CRYS_HMACUserContext_t *ContextID_ptr, DxUint8_t *DataIn_ptr,
                                  DxUint32_t DataInSize);
CRYSError_t __CC_CRYS_HMAC_Finish(CRYS_HMACUserContext_t *ContextID_ptr, CRYS_HASH_Result_t HmacResultBuff);
CRYSError_t __CC_CRYS_HMAC_Free(CRYS_HMACUserContext_t *ContextID_ptr);
CRYSError_t __CC_CRYS_HMAC(CRYS_HASH_OperationMode_t OperationMode, DxUint8_t *key_ptr, DxUint16_t keySize,
                           DxUint8_t *DataIn_ptr, DxUint32_t DataSize, CRYS_HASH_Result_t HmacResultBuff);
CRYSError_t __CC_CRYS_DES_Init(CRYS_DESUserContext_t *ContextID_ptr, CRYS_DES_Iv_t IV_ptr,
                               CRYS_DES_Key_t *Key_ptr, CRYS_DES_NumOfKeys_t NumOfKeys,
                               CRYS_DES_EncryptMode_t EncryptDecryptFlag,
                               CRYS_DES_OperationMode_t OperationMode);
CRYSError_t __CC_CRYS_DES_Block(CRYS_DESUserContext_t *ContextID_ptr, /* in */
                                DxUint8_t *DataIn_ptr,                /* in */
                                DxUint32_t DataInSize,                /* in */
                                DxUint8_t *DataOut_ptr);              /* in/out */
CRYSError_t __CC_CRYS_DES_Free(CRYS_DESUserContext_t *ContextID_ptr);
CRYSError_t __CC_CRYS_AES(CRYS_AES_IvCounter_t IVCounter_ptr, CRYS_AES_Key_t Key_ptr, CRYS_AES_KeySize_t KeySize,
                          CRYS_AES_EncryptMode_t EncryptDecryptFlag, CRYS_AES_OperationMode_t OperationMode,
                          DxUint8_t *DataIn_ptr, DxUint32_t DataInSize, DxUint8_t *DataOut_ptr);
CRYSError_t __CC_CRYS_AES_Init(CRYS_AESUserContext_t *ContextID_ptr, CRYS_AES_IvCounter_t IVCounter_ptr,
                               CRYS_AES_Key_t Key_ptr, CRYS_AES_KeySize_t KeySizeID,
                               CRYS_AES_EncryptMode_t EncryptDecryptFlag,
                               CRYS_AES_OperationMode_t OperationMode);
CRYSError_t __CC_CRYS_AES_Block(CRYS_AESUserContext_t *ContextID_ptr, DxUint8_t *DataIn_ptr,
                                DxUint32_t DataInSize, DxUint8_t *DataOut_ptr);
CRYSError_t __CC_CRYS_AES_Finish(CRYS_AESUserContext_t *ContextID_ptr, DxUint8_t *DataIn_ptr,
                                 DxUint32_t DataInSize, DxUint8_t *DataOut_ptr);
CRYSError_t __CC_CRYS_KDF_KeyDerivFunc(DxUint8_t *ZZSecret_ptr, DxUint32_t ZZSecretSize,
                                       CRYS_KDF_OtherInfo_t *OtherInfo_ptr, CRYS_KDF_HASH_OpMode_t KDFhashMode,
                                       CRYS_KDF_DerivFuncMode_t derivation_mode, DxUint8_t *KeyingData_ptr,
                                       DxUint32_t KeyingDataSizeBytes);
DxUTILError_t __CC_DX_UTIL_CmacDeriveKey(DX_CRYPTO_KEY_TYPE_t aesKeyType, DxUint8_t *pDataIn,
                                         DxUint32_t DataInSize, DxUint8_t *pCmacResult);
CRYSError_t __CC_CRYS_RND_GenerateVector(DxUint16_t outSizeBytes, /* in */
                                         DxUint8_t *out_ptr);     /* out */
CRYSError_t __CC_CRYS_RSA_Build_PubKey(CRYS_RSAUserPubKey_t *UserPubKey_ptr, DxUint8_t *Exponent_ptr,
                                       DxUint16_t ExponentSize, DxUint8_t *Modulus_ptr, DxUint16_t ModulusSize);
CRYSError_t __CC_CRYS_RSA_KG_GenerateKeyPair(DxUint8_t *pubExp_ptr, DxUint16_t pubExpSizeInBytes,
                                             DxUint32_t keySize, CRYS_RSAUserPrivKey_t *userPrivKey_ptr,
                                             CRYS_RSAUserPubKey_t *userPubKey_ptr,
                                             CRYS_RSAKGData_t *keyGenData_ptr);
CRYSError_t __CC_CRYS_RSA_Build_PrivKey(CRYS_RSAUserPrivKey_t *UserPrivKey_ptr, DxUint8_t *PrivExponent_ptr,
                                        DxUint16_t PrivExponentSize, DxUint8_t *PubExponent_ptr,
                                        DxUint16_t PubExponentSize, DxUint8_t *Modulus_ptr,
                                        DxUint16_t ModulusSize);
CRYSError_t __CC_CRYS_RSA_Build_PrivKeyCRT(CRYS_RSAUserPrivKey_t *UserPrivKey_ptr, DxUint8_t *P_ptr,
                                           DxUint16_t PSize, DxUint8_t *Q_ptr, DxUint16_t QSize,
                                           DxUint8_t *dP_ptr, DxUint16_t dPSize, DxUint8_t *dQ_ptr,
                                           DxUint16_t dQSize, DxUint8_t *qInv_ptr, DxUint16_t qInvSize);
CRYSError_t __CC_CRYS_RSA_Get_PubKey(CRYS_RSAUserPubKey_t *UserPubKey_ptr, DxUint8_t *Exponent_ptr,
                                     DxUint16_t *ExponentSize_ptr, DxUint8_t *Modulus_ptr,
                                     DxUint16_t *ModulusSize_ptr);
CRYSError_t __CC__DX_RSA_SCHEMES_Encrypt(CRYS_RSAUserPubKey_t *UserPubKey_ptr,
                                         CRYS_RSAPrimeData_t *PrimeData_ptr, CRYS_RSA_HASH_OpMode_t hashFunc,
                                         DxUint8_t *L, DxUint16_t Llen, CRYS_PKCS1_MGF_t MGF,
                                         DxUint8_t *DataIn_ptr, DxUint16_t DataInSize, DxUint8_t *Output_ptr,
                                         CRYS_PKCS1_version PKCS1_ver);
CRYSError_t __CC__DX_RSA_SCHEMES_Decrypt(CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
                                         CRYS_RSAPrimeData_t *PrimeData_ptr, CRYS_RSA_HASH_OpMode_t hashFunc,
                                         DxUint8_t *L, DxUint16_t Llen, CRYS_PKCS1_MGF_t MGF,
                                         DxUint8_t *DataIn_ptr, DxUint16_t DataInSize, DxUint8_t *Output_ptr,
                                         DxUint16_t *OutputSize_ptr, CRYS_PKCS1_version PKCS1_ver);
CRYSError_t __CC__DX_RSA_Sign(CRYS_RSAPrivUserContext_t *UserContext_ptr, CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
                              CRYS_RSA_HASH_OpMode_t hashFunc, CRYS_PKCS1_MGF_t MGF, DxUint16_t SaltLen,
                              DxUint8_t *DataIn_ptr, DxUint32_t DataInSize, DxUint8_t *Output_ptr,
                              DxUint16_t *OutputSize_ptr, CRYS_PKCS1_version PKCS1_ver);

CRYSError_t __CC__DX_RSA_Verify(CRYS_RSAPubUserContext_t *UserContext_ptr, CRYS_RSAUserPubKey_t *UserPubKey_ptr,
                                CRYS_RSA_HASH_OpMode_t hashFunc, CRYS_PKCS1_MGF_t MGF, DxUint16_t SaltLen,
                                DxUint8_t *DataIn_ptr, DxUint32_t DataInSize, DxUint8_t *Sig_ptr,
                                CRYS_PKCS1_version PKCS1_ver);
CRYSError_t __CC_CRYS_RSA_PRIM_Encrypt(CRYS_RSAUserPubKey_t *UserPubKey_ptr, CRYS_RSAPrimeData_t *PrimeData_ptr,
                                       DxUint8_t *Data_ptr, DxUint16_t DataSize, DxUint8_t *Output_ptr);
CRYSError_t __CC_CRYS_RSA_PRIM_Decrypt(CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
                                       CRYS_RSAPrimeData_t *PrimeData_ptr, DxUint8_t *Data_ptr,
                                       DxUint16_t DataSize, DxUint8_t *Output_ptr);
// ecc
CRYSError_t __CC_CRYS_ECPKI_BuildPublKey(CRYS_ECPKI_DomainID_t DomainID, /* in */
                                         DxUint8_t *PublKeyIn_ptr,       /* in */
                                         DxUint32_t PublKeySizeInBytes,  /* in */
                                         /* in */
                                         CRYS_ECPKI_UserPublKey_t *UserPublKey_ptr);
CRYSError_t __CC_CRYS_ECPKI_BuildPublKeyFullCheck(CRYS_ECPKI_DomainID_t DomainID,            /* in */
                                                  DxUint8_t *PublKeyIn_ptr,                  /* in */
                                                  DxUint32_t PublKeySizeInBytes,             /* in */
                                                  CRYS_ECPKI_UserPublKey_t *UserPublKey_ptr, /* out */
                                                  /* in */
                                                  CRYS_ECPKI_BUILD_TempData_t *TempBuff_ptr);
CRYSError_t __CC_CRYS_ECPKI_BuildPrivKey(CRYS_ECPKI_DomainID_t DomainID, /* in */
                                         DxUint8_t *PrivKeyIn_ptr,       /* in */
                                         DxUint32_t PrivKeySizeInBytes,  /* in */
                                         /* out */
                                         CRYS_ECPKI_UserPrivKey_t *UserPrivKey_ptr);
CRYSError_t __CC_CRYS_ECDH_SVDP_DH(CRYS_ECPKI_UserPublKey_t *PartnerPublKey_ptr, /* in */
                                   CRYS_ECPKI_UserPrivKey_t *UserPrivKey_ptr,    /* in */
                                   DxUint8_t *SharedSecretValue_ptr,             /* out */
                                   DxUint32_t *SharedSecrValSize_ptr,            /* in/out */
                                   /* in */
                                   CRYS_ECDH_TempData_t *TempBuff_ptr);
CRYSError_t __CC_CRYS_ECDSA_Sign(CRYS_ECDSA_SignUserContext_t *SignUserContext_ptr, /* in/out */
                                 CRYS_ECPKI_UserPrivKey_t *SignerPrivKey_ptr,       /* in */
                                 CRYS_ECPKI_HASH_OpMode_t HashMode,                 /* in */
                                 DxUint8_t *MessageDataIn_ptr,                      /* in */
                                 DxUint32_t MessageSizeInBytes,                     /* in */
                                 DxUint8_t *SignatureOut_ptr,                       /* out */
                                 /* in */
                                 DxUint32_t *SignatureOutSize_ptr);
CRYSError_t __CC_CRYS_ECDSA_Verify(CRYS_ECDSA_VerifyUserContext_t *VerifyUserContext_ptr, /* in/out */
                                   CRYS_ECPKI_UserPublKey_t *UserPublKey_ptr,             /* in */
                                   CRYS_ECPKI_HASH_OpMode_t HashMode,                     /* in */
                                   DxUint8_t *SignatureIn_ptr,                            /* in */
                                   DxUint32_t SignatureSizeBytes,                         /* in */
                                   DxUint8_t *MessageDataIn_ptr,                          /* in */
                                   /* in */
                                   DxUint32_t MessageSizeInBytes);
CRYSError_t __CC_CRYS_ECPKI_GenKeyPair(CRYS_ECPKI_DomainID_t DomainID,            /* in */
                                       CRYS_ECPKI_UserPrivKey_t *UserPrivKey_ptr, /* out */
                                       CRYS_ECPKI_UserPublKey_t *UserPublKey_ptr, /* out */
                                       /* in */
                                       CRYS_ECPKI_KG_TempData_t *TempData_ptr);
CRYSError_t __CC_CRYS_ECPKI_ExportPublKey(CRYS_ECPKI_UserPublKey_t *UserPublKey_ptr, /* in */
                                          CRYS_ECPKI_PointCompression_t Compression, /* in */
                                          DxUint8_t *ExternPublKey_ptr,              /* in */
                                          /* in/out */
                                          DxUint32_t *PublKeySizeInBytes_ptr);

#define __CC_CRYS_RSA_OAEP_Encrypt(UserPubKey_ptr, PrimeData_ptr, HashMode, L, Llen, MGF, Data_ptr, DataSize,       \
                                   Output_ptr)                                                                      \
    __CC__DX_RSA_SCHEMES_Encrypt(UserPubKey_ptr, PrimeData_ptr, HashMode, L, Llen, MGF, \
                                 Data_ptr, DataSize, Output_ptr, CRYS_PKCS1_VER21)

#define __CC_CRYS_RSA_PKCS1v15_Encrypt(UserPubKey_ptr, PrimeData_ptr, DataIn_ptr, DataInSize, Output_ptr) \
    __CC__DX_RSA_SCHEMES_Encrypt(UserPubKey_ptr, PrimeData_ptr, CRYS_RSA_HASH_NO_HASH_mode, DX_NULL, 0,   \
                                 CRYS_PKCS1_NO_MGF, DataIn_ptr, DataInSize, Output_ptr, CRYS_PKCS1_VER15)

#define __CC_CRYS_RSA_OAEP_Decrypt(UserPrivKey_ptr, PrimeData_ptr, HashMode, L, Llen, MGF, Data_ptr, DataSize,       \
                                   Output_ptr, OutputSize_ptr)                                                       \
    __CC__DX_RSA_SCHEMES_Decrypt(UserPrivKey_ptr, PrimeData_ptr, HashMode, L, Llen, MGF, \
                                 Data_ptr, DataSize, Output_ptr, OutputSize_ptr, CRYS_PKCS1_VER21)

#define __CC_CRYS_RSA_PKCS1v15_Decrypt(UserPrivKey_ptr, PrimeData_ptr, DataIn_ptr, DataInSize, Output_ptr, \
                                       OutputSize_ptr)                                                     \
    __CC__DX_RSA_SCHEMES_Decrypt(UserPrivKey_ptr, PrimeData_ptr, CRYS_RSA_HASH_NO_HASH_mode, DX_NULL, 0,   \
                                 CRYS_PKCS1_NO_MGF, DataIn_ptr, DataInSize, Output_ptr, OutputSize_ptr,    \
                                 CRYS_PKCS1_VER15)

#define __CC_CRYS_RSA_PKCS1v15_Sign(UserContext_ptr, UserPrivKey_ptr, hashFunc, DataIn_ptr, DataInSize, Output_ptr, \
                                    OutputSize_ptr)                                                                 \
    __CC__DX_RSA_Sign((UserContext_ptr), (UserPrivKey_ptr), (hashFunc), (CRYS_PKCS1_NO_MGF), 0, (DataIn_ptr),       \
                      (DataInSize), (Output_ptr), (OutputSize_ptr), CRYS_PKCS1_VER15)

#define __CC_CRYS_RSA_PKCS1v15_SHA1_Sign(UserContext_ptr, UserPrivKey_ptr, DataIn_ptr, Output_ptr, OutputSize_ptr) \
    __CC__DX_RSA_Sign((UserContext_ptr), (UserPrivKey_ptr), (CRYS_RSA_After_SHA1_mode), (CRYS_PKCS1_NO_MGF), 0,    \
                      (DataIn_ptr), CRYS_HASH_SHA1_DIGEST_SIZE_IN_BYTES, (Output_ptr), (OutputSize_ptr),           \
                      CRYS_PKCS1_VER15)
#define __CC_CRYS_RSA_PKCS1v15_MD5_Sign(UserContext_ptr, UserPrivKey_ptr, DataIn_ptr, Output_ptr, OutputSize_ptr) \
    __CC__DX_RSA_Sign((UserContext_ptr), (UserPrivKey_ptr), CRYS_RSA_After_MD5_mode, CRYS_PKCS1_NO_MGF, 0,        \
                      (DataIn_ptr), CRYS_HASH_MD5_DIGEST_SIZE_IN_BYTES, (Output_ptr), (OutputSize_ptr),           \
                      CRYS_PKCS1_VER15)
#define __CC_CRYS_RSA_PKCS1v15_SHA224_Sign(UserContext_ptr, UserPrivKey_ptr, DataIn_ptr, Output_ptr, OutputSize_ptr) \
    __CC__DX_RSA_Sign((UserContext_ptr), (UserPrivKey_ptr), (CRYS_RSA_After_SHA224_mode), (CRYS_PKCS1_NO_MGF), 0,    \
                      (DataIn_ptr), CRYS_HASH_SHA224_DIGEST_SIZE_IN_BYTES, (Output_ptr), (OutputSize_ptr),           \
                      CRYS_PKCS1_VER15)
#define __CC_CRYS_RSA_PKCS1v15_SHA256_Sign(UserContext_ptr, UserPrivKey_ptr, DataIn_ptr, Output_ptr, OutputSize_ptr) \
    __CC__DX_RSA_Sign((UserContext_ptr), (UserPrivKey_ptr), (CRYS_RSA_After_SHA256_mode), (CRYS_PKCS1_NO_MGF), 0,    \
                      (DataIn_ptr), CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES, (Output_ptr), (OutputSize_ptr),           \
                      CRYS_PKCS1_VER15)
#define __CC_CRYS_RSA_PKCS1v15_SHA384_Sign(UserContext_ptr, UserPrivKey_ptr, DataIn_ptr, Output_ptr, OutputSize_ptr) \
    __CC__DX_RSA_Sign((UserContext_ptr), (UserPrivKey_ptr), (CRYS_RSA_After_SHA384_mode), (CRYS_PKCS1_NO_MGF), 0,    \
                      (DataIn_ptr), CRYS_HASH_SHA384_DIGEST_SIZE_IN_BYTES, (Output_ptr), (OutputSize_ptr),           \
                      CRYS_PKCS1_VER15)
#define __CC_CRYS_RSA_PKCS1v15_SHA512_Sign(UserContext_ptr, UserPrivKey_ptr, DataIn_ptr, Output_ptr, OutputSize_ptr) \
    __CC__DX_RSA_Sign((UserContext_ptr), (UserPrivKey_ptr), (CRYS_RSA_After_SHA512_mode), (CRYS_PKCS1_NO_MGF), 0,    \
                      (DataIn_ptr), CRYS_HASH_SHA512_DIGEST_SIZE_IN_BYTES, (Output_ptr), (OutputSize_ptr),           \
                      CRYS_PKCS1_VER15)

#define __CC_CRYS_RSA_PSS_Sign(UserContext_ptr, UserPrivKey_ptr, hashFunc, MGF, SaltLen, DataIn_ptr, DataInSize,    \
                               Output_ptr, OutputSize_ptr)                                                          \
    __CC__DX_RSA_Sign(UserContext_ptr, UserPrivKey_ptr, hashFunc, MGF, SaltLen, DataIn_ptr, DataInSize, Output_ptr, \
                      OutputSize_ptr, CRYS_PKCS1_VER21)
#define __CC_CRYS_RSA_PSS_SHA1_Sign(UserContext_ptr, UserPrivKey_ptr, MGF, SaltLen, DataIn_ptr, Output_ptr, \
                                    OutputSize_ptr)                                                         \
    __CC__DX_RSA_Sign(UserContext_ptr, UserPrivKey_ptr, CRYS_RSA_After_SHA1_mode, MGF, SaltLen, DataIn_ptr, \
                      CRYS_HASH_SHA1_DIGEST_SIZE_IN_BYTES, Output_ptr, OutputSize_ptr, CRYS_PKCS1_VER21)
#define __CC_CRYS_RSA_PSS_SHA224_Sign(UserContext_ptr, UserPrivKey_ptr, MGF, SaltLen, DataIn_ptr, Output_ptr, \
                                      OutputSize_ptr)                                                         \
    __CC__DX_RSA_Sign(UserContext_ptr, UserPrivKey_ptr, CRYS_RSA_After_SHA224_mode, MGF, SaltLen, DataIn_ptr, \
                      CRYS_HASH_SHA224_DIGEST_SIZE_IN_BYTES, Output_ptr, OutputSize_ptr, CRYS_PKCS1_VER21)
#define __CC_CRYS_RSA_PSS_SHA256_Sign(UserContext_ptr, UserPrivKey_ptr, MGF, SaltLen, DataIn_ptr, Output_ptr, \
                                      OutputSize_ptr)                                                         \
    __CC__DX_RSA_Sign(UserContext_ptr, UserPrivKey_ptr, CRYS_RSA_After_SHA256_mode, MGF, SaltLen, DataIn_ptr, \
                      CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES, Output_ptr, OutputSize_ptr, CRYS_PKCS1_VER21)
#define __CC_CRYS_RSA_PSS_SHA384_Sign(UserContext_ptr, UserPrivKey_ptr, MGF, SaltLen, DataIn_ptr, Output_ptr, \
                                      OutputSize_ptr)                                                         \
    __CC__DX_RSA_Sign(UserContext_ptr, UserPrivKey_ptr, CRYS_RSA_After_SHA384_mode, MGF, SaltLen, DataIn_ptr, \
                      CRYS_HASH_SHA384_DIGEST_SIZE_IN_BYTES, Output_ptr, OutputSize_ptr, CRYS_PKCS1_VER21)
#define __CC_CRYS_RSA_PSS_SHA512_Sign(UserContext_ptr, UserPrivKey_ptr, MGF, SaltLen, DataIn_ptr, Output_ptr, \
                                      OutputSize_ptr)                                                         \
    __CC__DX_RSA_Sign(UserContext_ptr, UserPrivKey_ptr, CRYS_RSA_After_SHA512_mode, MGF, SaltLen, DataIn_ptr, \
                      CRYS_HASH_SHA512_DIGEST_SIZE_IN_BYTES, Output_ptr, OutputSize_ptr, CRYS_PKCS1_VER21)

#define __CC_CRYS_RSA_PKCS1v15_Verify(UserContext_ptr, UserPubKey_ptr, hashFunc, DataIn_ptr, DataInSize, Sig_ptr) \
    __CC__DX_RSA_Verify(UserContext_ptr, UserPubKey_ptr, hashFunc, CRYS_PKCS1_NO_MGF, 0, DataIn_ptr, DataInSize,  \
                        Sig_ptr, CRYS_PKCS1_VER15)
#define __CC_CRYS_RSA_PKCS1v15_MD5_Verify(UserContext_ptr, UserPubKey_ptr, DataIn_ptr, Sig_ptr)                     \
    __CC__DX_RSA_Verify(UserContext_ptr, UserPubKey_ptr, CRYS_RSA_After_MD5_mode, CRYS_PKCS1_NO_MGF, 0, DataIn_ptr, \
                        CRYS_HASH_MD5_DIGEST_SIZE_IN_BYTES, Sig_ptr, CRYS_PKCS1_VER15)
#define __CC_CRYS_RSA_PKCS1v15_SHA1_Verify(UserContext_ptr, UserPubKey_ptr, DataIn_ptr, Sig_ptr)                     \
    __CC__DX_RSA_Verify(UserContext_ptr, UserPubKey_ptr, CRYS_RSA_After_SHA1_mode, CRYS_PKCS1_NO_MGF, 0, DataIn_ptr, \
                        CRYS_HASH_SHA1_DIGEST_SIZE_IN_BYTES, Sig_ptr, CRYS_PKCS1_VER15)
#define __CC_CRYS_RSA_PKCS1v15_SHA224_Verify(UserContext_ptr, UserPubKey_ptr, DataIn_ptr, Sig_ptr)                     \
    __CC__DX_RSA_Verify(UserContext_ptr, UserPubKey_ptr, CRYS_RSA_After_SHA224_mode, CRYS_PKCS1_NO_MGF, 0, DataIn_ptr, \
                        CRYS_HASH_SHA224_DIGEST_SIZE_IN_BYTES, Sig_ptr, CRYS_PKCS1_VER15)
#define __CC_CRYS_RSA_PKCS1v15_SHA256_Verify(UserContext_ptr, UserPubKey_ptr, DataIn_ptr, Sig_ptr)                     \
    __CC__DX_RSA_Verify(UserContext_ptr, UserPubKey_ptr, CRYS_RSA_After_SHA256_mode, CRYS_PKCS1_NO_MGF, 0, DataIn_ptr, \
                        CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES, Sig_ptr, CRYS_PKCS1_VER15)
#define __CC_CRYS_RSA_PKCS1v15_SHA384_Verify(UserContext_ptr, UserPubKey_ptr, DataIn_ptr, Sig_ptr)                     \
    __CC__DX_RSA_Verify(UserContext_ptr, UserPubKey_ptr, CRYS_RSA_After_SHA384_mode, CRYS_PKCS1_NO_MGF, 0, DataIn_ptr, \
                        CRYS_HASH_SHA384_DIGEST_SIZE_IN_BYTES, Sig_ptr, CRYS_PKCS1_VER15)
#define __CC_CRYS_RSA_PKCS1v15_SHA512_Verify(UserContext_ptr, UserPubKey_ptr, DataIn_ptr, Sig_ptr)                     \
    __CC__DX_RSA_Verify(UserContext_ptr, UserPubKey_ptr, CRYS_RSA_After_SHA512_mode, CRYS_PKCS1_NO_MGF, 0, DataIn_ptr, \
                        CRYS_HASH_SHA512_DIGEST_SIZE_IN_BYTES, Sig_ptr, CRYS_PKCS1_VER15)

#define __CC_CRYS_RSA_PSS_Verify(UserContext_ptr, UserPubKey_ptr, hashFunc, MGF, SaltLen, DataIn_ptr, DataInSize, \
                                 Sig_ptr)                                                                         \
    __CC__DX_RSA_Verify(UserContext_ptr, UserPubKey_ptr, hashFunc, MGF, SaltLen, DataIn_ptr, DataInSize, Sig_ptr, \
                        CRYS_PKCS1_VER21)
#define __CC_CRYS_RSA_PSS_SHA1_Verify(UserContext_ptr, UserPubKey_ptr, MGF, SaltLen, DataIn_ptr, Sig_ptr)    \
    __CC__DX_RSA_Verify(UserContext_ptr, UserPubKey_ptr, CRYS_RSA_After_SHA1_mode, MGF, SaltLen, DataIn_ptr, \
                        CRYS_HASH_SHA1_DIGEST_SIZE_IN_BYTES, Sig_ptr, CRYS_PKCS1_VER21)
#define __CC_CRYS_RSA_PSS_SHA224_Verify(UserContext_ptr, UserPubKey_ptr, MGF, SaltLen, DataIn_ptr, Sig_ptr)    \
    __CC__DX_RSA_Verify(UserContext_ptr, UserPubKey_ptr, CRYS_RSA_After_SHA224_mode, MGF, SaltLen, DataIn_ptr, \
                        CRYS_HASH_SHA224_DIGEST_SIZE_IN_BYTES, Sig_ptr, CRYS_PKCS1_VER21)
#define __CC_CRYS_RSA_PSS_SHA256_Verify(UserContext_ptr, UserPubKey_ptr, MGF, SaltLen, DataIn_ptr, Sig_ptr)    \
    __CC__DX_RSA_Verify(UserContext_ptr, UserPubKey_ptr, CRYS_RSA_After_SHA256_mode, MGF, SaltLen, DataIn_ptr, \
                        CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES, Sig_ptr, CRYS_PKCS1_VER21)
#define __CC_CRYS_RSA_PSS_SHA384_Verify(UserContext_ptr, UserPubKey_ptr, MGF, SaltLen, DataIn_ptr, Sig_ptr)    \
    __CC__DX_RSA_Verify(UserContext_ptr, UserPubKey_ptr, CRYS_RSA_After_SHA384_mode, MGF, SaltLen, DataIn_ptr, \
                        CRYS_HASH_SHA384_DIGEST_SIZE_IN_BYTES, Sig_ptr, CRYS_PKCS1_VER21)
#define __CC_CRYS_RSA_PSS_SHA512_Verify(UserContext_ptr, UserPubKey_ptr, MGF, SaltLen, DataIn_ptr, Sig_ptr)    \
    __CC__DX_RSA_Verify(UserContext_ptr, UserPubKey_ptr, CRYS_RSA_After_SHA512_mode, MGF, SaltLen, DataIn_ptr, \
                        CRYS_HASH_SHA512_DIGEST_SIZE_IN_BYTES, Sig_ptr, CRYS_PKCS1_VER21)
#endif

#endif /* DX_CCMGR_OPS_EXT_H */
