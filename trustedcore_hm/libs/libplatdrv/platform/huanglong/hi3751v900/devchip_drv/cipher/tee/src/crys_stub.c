/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: stub
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "crys_aes.h"
#include "dx_pal_types.h"
#include "crys_aes.h"
#include "crys_des.h"
#include "crys_hash.h"
#include "crys_hmac.h"
#include "crys_aes_error.h"
#include "crys_rsa_error.h"

#include "crys_aesccm.h"
#include "crys_dh.h"
#include "crys_ecpki_build.h"
#include "crys_ecpki_dh.h"
#include "crys_ecpki_ecdsa.h"
#include "crys_ecpki_elgamal.h"
#include "crys_ecpki_kg.h"
#include "crys_ecpki_types.h"
#include "dx_util_oem_asset.h"

unsigned int DX_CclibInit()
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CRYSError_t CRYS_AESCCM_Init(
        CRYS_AESCCM_UserContext_t *ContextID_ptr,
        CRYS_AES_EncryptMode_t EncrDecrMode,
        CRYS_AESCCM_Key_t CCM_Key,
        CRYS_AESCCM_KeySize_t KeySizeId,
        DxUint32_t AdataSize,
        DxUint32_t TextSize,
        DxUint8_t *N_ptr,
        DxUint8_t SizeOfN,
        DxUint8_t SizeOfT)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CRYSError_t CRYS_AESCCM_BlockAdata(
        CRYS_AESCCM_UserContext_t *ContextID_ptr,
        DxUint8_t *DataIn_ptr,
        DxUint32_t DataInSize)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CRYSError_t CRYS_AESCCM_BlockTextData(
        CRYS_AESCCM_UserContext_t *ContextID_ptr,
        DxUint8_t *DataIn_ptr,
        DxUint32_t DataInSize,
        DxUint8_t *DataOut_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}


CEXPORT_C CRYSError_t CRYS_AESCCM_Finish(
        CRYS_AESCCM_UserContext_t *ContextID_ptr,
        DxUint8_t *DataIn_ptr,
        DxUint32_t DataInSize,
        DxUint8_t *DataOut_ptr,
        CRYS_AESCCM_Mac_Res_t MacRes,
        DxUint8_t *SizeOfT)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}


CIMPORT_C CRYSError_t  CRYS_AESCCM(
        CRYS_AES_EncryptMode_t       EncrDecrMode,   /* CCM encrypt-decrypt mode */
        CRYS_AESCCM_Key_t            CCM_Key,        /* AES-CCM key */
        CRYS_AESCCM_KeySize_t        KeySizeId,      /* Key size ID */
        DxUint8_t                   *N_ptr,          /* Nonce */
        DxUint8_t                    SizeOfN,        /* size of N buffer */
        DxUint8_t                   *ADataIn_ptr,    /* input data pointer */
        DxUint32_t                   ADataInSize,    /* input data size */
        DxUint8_t                   *TextDataIn_ptr, /* input data pointer */
        DxUint32_t                   TextDataInSize, /* input data size */
        DxUint8_t                   *TextDataOut_ptr, /* output data pointer */
        DxUint8_t                    SizeOfT,    /* size of CCM-MAC (T) */
        CRYS_AESCCM_Mac_Res_t    Mac_Res)

{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t _DX_DH_GeneratePubPrv(
        DxUint8_t *Generator_ptr,              /* generator */
        DxUint16_t GeneratorSize,
        DxUint8_t *Prime_ptr,                  /* modulus */
        DxUint16_t PrimeSize,
        DxUint16_t L,         /* Exact length of Private key in bits */
        DxUint8_t *Q_ptr,                      /* order */
        DxUint16_t QSize,
        CRYS_DH_OpMode_t DH_mode,
        CRYS_DHUserPubKey_t *tmpPubKey_ptr,    /* temp buff */
        CRYS_DHPrimeData_t  *tmpPrimeData_ptr, /* temp buff */
        DxUint8_t *ClientPrvKey_ptr,           /* out */
        DxUint16_t *ClientPrvKeySize_ptr,      /* in/out */
        DxUint8_t *ClientPub1_ptr,             /* out */
        DxUint16_t *ClientPubSize_ptr)        /* in/out */
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_DH_X942_HybridGetSecretData(
        DxUint8_t            *ClientPrvKey_ptr1,
        DxUint16_t            ClientPrvKeySize1,
        DxUint8_t            *ClientPrvKey_ptr2,
        DxUint16_t            ClientPrvKeySize2,
        DxUint8_t            *ServerPubKey_ptr1,
        DxUint16_t            ServerPubKeySize1,
        DxUint8_t            *ServerPubKey_ptr2,
        DxUint16_t            ServerPubKeySize2,
        DxUint8_t            *Prime_ptr,
        DxUint16_t            PrimeSize,
        CRYS_DH_OtherInfo_t  *otherInfo_ptr,
        CRYS_DH_HASH_OpMode_t hashMode,
        CRYS_DH_DerivationFunc_Mode DerivFunc_mode,
        CRYS_DH_HybrTemp_t   *tmpDhHybr_ptr,
        DxUint8_t            *SecretKeyingData_ptr,
        DxUint16_t            SecretKeyingDataSize)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_DH_GetSecretKey(
        DxUint8_t *ClientPrvKey_ptr,
        DxUint16_t ClientPrvKeySize,
        DxUint8_t *ServerPubKey_ptr,
        DxUint16_t ServerPubKeySize,
        DxUint8_t *Prime_ptr,
        DxUint16_t PrimeSize,
        CRYS_DHUserPubKey_t *tmpPubKey_ptr,
        CRYS_DHPrimeData_t  *tmpPrimeData_ptr,
        DxUint8_t *SecretKey_ptr,
        DxUint16_t *SecretKeySize_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_DH_X942_GetSecretData(
        DxUint8_t                  *ClientPrvKey_ptr,
        DxUint16_t                  ClientPrvKeySize,
        DxUint8_t                  *ServerPubKey_ptr,
        DxUint16_t                  ServerPubKeySize,
        DxUint8_t                  *Prime_ptr,
        DxUint16_t                  PrimeSize,
        CRYS_DH_OtherInfo_t        *otherInfo_ptr,
        CRYS_DH_HASH_OpMode_t       hashMode,
        CRYS_DH_DerivationFunc_Mode DerivFunc_mode,
        CRYS_DH_Temp_t             *tmpBuff_ptr,
        DxUint8_t                  *SecretKeyingData_ptr,
        DxUint16_t                  SecretKeyingDataSize)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

DxUTILError_t DX_UTIL_OemAssetUnpack(
        DX_UTIL_OemKey_t     pOemKey,
        DxUint32_t           assetId,
        DxUint8_t            *pAssetPackage,
        DxUint32_t           assetPackageLen,
        DxUint8_t            *pAssetData,
        DxUint32_t           *pAssetDataLen,
        DxUint32_t           *pUserData)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_ECDH_SVDP_DH(
        CRYS_ECPKI_UserPublKey_t *PartnerPublKey_ptr, /* in */
        CRYS_ECPKI_UserPrivKey_t *UserPrivKey_ptr,           /* in */
        DxUint8_t                 *SharedSecretValue_ptr,     /* out */
        DxUint32_t               *SharedSecrValSize_ptr,     /* in/out */
        CRYS_ECDH_TempData_t     *TempBuff_ptr               /* in */)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}
#if 0
CIMPORT_C CRYSError_t _DX_ECPKI_BuildPublKey(
        CRYS_ECPKI_DomainID_t        DomainID,             /* in */
        DxUint8_t               *PublKeyIn_ptr,         /* in */
        DxUint32_t                    PublKeySizeInBytes,  /* in */
        EC_PublKeyCheckMode_t        CheckMode,             /* in */
        CRYS_ECPKI_UserPublKey_t    *UserPublKey_ptr,     /* out */
        CRYS_ECPKI_BUILD_TempData_t *TempBuff_ptr         /* in */)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_ECPKI_ExportPublKey(
        CRYS_ECPKI_UserPublKey_t      *UserPublKey_ptr,       /* in */
        CRYS_ECPKI_PointCompression_t  Compression,           /* in */
        DxUint8_t              *ExternPublKey_ptr,     /* in */
        DxUint32_t                    *PublKeySizeInBytes_ptr /* in/out */)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}


CIMPORT_C CRYSError_t CRYS_ECPKI_BuildPrivKey(
        CRYS_ECPKI_DomainID_t      DomainID,          /* in */
        DxUint8_t          *PrivKeyIn_ptr,     /* in */
        DxUint32_t                 PrivKeySizeInBytes, /* in */
        CRYS_ECPKI_UserPrivKey_t  *UserPrivKey_ptr    /* out */)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_ECPKI_GenKeyPair(
        CRYS_ECPKI_DomainID_t        DomainID,            /* in */
        CRYS_ECPKI_UserPrivKey_t   *UserPrivKey_ptr,    /* out */
        CRYS_ECPKI_UserPublKey_t   *UserPublKey_ptr,    /* out */
        CRYS_ECPKI_KG_TempData_t   *TempData_ptr        /* in */)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_ECDSA_VerifyInit(
        CRYS_ECDSA_VerifyUserContext_t  *VerifyUserContext_ptr, /* in/out */
        CRYS_ECPKI_UserPublKey_t        *SignerPublKey_ptr,     /* in */
        CRYS_ECPKI_HASH_OpMode_t        HashMode               /* in */)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_ECDSA_VerifyUpdate(
        CRYS_ECDSA_VerifyUserContext_t *VerifyUserContext_ptr, /* in/out */
        DxUint8_t                      *MessageDataIn_ptr,     /* in */
        DxUint32_t                      DataInSize             /* in */)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_ECDSA_VerifyFinish(
        CRYS_ECDSA_VerifyUserContext_t *VerifyUserContext_ptr, /* in */
        DxUint8_t                      *SignatureIn_ptr,       /* in */
        DxUint32_t                      SignatureSizeBytes    /* in */)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}


CIMPORT_C CRYSError_t CRYS_ECDSA_Verify (
        CRYS_ECDSA_VerifyUserContext_t *VerifyUserContext_ptr, /* in/out */
        CRYS_ECPKI_UserPublKey_t       *UserPublKey_ptr,        /* in */
        CRYS_ECPKI_HASH_OpMode_t        HashMode,               /* in */
        DxUint8_t                      *SignatureIn_ptr,        /* in */
        DxUint32_t                      SignatureSizeBytes,     /* in */
        DxUint8_t                      *MessageDataIn_ptr,      /* in */
        DxUint32_t                      MessageSizeInBytes      /* in */)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_ECDSA_Sign(
        CRYS_ECDSA_SignUserContext_t  *SignUserContext_ptr,     /* in/out */
        CRYS_ECPKI_UserPrivKey_t      *SignerPrivKey_ptr,       /* in */
        CRYS_ECPKI_HASH_OpMode_t       HashMode,                /* in */
        DxUint8_t                     *MessageDataIn_ptr,       /* in */
        DxUint32_t                     MessageSizeInBytes,      /* in */
        DxUint8_t                     *SignatureOut_ptr,        /* out */
        DxUint32_t                    *SignatureOutSize_ptr     /* in */)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_ECDSA_SignInit(
        CRYS_ECDSA_SignUserContext_t  *SignUserContext_ptr, /* in/out */
        CRYS_ECPKI_UserPrivKey_t      *SignerPrivKey_ptr,   /* in */
        CRYS_ECPKI_HASH_OpMode_t       HashMode             /* in */)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_ECDSA_SignUpdate(
        CRYS_ECDSA_SignUserContext_t  *SignUserContext_ptr,  /* in/out */
        DxUint8_t                     *MessageDataIn_ptr,    /* in */
        DxUint32_t                    DataInSize            /* in */)

{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C  CRYSError_t _DX_ECDSA_SignFinish(
        CRYS_ECDSA_SignUserContext_t *SignUserContext_ptr, /* in */
        uint8_t                      *SignatureOut_ptr,    /* out */
        uint32_t                     *SignatureOutSize_ptr, /* in/out */
        int8_t                       IsEphemerKeyInternal, /* in */
        uint32_t                     *EphemerKeyData_ptr   /* in */)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_RSA_Get_PubKey(
        CRYS_RSAUserPubKey_t *UserPubKey_ptr,
        uint8_t  *Exponent_ptr,
        uint16_t *ExponentSize_ptr,
        uint8_t  *Modulus_ptr,
        uint16_t *ModulusSize_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}


CIMPORT_C CRYSError_t _DX_RSA_Sign(
        CRYS_RSAPrivUserContext_t *UserContext_ptr,
        CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
        CRYS_RSA_HASH_OpMode_t rsaHashMode,
        CRYS_PKCS1_MGF_t MGF,
        uint16_t     SaltLen,
        uint8_t     *DataIn_ptr,
        uint32_t     DataInSize,
        uint8_t     *Output_ptr,
        uint16_t    *OutputSize_ptr,
        CRYS_PKCS1_version PKCS1_ver)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CEXPORT_C CRYSError_t _DX_RSA_Verify(
        CRYS_RSAPubUserContext_t *UserContext_ptr,
        CRYS_RSAUserPubKey_t *UserPubKey_ptr,
        CRYS_RSA_HASH_OpMode_t hashFunc,
        CRYS_PKCS1_MGF_t MGF,
        DxUint16_t SaltLen,
        DxUint8_t     *DataIn_ptr,
        DxUint32_t     DataInSize,
        DxUint8_t     *Sig_ptr,
        CRYS_PKCS1_version PKCS1_ver)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t _DX_RSA_SCHEMES_Decrypt(
        CRYS_RSAUserPrivKey_t  *UserPrivKey_ptr,
        CRYS_RSAPrimeData_t    *PrimeData_ptr,
        CRYS_RSA_HASH_OpMode_t  hashFunc,
        uint8_t              *L,
        uint16_t              Llen,
        CRYS_PKCS1_MGF_t        MGF,
        uint8_t              *DataIn_ptr,
        uint16_t              DataInSize,
        uint8_t              *Output_ptr,
        uint16_t             *OutputSize_ptr,
        CRYS_PKCS1_version      PKCS1_ver)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CEXPORT_C CRYSError_t _DX_RSA_SCHEMES_Encrypt(
        CRYS_RSAUserPubKey_t *UserPubKey_ptr,
        CRYS_RSAPrimeData_t  *PrimeData_ptr,
        CRYS_RSA_HASH_OpMode_t hashFunc,
        DxUint8_t            *L,
        DxUint16_t           Llen,
        CRYS_PKCS1_MGF_t   MGF,
        DxUint8_t           *DataIn_ptr,
        DxUint16_t           DataInSize,
        DxUint8_t            *Output_ptr,
        CRYS_PKCS1_version PKCS1_ver)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_HASH_Init(
        CRYS_HASHUserContext_t     *ContextID_ptr,
        CRYS_HASH_OperationMode_t  OperationMode)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_HASH_Update(
        CRYS_HASHUserContext_t  *ContextID_ptr,
        uint8_t                 *DataIn_ptr,
        uint32_t                 DataInSize)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_HASH_Finish(
        CRYS_HASHUserContext_t  *ContextID_ptr,
        CRYS_HASH_Result_t       HashResultBuff)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t  CRYS_HASH_Free(CRYS_HASHUserContext_t  *ContextID_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_HASH  (
        CRYS_HASH_OperationMode_t  OperationMode,
        uint8_t                   *DataIn_ptr,
        uint32_t                   DataSize,
        CRYS_HASH_Result_t         HashResultBuff)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_HMAC_Init(
        CRYS_HMACUserContext_t     *ContextID_ptr,
        CRYS_HASH_OperationMode_t  OperationMode,
        uint8_t                    *key_ptr,
        uint16_t                    keySize)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_HMAC_Update(
        CRYS_HMACUserContext_t  *ContextID_ptr,
        uint8_t                 *DataIn_ptr,
        uint32_t                 DataInSize)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_HMAC_Finish(
        CRYS_HMACUserContext_t  *ContextID_ptr,
        CRYS_HASH_Result_t       HmacResultBuff)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t  CRYS_HMAC_Free(CRYS_HMACUserContext_t  *ContextID_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_HMAC  (
        CRYS_HASH_OperationMode_t  OperationMode,
        uint8_t                    *key_ptr,
        uint16_t                    keySize,
        uint8_t                    *DataIn_ptr,
        uint32_t                    DataSize,
        CRYS_HASH_Result_t          HmacResultBuff)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_RND_GenerateVector(
        uint16_t   outSizeBytes, /* in */
        uint8_t   *out_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}
#endif

CIMPORT_C  CRYSError_t CRYS_AES_SetIv(
        CRYS_AESUserContext_t   *ContextID_ptr,
        uint8_t               *iv_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

#if 0
CIMPORT_C CRYSError_t  CRYS_AES_Init(
        CRYS_AESUserContext_t    *ContextID_ptr,
        CRYS_AES_IvCounter_t     IVCounter_ptr,
        CRYS_AES_Key_t           Key_ptr,
        CRYS_AES_KeySize_t       KeySizeID,
        CRYS_AES_EncryptMode_t   EncryptDecryptFlag,
        CRYS_AES_OperationMode_t OperationMode)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t  CRYS_AES_Block(
        CRYS_AESUserContext_t   *ContextID_ptr,
        uint8_t               *DataIn_ptr,
        uint32_t               DataInSize,
        uint8_t               *DataOut_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t  CRYS_AES_Finish(
        CRYS_AESUserContext_t   *ContextID_ptr,
        uint8_t               *DataIn_ptr,
        uint32_t               DataInSize,
        uint8_t               *DataOut_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t  CRYS_AES(
        CRYS_AES_IvCounter_t       IVCounter_ptr,
        CRYS_AES_Key_t             Key_ptr,
        CRYS_AES_KeySize_t         KeySize,
        CRYS_AES_EncryptMode_t     EncryptDecryptFlag,
        CRYS_AES_OperationMode_t   OperationMode,
        uint8_t                    *DataIn_ptr,
        uint32_t                   DataInSize,
        uint8_t                    *DataOut_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t  CRYS_KDF_KeyDerivFunc(
        uint8_t                *ZZSecret_ptr,
        uint32_t                ZZSecretSize,
        CRYS_KDF_OtherInfo_t     *OtherInfo_ptr,
        CRYS_KDF_HASH_OpMode_t    KDFhashMode,
        CRYS_KDF_DerivFuncMode_t  derivation_mode,
        uint8_t                *KeyingData_ptr,
        uint32_t                KeyingDataSizeBytes)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

DxUTILError_t DX_UTIL_CmacDeriveKey(
        DX_UTIL_KeyType_t        aesKeyType,
        uint8_t            *pDataIn,
        uint32_t        dataInSize,
        DX_UTIL_AES_CmacResult_t    pCmacResult)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_RSA_KG_GenerateKeyPair(
        uint8_t             *pubExp_ptr,
        uint16_t             pubExpSizeInBytes,
        uint32_t             keySize,
        CRYS_RSAUserPrivKey_t *userPrivKey_ptr,
        CRYS_RSAUserPubKey_t  *userPubKey_ptr,
        CRYS_RSAKGData_t      *keyGenData_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_RSA_Build_PrivKeyCRT(
        CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
        uint8_t *P_ptr,
        uint16_t PSize,
        uint8_t *Q_ptr,
        uint16_t QSize,
        uint8_t *dP_ptr,
        uint16_t dPSize,
        uint8_t *dQ_ptr,
        uint16_t dQSize,
        uint8_t *qInv_ptr,
        uint16_t qInvSize)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_RSA_Build_PubKey(
        CRYS_RSAUserPubKey_t *UserPubKey_ptr,
        uint8_t *Exponent_ptr,
        uint16_t ExponentSize,
        uint8_t *Modulus_ptr,
        uint16_t ModulusSize)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_RSA_Build_PrivKey(
        CRYS_RSAUserPrivKey_t   *UserPrivKey_ptr,
        uint8_t               *PrivExponent_ptr,
        uint16_t               PrivExponentSize,
        uint8_t               *PubExponent_ptr,
        uint16_t               PubExponentSize,
        uint8_t               *Modulus_ptr,
        uint16_t               ModulusSize)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}


CIMPORT_C CRYSError_t CRYS_RSA_KG_GenerateKeyPairCRT(
        uint8_t             *pubExp_ptr,
        uint16_t             pubExpSizeInBytes,
        uint32_t             keySize,
        CRYS_RSAUserPrivKey_t *userPrivKey_ptr,
        CRYS_RSAUserPubKey_t  *userPubKey_ptr,
        CRYS_RSAKGData_t      *keyGenData_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_RSA_PRIM_Decrypt(
        CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
        CRYS_RSAPrimeData_t   *PrimeData_ptr,
        uint8_t     *Data_ptr,
        uint16_t     DataSize,
        uint8_t     *Output_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t CRYS_RSA_PRIM_Encrypt(
        CRYS_RSAUserPubKey_t *UserPubKey_ptr,
        CRYS_RSAPrimeData_t  *PrimeData_ptr,
        uint8_t              *Data_ptr,
        uint16_t              DataSize,
        uint8_t              *Output_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}
#endif

CIMPORT_C CRYSError_t  CRYS_DES_Free(CRYS_DESUserContext_t  *ContextID_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t  CRYS_DES(
        CRYS_DES_Iv_t             IV_ptr,                 /* in */
        CRYS_DES_Key_t           *Key_ptr,                /* in */
        CRYS_DES_NumOfKeys_t      NumOfKeys,              /* in */
        CRYS_DES_EncryptMode_t    EncryptDecryptFlag,     /* in */
        CRYS_DES_OperationMode_t  OperationMode,          /* in */
        uint8_t                *DataIn_ptr,             /* in */
        uint32_t                DataInSize,             /* in */
        uint8_t                *DataOut_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t  CRYS_DES_Init(
        CRYS_DESUserContext_t    *ContextID_ptr,
        CRYS_DES_Iv_t            IV_ptr,
        CRYS_DES_Key_t           *Key_ptr,
        CRYS_DES_NumOfKeys_t     NumOfKeys,
        CRYS_DES_EncryptMode_t   EncryptDecryptFlag,
        CRYS_DES_OperationMode_t OperationMode)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}

CIMPORT_C CRYSError_t  CRYS_DES_Block(
        CRYS_DESUserContext_t       *ContextID_ptr, /* in */
        uint8_t                     *DataIn_ptr,    /* in */
        uint32_t                    DataInSize,     /* in */
        uint8_t                     *DataOut_ptr)
{
    /* not support */
    return CRYS_FATAL_ERROR;
}
