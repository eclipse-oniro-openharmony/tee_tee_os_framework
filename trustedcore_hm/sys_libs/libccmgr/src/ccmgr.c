/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: cc manager implementation
 * Create: 2018-05-18
 */

#include "ccmgr.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/usrsyscall_ext.h>
#include <crypto_syscal_types.h>
#include "sre_syscalls_id.h"
#include "tee_defines.h"
#include "hmdrv.h"
#include "ccmgr_ops.h"
#include "ccmgr_ops_ext.h"

#ifdef SUPPORT_M_CC
#include <tem_sasi.h>
#endif

int hm_ccmgr_init(void)
{
    return hm_drv_init("platdrv");
}
#define hmccmgr_call_ex(...) hm_drv_call_ex(__VA_ARGS__)
#define hmccmgr_call(...)    hm_drv_call(__VA_ARGS__)

#define AES_IV_LEN           16
#define EPS_SUPPORT          1
#define AES_DATA_MAX_SIZE    512
#define AES_DATA_SIZE_DOUBLE 2

#ifdef DX_ENABLE

CRYSError_t __CC_DX_power_on()
{
    return hmccmgr_call(SW_SYSCALL_CC_SECS_POWER_ON, NULL, 0);
}

CRYSError_t __CC_DX_power_down()
{
    return hmccmgr_call(SW_SYSCALL_CC_SECS_POWER_DOWN, NULL, 0);
}

CRYSError_t __CC_CRYS_HMAC_Init(CRYS_HMACUserContext_t *context_id_ptr, CRYS_HASH_OperationMode_t operation_mode,
                                DxUint8_t *key_ptr, DxUint16_t key_size)
{
    uint64_t args[] = {
        (uint64_t)((uintptr_t)context_id_ptr),
        (uint64_t)operation_mode,
        (uint64_t)(uintptr_t)key_ptr,
        (uint64_t)key_size
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_HMAC_INIT, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_HMAC_Update(CRYS_HMACUserContext_t *context_id_ptr,
                                  DxUint8_t *data_in_ptr, DxUint32_t data_in_size)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context_id_ptr,
        (uint64_t)(uintptr_t)data_in_ptr,
        (uint64_t)data_in_size
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_HMAC_UPDATE, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_HMAC_Finish(CRYS_HMACUserContext_t *context_id_ptr, CRYS_HASH_Result_t hmac_result_buff)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context_id_ptr,
        (uint64_t)(uintptr_t)hmac_result_buff
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_HMAC_FINISH, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_HMAC_Free(CRYS_HMACUserContext_t *context_id_ptr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context_id_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_HMAC_FREE, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_HMAC(CRYS_HASH_OperationMode_t operation_mode, DxUint8_t *key_ptr, DxUint16_t key_size,
                           DxUint8_t *data_in_ptr, DxUint32_t data_size, CRYS_HASH_Result_t hmac_result_buff)
{
    uint64_t args[] = {
        (uint64_t)operation_mode, (uint64_t)(uintptr_t)key_ptr,
        (uint64_t)key_size,       (uint64_t)(uintptr_t)data_in_ptr,
        (uint64_t)data_size,      (uint64_t)(uintptr_t)hmac_result_buff
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_HMAC, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_KDF_KeyDerivFunc(DxUint8_t *secret_ptr, DxUint32_t secret_size,
                                       CRYS_KDF_OtherInfo_t *other_info_ptr, CRYS_KDF_HASH_OpMode_t kdf_hash_mode,
                                       CRYS_KDF_DerivFuncMode_t derivation_mode, DxUint8_t *keying_data_ptr,
                                       DxUint32_t keying_data_size_bytes)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)secret_ptr,
        (uint64_t)secret_size,
        (uint64_t)(uintptr_t)other_info_ptr,
        (uint64_t)kdf_hash_mode,
        (uint64_t)derivation_mode,
        (uint64_t)(uintptr_t)keying_data_ptr,
        (uint64_t)keying_data_size_bytes
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_KDF_KEYDERIVFUNC, args, ARRAY_SIZE(args));
}

CRYSError_t __CC__DX_RSA_SCHEMES_Encrypt(CRYS_RSAUserPubKey_t *user_pubkey_ptr, CRYS_RSAPrimeData_t *prime_data_ptr,
                                         CRYS_RSA_HASH_OpMode_t hash_func, DxUint8_t *l_ptr, DxUint16_t l_len,
                                         CRYS_PKCS1_MGF_t mgf, DxUint8_t *data_in_ptr, DxUint16_t data_in_size,
                                         DxUint8_t *output_ptr, CRYS_PKCS1_version pkcs1_ver)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)user_pubkey_ptr,
        (uint64_t)(uintptr_t)prime_data_ptr,
        (uint64_t)hash_func,
        (uint64_t)(uintptr_t)l_ptr,
        (uint64_t)l_len,
        (uint64_t)mgf,
        (uint64_t)(uintptr_t)data_in_ptr,
        (uint64_t)data_in_size,
        (uint64_t)(uintptr_t)output_ptr,
        (uint64_t)pkcs1_ver
    };
    return hmccmgr_call(SW_SYSCALL_CC__DX_RSA_SCHEMES_ENCRYPT, args, ARRAY_SIZE(args));
}

struct decrypt_wraper {
    uint32_t hash_func;
    uint32_t l_len;
    uint32_t mgf;
    uint32_t data_in_size;
    uint32_t pkcs1_ver;
};

CRYSError_t __CC__DX_RSA_SCHEMES_Decrypt(CRYS_RSAUserPrivKey_t *user_priv_key_ptr, CRYS_RSAPrimeData_t *prime_data_ptr,
                                         CRYS_RSA_HASH_OpMode_t hash_func, DxUint8_t *l_ptr, DxUint16_t l_len,
                                         CRYS_PKCS1_MGF_t mgf, DxUint8_t *data_in_ptr, DxUint16_t data_in_size,
                                         DxUint8_t *output_ptr, DxUint16_t *output_size_ptr,
                                         CRYS_PKCS1_version pkcs1_ver)
{
    struct decrypt_wraper param_wraper;
    param_wraper.hash_func            = (uint32_t)hash_func;
    param_wraper.l_len                = (uint32_t)l_len;
    param_wraper.mgf                  = (uint32_t)mgf;
    param_wraper.data_in_size         = (uint32_t)data_in_size;
    param_wraper.pkcs1_ver            = (uint32_t)pkcs1_ver;
    struct decrypt_wraper *param_wraper_ptr = &param_wraper;
    uint64_t args[] = {
        (uint64_t)(uintptr_t)user_priv_key_ptr,
        (uint64_t)(uintptr_t)prime_data_ptr,
        (uint64_t)(uintptr_t)l_ptr,
        (uint64_t)(uintptr_t)data_in_ptr,
        (uint64_t)(uintptr_t)output_ptr,
        (uint64_t)(uintptr_t)output_size_ptr,
        (uint64_t)(uintptr_t)param_wraper_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC__DX_RSA_SCHEMES_DECRYPT, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_RSA_PRIM_Encrypt(CRYS_RSAUserPubKey_t *user_pub_key_ptr, CRYS_RSAPrimeData_t *prime_data_ptr,
                                       DxUint8_t *data_ptr, DxUint16_t data_size, DxUint8_t *output_ptr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)user_pub_key_ptr,
        (uint64_t)(uintptr_t)prime_data_ptr,
        (uint64_t)(uintptr_t)data_ptr,
        (uint64_t)data_size, (uint64_t)(uintptr_t)output_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_RSA_PRIM_ENCRYPT, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_RSA_PRIM_Decrypt(CRYS_RSAUserPrivKey_t *user_priv_key_ptr, CRYS_RSAPrimeData_t *prime_data_ptr,
                                       DxUint8_t *data_ptr, DxUint16_t data_size, DxUint8_t *output_ptr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)user_priv_key_ptr,
        (uint64_t)(uintptr_t)prime_data_ptr,
        (uint64_t)(uintptr_t)data_ptr,
        (uint64_t)data_size, (uint64_t)(uintptr_t)output_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_RSA_PRIM_DECRYPT, args, ARRAY_SIZE(args));
}

CRYSError_t __CC__DX_RSA_Sign(CRYS_RSAPrivUserContext_t *user_context_ptr, CRYS_RSAUserPrivKey_t *user_privkey_ptr,
                              CRYS_RSA_HASH_OpMode_t hash_func, CRYS_PKCS1_MGF_t mgf, DxUint16_t salt_len,
                              DxUint8_t *data_in_ptr, DxUint32_t data_in_size, DxUint8_t *output_ptr,
                              DxUint16_t *output_size_ptr, CRYS_PKCS1_version pkcs1_ver)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)user_context_ptr,
        (uint64_t)(uintptr_t)user_privkey_ptr,
        (uint64_t)hash_func,
        (uint64_t)mgf,
        (uint64_t)salt_len,
        (uint64_t)(uintptr_t)data_in_ptr,
        (uint64_t)data_in_size,
        (uint64_t)(uintptr_t)output_ptr,
        (uint64_t)(uintptr_t)output_size_ptr,
        (uint64_t)pkcs1_ver
    };
    return hmccmgr_call(SW_SYSCALL_CC__DX_RSA_SIGN, args, ARRAY_SIZE(args));
}

CRYSError_t __CC__DX_RSA_Verify(CRYS_RSAPubUserContext_t *user_context_ptr, CRYS_RSAUserPubKey_t *user_pubkey_ptr,
                                CRYS_RSA_HASH_OpMode_t hash_func, CRYS_PKCS1_MGF_t mgf, DxUint16_t salt_len,
                                DxUint8_t *data_in_ptr, DxUint32_t data_in_size, DxUint8_t *sig_ptr,
                                CRYS_PKCS1_version pkcs1_ver)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)user_context_ptr,
        (uint64_t)(uintptr_t)user_pubkey_ptr,
        (uint64_t)hash_func,
        (uint64_t)mgf,
        (uint64_t)salt_len,
        (uint64_t)(uintptr_t)data_in_ptr,
        (uint64_t)data_in_size,
        (uint64_t)(uintptr_t)sig_ptr,
        (uint64_t)pkcs1_ver
    };
    return hmccmgr_call(SW_SYSCALL_CC__DX_RSA_VERIFY, args, ARRAY_SIZE(args));
}

static int aes_key_size(CRYS_AES_KeySize_t key_size_id)
{
    switch (key_size_id) {
    case CRYS_AES_Key128BitSize:
        return AES_KEY_BYTES_16;
    case CRYS_AES_Key192BitSize:
        return AES_KEY_BYTES_24;
    case CRYS_AES_Key256BitSize:
        return AES_KEY_BYTES_32;
    case CRYS_AES_Key512BitSize:
        return AES_KEY_BYTES_64;
    default:
        return 0;
    }
}
CRYSError_t __CC_CRYS_AES_Init(CRYS_AESUserContext_t *context_id_ptr, CRYS_AES_IvCounter_t iv_counter_ptr,
                               CRYS_AES_Key_t key_ptr, CRYS_AES_KeySize_t key_size_id,
                               CRYS_AES_EncryptMode_t encrypt_decrypt_flag, CRYS_AES_OperationMode_t operation_mode)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context_id_ptr,
        (uint64_t)(uintptr_t)iv_counter_ptr,
        (uint64_t)(uintptr_t)key_ptr,
        (uint64_t)key_size_id,
        (uint64_t)encrypt_decrypt_flag,
        (uint64_t)operation_mode
    };
    uint32_t lens[] = {
        sizeof(CRYS_AESUserContext_t), sizeof(CRYS_AES_IvCounter_t), (uint32_t)aes_key_size(key_size_id), 0, 0, 0
    };
    return hmccmgr_call_ex(SW_SYSCALL_CC_CRYS_AES_INIT, args, lens, ARRAY_SIZE(args), context_id_ptr,
                           sizeof(CRYS_AESUserContext_t));
}

CRYSError_t __CC_CRYS_AES_Block(CRYS_AESUserContext_t *context_id_ptr, DxUint8_t *data_in_ptr, DxUint32_t data_in_size,
                                DxUint8_t *data_out_ptr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context_id_ptr,
        (uint64_t)(uintptr_t)data_in_ptr,
        (uint64_t)data_in_size, (uint64_t)(uintptr_t)data_out_ptr
    };

    if (context_id_ptr == NULL)
        return CRYS_FATAL_ERROR;

    /* data_in_size Max is 512 */
    uint32_t lens[] = { sizeof(CRYS_AESUserContext_t), data_in_size <= AES_DATA_MAX_SIZE ? data_in_size : 0, 0, 0 };
    return hmccmgr_call_ex(SW_SYSCALL_CC_CRYS_AES_BLOCK, args, lens, ARRAY_SIZE(args), context_id_ptr,
                           sizeof(CRYS_AESUserContext_t));
}

CRYSError_t __CC_CRYS_AES_Finish(CRYS_AESUserContext_t *context_id_ptr, DxUint8_t *data_in_ptr, DxUint32_t data_in_size,
                                 DxUint8_t *data_out_ptr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context_id_ptr,
        (uint64_t)(uintptr_t)data_in_ptr,
        (uint64_t)data_in_size, (uint64_t)(uintptr_t)data_out_ptr
    };

    if (context_id_ptr == NULL)
        return CRYS_FATAL_ERROR;

    /* data_in_size Max is 512 */
    uint32_t lens[] = { sizeof(CRYS_AESUserContext_t), data_in_size <= AES_DATA_MAX_SIZE ? data_in_size : 0, 0, 0 };

    /* data_out_ptr or data_in_size maybe 0 */
    if (data_in_size <= (AES_DATA_MAX_SIZE * AES_DATA_SIZE_DOUBLE) && (data_out_ptr != NULL) && data_in_size != 0)
        return hmccmgr_call_ex(SW_SYSCALL_CC_CRYS_AES_FINISH, args, lens, ARRAY_SIZE(args), data_out_ptr, data_in_size);
    else
        return hmccmgr_call_ex(SW_SYSCALL_CC_CRYS_AES_FINISH, args, lens, ARRAY_SIZE(args), NULL, 0);
}

CRYSError_t __CC_CRYS_ECDSA_Sign(CRYS_ECDSA_SignUserContext_t *sign_user_context_ptr, /* in/out */
                                 CRYS_ECPKI_UserPrivKey_t *signer_priv_key_ptr,       /* in */
                                 CRYS_ECPKI_HASH_OpMode_t hash_mode,                  /* in */
                                 DxUint8_t *message_data_in_ptr,                      /* in */
                                 DxUint32_t message_size_in_bytes,                    /* in */
                                 DxUint8_t *signature_out_ptr,                        /* out */
                                 /* in */
                                 DxUint32_t *signature_out_size_ptr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)sign_user_context_ptr,
        (uint64_t)(uintptr_t)signer_priv_key_ptr,
        (uint64_t)hash_mode,
        (uint64_t)(uintptr_t)message_data_in_ptr,
        (uint64_t)message_size_in_bytes,
        (uint64_t)(uintptr_t)signature_out_ptr,
        (uint64_t)(uintptr_t)signature_out_size_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_ECDSA_SIGN, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_ECDSA_Verify(CRYS_ECDSA_VerifyUserContext_t *verify_user_context_ptr, /* in/out */
                                   CRYS_ECPKI_UserPublKey_t *user_publ_key_ptr,             /* in */
                                   CRYS_ECPKI_HASH_OpMode_t hash_mode,                     /* in */
                                   DxUint8_t *signature_in_ptr,                            /* in */
                                   DxUint32_t signature_size_bytes,                         /* in */
                                   DxUint8_t *message_data_in_ptr,                          /* in */
                                   /* in */
                                   DxUint32_t message_size_in_bytes)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)verify_user_context_ptr, /* in/out */
        (uint64_t)(uintptr_t)user_publ_key_ptr,       /* in */
        (uint64_t)hash_mode,                          /* in */
        (uint64_t)(uintptr_t)signature_in_ptr,        /* in */
        (uint64_t)signature_size_bytes,               /* in */
        (uint64_t)(uintptr_t)message_data_in_ptr,     /* in */
        (uint64_t)message_size_in_bytes               /* in */
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_ECDSA_VERIFY, args, ARRAY_SIZE(args));
}

DxUTILError_t __DX_UTIL_OemAssetUnpack(DX_UTIL_OemKey_t p_oem_key, DxUint32_t asset_id, DxUint8_t *p_asset_package,
                                       DxUint32_t asset_package_len, DxUint8_t *p_asset_data,
                                       DxUint32_t *p_asset_data_len, DxUint32_t *p_user_data)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)p_oem_key,
        (uint64_t)asset_id,
        (uint64_t)(uintptr_t)p_asset_package,
        (uint64_t)asset_package_len,
        (uint64_t)(uintptr_t)p_asset_data,
        (uint64_t)(uintptr_t)p_asset_data_len,
        (uint64_t)(uintptr_t)p_user_data
    };
    return hmccmgr_call(SW_SYSCALL_DX_UTIL_OEMASSETUNPACK, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_ECPKI_BuildPublKey(CRYS_ECPKI_DomainID_t domain_id,           /* in */
                                         DxUint8_t *publ_key_in_ptr,                /* in */
                                         DxUint32_t publ_key_size_in,               /* in */
                                         /* in */
                                         CRYS_ECPKI_UserPublKey_t *user_publ_key_ptr)
{
    uint64_t args[] = {
        (uint64_t)domain_id,                           /* in */
        (uint64_t)(uintptr_t)publ_key_in_ptr, /* in */
        (uint64_t)publ_key_size_in,                 /* in */
        (uint64_t)(uintptr_t)user_publ_key_ptr /* in */
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_ECPKI_BUILD_PUBLKEY, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_ECPKI_ExportPublKey(CRYS_ECPKI_UserPublKey_t *user_publ_key_ptr, /* in */
                                          CRYS_ECPKI_PointCompression_t compression,   /* in */
                                          DxUint8_t *extern_publ_key_ptr,              /* in */
                                          /* in/out */
                                          DxUint32_t *publkey_size_in_ptr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)user_publ_key_ptr,   /* in */
        (uint64_t)compression,                    /* in */
        (uint64_t)(uintptr_t)extern_publ_key_ptr, /* in */
        (uint64_t)(uintptr_t)publkey_size_in_ptr  /* in/out */
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_ECPKI_EXPORTPUBLKEY, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_RSA_KG_GenerateKeyPair(DxUint8_t *pub_exp_ptr, DxUint16_t pub_exp_size_in, DxUint32_t key_size,
                                             CRYS_RSAUserPrivKey_t *user_priv_key_ptr,
                                             CRYS_RSAUserPubKey_t *user_pubkey_ptr, CRYS_RSAKGData_t *key_gen_data_ptr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)pub_exp_ptr,
        (uint64_t)pub_exp_size_in,
        (uint64_t)key_size,
        (uint64_t)(uintptr_t)user_priv_key_ptr,
        (uint64_t)(uintptr_t)user_pubkey_ptr,
        (uint64_t)(uintptr_t)key_gen_data_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_RSA_KG_GENERATEKEYPAIR, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_ECPKI_GenKeyPair(CRYS_ECPKI_DomainID_t domain_id,             /* in */
                                       CRYS_ECPKI_UserPrivKey_t *user_priv_key_ptr, /* out */
                                       CRYS_ECPKI_UserPublKey_t *user_publKey_ptr,  /* out */
                                       /* in */
                                       CRYS_ECPKI_KG_TempData_t *temp_data_ptr)
{
    uint64_t args[] = {
        (uint64_t)domain_id,                                  /* in */
        (uint64_t)(uintptr_t)user_priv_key_ptr,               /* out */
        (uint64_t)(uintptr_t)user_publKey_ptr,                /* out */
        (uint64_t)(uintptr_t)temp_data_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_ECPKI_GENKEY_PAIR, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_RSA_Build_PubKey(CRYS_RSAUserPubKey_t *user_pubkey_ptr, DxUint8_t *exponent_ptr,
                                       DxUint16_t exponent_size, DxUint8_t *modulus_ptr, DxUint16_t modulus_size)
{
    CRYSError_t ret;
    uint64_t args[] = {
        (uint64_t)(uintptr_t)user_pubkey_ptr,
        (uint64_t)(uintptr_t)exponent_ptr,
        (uint64_t)exponent_size,
        (uint64_t)(uintptr_t)modulus_ptr,
        (uint64_t)modulus_size
    };
    ret             = hmccmgr_call(SW_SYSCALL_CC_CRYS_RSA_BUILD_PUBKEY, args, ARRAY_SIZE(args));
    return ret;
}

CRYSError_t __CC_CRYS_RSA_Build_PrivKey(CRYS_RSAUserPrivKey_t *user_privkey_ptr, DxUint8_t *priv_exponent_ptr,
                                        DxUint16_t priv_exponent_size, DxUint8_t *pub_exponent_ptr,
                                        DxUint16_t pub_exponent_size, DxUint8_t *modulus_ptr, DxUint16_t modulus_size)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)user_privkey_ptr,
        (uint64_t)(uintptr_t)priv_exponent_ptr,
        (uint64_t)priv_exponent_size,
        (uint64_t)(uintptr_t)pub_exponent_ptr,
        (uint64_t)pub_exponent_size,
        (uint64_t)(uintptr_t)modulus_ptr,
        (uint64_t)modulus_size
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_RSA_BUILD_PRIVKEY, args, ARRAY_SIZE(args));
}

typedef struct {
    uint32_t p_size;
    uint32_t q_size;
    uint32_t dp_size;
    uint32_t dq_size;
    uint32_t q_inv_size;
} private_key_crt_size_t;

CRYSError_t __CC_CRYS_RSA_Build_PrivKeyCRT(CRYS_RSAUserPrivKey_t *user_privkey_ptr, DxUint8_t *p_ptr, DxUint16_t p_size,
                                           DxUint8_t *q_ptr, DxUint16_t q_size, DxUint8_t *dp_ptr, DxUint16_t dp_size,
                                           DxUint8_t *dq_ptr, DxUint16_t dq_size, DxUint8_t *qinv_ptr,
                                           DxUint16_t q_inv_size)
{
    private_key_crt_size_t all_size;
    all_size.p_size                      = (uint32_t)p_size;
    all_size.q_size                      = (uint32_t)q_size;
    all_size.dp_size                     = (uint32_t)dp_size;
    all_size.dq_size                     = (uint32_t)dq_size;
    all_size.q_inv_size                  = (uint32_t)q_inv_size;
    private_key_crt_size_t *all_size_ptr = &all_size;
    uint64_t args[] = {
        (uint64_t)(uintptr_t)user_privkey_ptr,
        (uint64_t)(uintptr_t)p_ptr,
        (uint64_t)(uintptr_t)q_ptr,
        (uint64_t)(uintptr_t)dp_ptr,
        (uint64_t)(uintptr_t)dq_ptr,
        (uint64_t)(uintptr_t)qinv_ptr,
        (uint64_t)(uintptr_t)all_size_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_RSA_BUILD_PRIVKEYCRT, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_ECPKI_BuildPublKeyFullCheck(CRYS_ECPKI_DomainID_t domain_id,            /* in */
                                                  DxUint8_t *publkey_in_ptr,                  /* in */
                                                  DxUint32_t publ_key_size_in,                /* in */
                                                  CRYS_ECPKI_UserPublKey_t *user_publkey_ptr, /* out */
                                                  /* in */
                                                  CRYS_ECPKI_BUILD_TempData_t *temp_buff_ptr)
{
    uint64_t args[] = {
        (uint64_t)domain_id,                                /* in */
        (uint64_t)(uintptr_t)publkey_in_ptr,                /* in */
        (uint64_t)publ_key_size_in,                         /* in */
        (uint64_t)(uintptr_t)user_publkey_ptr,              /* out */
        (uint64_t)(uintptr_t)temp_buff_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_ECPKI_BUILDPUBLKEY_FULLCHECK, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_ECPKI_BuildPrivKey(CRYS_ECPKI_DomainID_t domain_id, /* in */
                                         DxUint8_t *privkey_in_ptr,       /* in */
                                         DxUint32_t privkey_size_in,      /* in */
                                         /* out */
                                         CRYS_ECPKI_UserPrivKey_t *user_privkey_ptr)
{
    uint64_t args[] = {
        (uint64_t)domain_id,                                /* in */
        (uint64_t)(uintptr_t)privkey_in_ptr,                /* in */
        (uint64_t)privkey_size_in,                          /* in */
        (uint64_t)(uintptr_t)user_privkey_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_ECPKI_BUILD_PRIVKEY, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_RSA_Get_PubKey(CRYS_RSAUserPubKey_t *user_pubkey_ptr, DxUint8_t *exponent_ptr,
                                     DxUint16_t *exponent_size_ptr,
                                     DxUint8_t *modulus_ptr, DxUint16_t *modulus_size_ptr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)user_pubkey_ptr,
        (uint64_t)(uintptr_t)exponent_ptr,
        (uint64_t)(uintptr_t)exponent_size_ptr,
        (uint64_t)(uintptr_t)modulus_ptr,
        (uint64_t)(uintptr_t)modulus_size_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_RSA_GET_PUBKEY, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_RSA_Get_PrivKeyCRT(CRYS_RSAUserPrivKey_t *user_privkey_ptr, DxUint8_t *p_ptr,
                                         DxUint16_t *p_size_ptr, DxUint8_t *q_ptr, DxUint16_t *q_size_ptr,
                                         DxUint8_t *dp_ptr, DxUint16_t *dp_size_ptr, DxUint8_t *dq_ptr,
                                         DxUint16_t *dq_size_ptr, DxUint8_t *q_inv_ptr, DxUint16_t *q_inv_size_ptr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)user_privkey_ptr,
        (uint64_t)(uintptr_t)p_ptr,
        (uint64_t)(uintptr_t)p_size_ptr,
        (uint64_t)(uintptr_t)q_ptr,
        (uint64_t)(uintptr_t)q_size_ptr,
        (uint64_t)(uintptr_t)dp_ptr,
        (uint64_t)(uintptr_t)dp_size_ptr,
        (uint64_t)(uintptr_t)dq_ptr,
        (uint64_t)(uintptr_t)dq_size_ptr,
        (uint64_t)(uintptr_t)q_inv_ptr,
        (uint64_t)(uintptr_t)q_inv_size_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_RSA_GET_PRIVKEYCRT, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_DES_Block(CRYS_DESUserContext_t *context_id_ptr, /* in */
                                DxUint8_t *data_in_ptr,                /* in */
                                DxUint32_t data_in_size,                /* in */
                                DxUint8_t *data_out_ptr)               /* in/out */
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context_id_ptr, /* in */
        (uint64_t)(uintptr_t)data_in_ptr,    /* in */
        (uint64_t)data_in_size,              /* in */
        (uint64_t)(uintptr_t)data_out_ptr    /* in/out */
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_DES_BLOCK, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_DES_Free(CRYS_DESUserContext_t *context_id_ptr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context_id_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_DES_FREE, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_DH_GetSecretKey(DxUint8_t *client_prvkey_ptr, DxUint16_t client_prvkey_size,
                                      DxUint8_t *server_pubkey_ptr, DxUint16_t server_pubkey_size, DxUint8_t *prime_ptr,
                                      DxUint16_t prime_size, CRYS_DHUserPubKey_t *tmp_pubkey_ptr,
                                      CRYS_DHPrimeData_t *tmp_prime_data_ptr, DxUint8_t *secret_key_ptr,
                                      DxUint16_t *secret_key_size_ptr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)client_prvkey_ptr,
        (uint64_t)client_prvkey_size,
        (uint64_t)(uintptr_t)server_pubkey_ptr,
        (uint64_t)server_pubkey_size,
        (uint64_t)(uintptr_t)prime_ptr,
        (uint64_t)prime_size,
        (uint64_t)(uintptr_t)tmp_pubkey_ptr,
        (uint64_t)(uintptr_t)tmp_prime_data_ptr,
        (uint64_t)(uintptr_t)secret_key_ptr,
        (uint64_t)(uintptr_t)secret_key_size_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_DH_GET_SECRETKEY, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_AESCCM_Init(CRYS_AESCCM_UserContext_t *context_id_ptr, CRYS_AES_EncryptMode_t encr_decr_mode,
    CRYS_AESCCM_Key_t ccm_key, CRYS_AESCCM_KeySize_t key_size_id, DxUint32_t adata_size,
    DxUint32_t text_size, DxUint8_t *n_ptr, DxUint8_t size_Of_n, DxUint8_t size_of_t)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context_id_ptr,
        (uint64_t)encr_decr_mode,
        (uint64_t)(uintptr_t)ccm_key,
        (uint64_t)key_size_id,
        (uint64_t)adata_size,
        (uint64_t)text_size,
        (uint64_t)(uintptr_t)n_ptr,
        (uint64_t)size_Of_n,
        (uint64_t)size_of_t
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_AESCCM_INIT, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_AESCCM_BlockAdata(CRYS_AESCCM_UserContext_t *context_id_ptr, DxUint8_t *data_in_ptr,
                                        DxUint32_t data_in_size)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context_id_ptr,
        (uint64_t)(uintptr_t)data_in_ptr,
        (uint64_t)data_in_size
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_AESCCM_BLOCKADATA, args, ARRAY_SIZE(args));
}
CRYSError_t __CC_CRYS_AESCCM_BlockTextData(CRYS_AESCCM_UserContext_t *context_id_ptr, DxUint8_t *data_in_ptr,
                                           DxUint32_t data_in_size, DxUint8_t *data_out_ptr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context_id_ptr,
        (uint64_t)(uintptr_t)data_in_ptr,
        (uint64_t)data_in_size,
        (uint64_t)(uintptr_t)data_out_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_AESCCM_BLOCK_TEXTDATA, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_AESCCM_Finish(CRYS_AESCCM_UserContext_t *context_id_ptr, DxUint8_t *data_in_ptr,
                                    DxUint32_t data_in_size, DxUint8_t *data_out_ptr, CRYS_AESCCM_Mac_Res_t mac_res,
                                    DxUint8_t *size_of_t)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context_id_ptr,
        (uint64_t)(uintptr_t)data_in_ptr,
        (uint64_t)data_in_size,
        (uint64_t)(uintptr_t)data_out_ptr,
        (uint64_t)(uintptr_t)mac_res,
        (uint64_t)(uintptr_t)size_of_t
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_AESCCM_FINISH, args, ARRAY_SIZE(args));
}
CRYSError_t __CC_CRYS_DES_Init(CRYS_DESUserContext_t *context_id_ptr, CRYS_DES_Iv_t iv_ptr, CRYS_DES_Key_t *key_ptr,
                               CRYS_DES_NumOfKeys_t num_of_keys, CRYS_DES_EncryptMode_t encrypt_decrypt_flag,
                               CRYS_DES_OperationMode_t operation_mode)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context_id_ptr,
        (uint64_t)(uintptr_t)iv_ptr,
        (uint64_t)(uintptr_t)key_ptr,
        (uint64_t)num_of_keys,
        (uint64_t)encrypt_decrypt_flag,
        (uint64_t)operation_mode
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_DES_INIT, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_AES_SetIv(CRYS_AESUserContext_t *context_id_ptr, DxUint8_t *iv_ptr, DxUint32_t iv_size)
{
    if (iv_size < AES_IV_LEN)
        return TEE_ERROR_BAD_PARAMETERS;
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context_id_ptr,
        (uint64_t)(uintptr_t)iv_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_AES_SETIV, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_ECDH_SVDP_DH(CRYS_ECPKI_UserPublKey_t *partner_publkey_ptr, /* in */
                                   CRYS_ECPKI_UserPrivKey_t *user_privkey_ptr,    /* in */
                                   DxUint8_t *shared_secret_value_ptr,             /* out */
                                   DxUint32_t *shared_secrval_size_ptr,            /* in/out */
                                   /* in */
                                   CRYS_ECDH_TempData_t *temp_buff_ptr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)partner_publkey_ptr,     /* in */
        (uint64_t)(uintptr_t)user_privkey_ptr,        /* in */
        (uint64_t)(uintptr_t)shared_secret_value_ptr, /* out */
        (uint64_t)(uintptr_t)shared_secrval_size_ptr, /* in/out */
        (uint64_t)(uintptr_t)temp_buff_ptr            /* in */
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_ECDH_SVDP_DH, args, ARRAY_SIZE(args));
}

DxUTILError_t __CC_DX_UTIL_CmacDeriveKey(DX_CRYPTO_KEY_TYPE_t aes_key_type, DxUint8_t *p_data_in,
                                         DxUint32_t data_in_size, DxUint8_t *p_cmac_result)
{
    uint64_t args[] = {
        (uint64_t)aes_key_type,
        (uint64_t)(uintptr_t)p_data_in,     /* get low 32bit */
        (uint64_t)data_in_size,
        (uint64_t)(uintptr_t)p_cmac_result, /* get low 32bit */
    };
    return hmccmgr_call(SW_SYSCALL_CC_DX_UTIL_CMACDERIVEKEY, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_AES(CRYS_AES_IvCounter_t iv_counter_ptr, CRYS_AES_Key_t key_ptr, CRYS_AES_KeySize_t key_size,
                          CRYS_AES_EncryptMode_t encrypt_decrypt_flag, CRYS_AES_OperationMode_t operation_mode,
                          DxUint8_t *data_in_ptr, DxUint32_t data_in_size, DxUint8_t *data_out_ptr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)iv_counter_ptr,
        (uint64_t)(uintptr_t)key_ptr,
        (uint64_t)key_size,
        (uint64_t)encrypt_decrypt_flag,
        (uint64_t)operation_mode,
        (uint64_t)(uintptr_t)data_in_ptr,
        (uint64_t)data_in_size,
        (uint64_t)(uintptr_t)data_out_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_AES, args, ARRAY_SIZE(args));
}

CRYSError_t __CC_CRYS_RND_GenerateVector(DxUint16_t out_size_bytes, /* in */
                                         DxUint8_t *out_ptr)      /* out */
{
    uint64_t args[] = {
        (uint64_t)out_size_bytes,
        (uint64_t)(uintptr_t)out_ptr
    };
    return hmccmgr_call(SW_SYSCALL_CC_CRYS_RND_GENERATEVECTOR, args, ARRAY_SIZE(args));
}

bool __CC_EPS_SupportCdrmEnhance()
{
    uint32_t ret = hmccmgr_call(SW_SYSCALL_EPS_SUPPORTCDRMENHANCE, NULL, 0);
    return ret == EPS_SUPPORT;
}

CRYSError_t __CC_EPS_CTRL(uint32_t type, uint32_t profile)
{
    uint64_t args[] = {
        (uint64_t)type,
        (uint64_t)profile
    };
    return hmccmgr_call(SW_SYSCALL_CC_EPS_CTRL, args, ARRAY_SIZE(args));
}


int32_t __cc_eps_sm2_sign(void *private_key, uint8_t *input, uint32_t input_len, void *signature)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)private_key,
        (uint64_t)(uintptr_t)input, input_len,
        (uint64_t)(uintptr_t)signature
    };
    return hmccmgr_call(SW_SYSCALL_CC_EPS_SM2_SIGN, args, ARRAY_SIZE(args));
}

int32_t __cc_eps_sm2_verify(void *public_key, uint8_t *input, uint32_t input_len, void *signature)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)public_key,
        (uint64_t)(uintptr_t)input, input_len,
        (uint64_t)(uintptr_t)signature
    };
    return hmccmgr_call(SW_SYSCALL_CC_EPS_SM2_VERIFY, args, ARRAY_SIZE(args));
}

int32_t __cc_eps_sm2_encrypt(void *public_key, uint8_t *input, uint32_t input_len, void *cipher, uint32_t clen)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)public_key,
        (uint64_t)(uintptr_t)input, input_len,
        (uint64_t)(uintptr_t)cipher, clen
    };
    return hmccmgr_call(SW_SYSCALL_CC_EPS_SM2_ENCRYPT, args, ARRAY_SIZE(args));
}

int32_t __cc_eps_sm2_decrypt(void *public_key, uint8_t *output, uint32_t *output_len, void *cipher, uint32_t clen)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)public_key,
        (uint64_t)(uintptr_t)output,
        (uint64_t)(uintptr_t)output_len,
        (uint64_t)(uintptr_t)cipher, clen
    };
    return hmccmgr_call(SW_SYSCALL_CC_EPS_SM2_DECRYPT, args, ARRAY_SIZE(args));
}


int32_t __cc_eps_sm4_symmetric_encrypt(uint32_t algo, void *params)
{
    uint64_t args[] = { algo, (uint64_t)(uintptr_t)params };
    return hmccmgr_call(SW_SYSCALL_CC_EPS_SM4_SYMMETRIC_ENCRYPT, args, ARRAY_SIZE(args));
}

int32_t __cc_eps_sm4_symmetric_decrypt(uint32_t algo, void *params)
{
    uint64_t args[] = { algo, (uint64_t)(uintptr_t)params };
    return hmccmgr_call(SW_SYSCALL_CC_EPS_SM4_SYMMETRIC_DECRYPT, args, ARRAY_SIZE(args));
}

int32_t __cc_eps_sm4_config(void *context, void *param)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context,
        (uint64_t)(uintptr_t)param
    };
    return hmccmgr_call(SW_SYSCALL_CC_EPS_SM4_CONFIG, args, ARRAY_SIZE(args));
}

int32_t __cc_eps_sm4_cenc_decrypt(void *context, void *param)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)context,
        (uint64_t)(uintptr_t)param
    };
    return hmccmgr_call(SW_SYSCALL_CC_EPS_SM4_CENC_DECRYPT, args, ARRAY_SIZE(args));
}

#endif
