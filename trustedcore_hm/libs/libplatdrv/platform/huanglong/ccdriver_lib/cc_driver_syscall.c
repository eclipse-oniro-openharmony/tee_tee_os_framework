/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cc driver syscall
 * Create: 2020-11-02
 */

#include <errno.h>
#include <crypto_syscal_types.h>
#include "sre_syscalls_ext.h"
#include "sre_syscalls_id.h"
#include "sre_access_control.h"
#include "param_check.h"
#include "drv_module.h"
#include <hmdrv_stub.h>

/* cc */
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
#include "dx_cc_defs.h"
#include "dx_util_oem_asset.h"
#include "cc_aes_defs.h"
#include "cc_crypto_ctx.h"
#include <sep_ctx.h>

#include "crys_ecpki_types.h"
#include "crys_ecpki_build.h"
#include "crys_ecpki_ecdsa.h"
#include "crys_ecpki_dh.h"
#include "crys_ecpki_kg.h"
#include "crys_rsa_kg.h"

static int aes_key_size(CRYS_AES_KeySize_t keysize_id)
{
    switch (keysize_id) {
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

typedef struct {
    uint32_t p_size;
    uint32_t q_size;
    uint32_t dp_size;
    uint32_t dq_size;
    uint32_t q_inv_size;
} private_key_crt_size_t;

typedef struct {
    uint32_t hash_func;
    uint32_t l_len;
    uint32_t mgf;
    uint32_t data_in_size;
    uint32_t pkcs1_ver;
} decrypt_wraper_t;

int cc_driver_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t ret;
    if (params == NULL || params->args == 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    char *data = (char *)(uintptr_t)params->data;
    char *rdata = (char *)(uintptr_t)params->rdata;
    size_t rdata_len = (size_t)params->rdata_len;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_HMAC_INIT, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_HMACUserContext_t));
        ACCESS_CHECK_A64(args[2], args[3]);
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_HMACUserContext_t));
        ACCESS_READ_RIGHT_CHECK(args[2], args[3]);
        ret = CRYS_HMAC_Init((CRYS_HMACUserContext_t *)(uintptr_t)args[0], (CRYS_HASH_OperationMode_t)args[1],
                             (DxUint8_t *)(uintptr_t)args[2], (DxUint16_t)args[3]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_HMAC_UPDATE, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_HMACUserContext_t));
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_HMACUserContext_t));
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ret = CRYS_HMAC_Update((CRYS_HMACUserContext_t *)(uintptr_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                               (DxUint32_t)args[2]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_HMAC_FINISH, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_HMACUserContext_t));
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_HASH_Result_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_HMACUserContext_t));
        ACCESS_WRITE_RIGHT_CHECK(args[1], sizeof(CRYS_HASH_Result_t));
        ret = CRYS_HMAC_Finish((CRYS_HMACUserContext_t *)(uintptr_t)args[0], (DxUint32_t *)(uintptr_t)args[1]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_HMAC_FREE, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_HMACUserContext_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_HMACUserContext_t));
        ret = CRYS_HMAC_Free((CRYS_HMACUserContext_t *)(uintptr_t)args[0]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_HMAC, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], args[4]);
        ACCESS_CHECK_A64(args[5], sizeof(CRYS_HASH_Result_t));
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[3], args[4]);
        ACCESS_WRITE_RIGHT_CHECK(args[5], sizeof(CRYS_HASH_Result_t));
        ret = CRYS_HMAC((CRYS_HASH_OperationMode_t)args[0], (DxUint8_t *)(uintptr_t)args[1], (DxUint16_t)args[2],
                        (DxUint8_t *)(uintptr_t)args[3], (DxUint32_t)args[4], (DxUint32_t *)(uintptr_t)args[5]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_DES_INIT, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_DESUserContext_t));
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_DES_Iv_t));
        ACCESS_CHECK_A64(args[2], sizeof(CRYS_DES_Key_t) * args[3]);
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_DESUserContext_t));
        ACCESS_READ_RIGHT_CHECK(args[1], sizeof(CRYS_DES_Iv_t));
        ACCESS_READ_RIGHT_CHECK(args[2], sizeof(CRYS_DES_Key_t) * args[3]);
        ret = CRYS_DES_Init((CRYS_DESUserContext_t *)(uintptr_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                            (CRYS_DES_Key_t *)(uintptr_t)args[2],
                            (CRYS_DES_NumOfKeys_t)args[3], (CRYS_DES_EncryptMode_t)args[4],
                            (CRYS_DES_OperationMode_t)args[5]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_DES_BLOCK, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_DESUserContext_t));
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], args[2]);
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_DESUserContext_t));
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[3], args[2]);
        ret = CRYS_DES_Block((CRYS_DESUserContext_t *)(uintptr_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                             (DxUint32_t)args[2], (DxUint8_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_DES_FREE, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_DESUserContext_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_DESUserContext_t));
        ret = CRYS_DES_Free((CRYS_DESUserContext_t *)(uintptr_t)args[0]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_AES, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_AES_IvCounter_t));
        ACCESS_CHECK_A64(args[1], aes_key_size(args[2]));
        ACCESS_CHECK_A64(args[5], args[6]);
        ACCESS_CHECK_A64(args[7], args[6]);
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(CRYS_AES_IvCounter_t));
        ACCESS_READ_RIGHT_CHECK(args[5], args[6]);
        ACCESS_WRITE_RIGHT_CHECK(args[7], args[6]);
        ret = CRYS_AES((DxUint8_t *)(uintptr_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                       (CRYS_AES_KeySize_t)args[2],
                       (CRYS_AES_EncryptMode_t)args[3], (CRYS_AES_OperationMode_t)args[4],
                       (DxUint8_t *)(uintptr_t)args[5],
                       (DxUint32_t)args[6], (DxUint8_t *)(uintptr_t)args[7]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_AES_SETIV, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_AESUserContext_t));
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_AES_IvCounter_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_AESUserContext_t));
        ACCESS_WRITE_RIGHT_CHECK(args[1], sizeof(CRYS_AES_IvCounter_t));
        ret = CRYS_AES_SetIv((CRYS_AESUserContext_t *)(uintptr_t)args[0], (DxUint8_t *)(uintptr_t)args[1]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_AES_INIT, permissions, CC_CRYPTO_GROUP_PERMISSION)
        if (args[0] != 0) {
            params->rdata_len = 0;
            args[0]  = OS_ERROR;
            goto out;
        }
        if (args[1] != sizeof(CRYS_AESUserContext_t)) {
            params->rdata_len = 0;
            args[0]  = OS_ERROR;
            goto out;
        }
        if (args[2] != (sizeof(CRYS_AESUserContext_t) + sizeof(CRYS_AES_IvCounter_t))) {
            params->rdata_len = 0;
            args[0]  = OS_ERROR;
            goto out;
        }
        args[0] = (uintptr_t)(data + (uintptr_t)args[0]);
        args[1] = (uintptr_t)(data + (uintptr_t)args[1]);
        args[2] = (uintptr_t)(data + (uintptr_t)args[2]);
        ret = CRYS_AES_Init((CRYS_AESUserContext_t *)(uintptr_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                            (DxUint8_t *)(uintptr_t)args[2],
                            (CRYS_AES_KeySize_t)args[3], (CRYS_AES_EncryptMode_t)args[4],
                            (CRYS_AES_OperationMode_t)args[5]);
        if (memcpy_s(rdata, rdata_len, (void *)(uintptr_t)args[0], sizeof(CRYS_AESUserContext_t))) {
            params->rdata_len = 0;
            args[0]  = OS_ERROR;
        } else {
            params->rdata_len = sizeof(CRYS_AESUserContext_t);
            args[0]  = ret;
        }
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_AES_BLOCK, permissions, CC_CRYPTO_GROUP_PERMISSION)
        if (args[0] != 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        args[0] = (uintptr_t)(data + (uintptr_t)args[0]);
        if (args[2] <= 512) {
            if (args[1] != sizeof(CRYS_AESUserContext_t)) {
                args[0] = OS_ERROR;
                goto out;
            }
            args[1] = (uintptr_t)(data + args[1]);
        } else {
            ACCESS_CHECK_A64(args[1], args[2]);
            ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        }
        ACCESS_CHECK_A64(args[3], args[2]);
        ACCESS_WRITE_RIGHT_CHECK(args[3], args[2]);
        ret = CRYS_AES_Block((CRYS_AESUserContext_t *)(uintptr_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                             (DxUint32_t)args[2], (DxUint8_t *)(uintptr_t)args[3]);
        if (memcpy_s(rdata, rdata_len, (void *)(uintptr_t)args[0], sizeof(CRYS_AESUserContext_t))) {
            params->rdata_len = 0;
            args[0]  = OS_ERROR;
        } else {
            params->rdata_len = sizeof(CRYS_AESUserContext_t);
            args[0]  = ret;
        }
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_AES_FINISH, permissions, CC_CRYPTO_GROUP_PERMISSION)
        if (args[0] != 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        args[0] = (uintptr_t)(data + (uintptr_t)args[0]);
        if (args[2] <= 512 && args[2] != 0) {
            if (args[1] != sizeof(CRYS_AESUserContext_t)) {
                args[0] = OS_ERROR;
                goto out;
            }
            args[1] = (uintptr_t)(data + (uintptr_t)args[1]);
        } else {
            ACCESS_CHECK_A64(args[1], args[2]);
            ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        }
        if (args[2] <= 1024 && args[3] != 0 && args[2] != 0) {
            args[3]  = (uintptr_t)rdata;
            params->rdata_len = args[2];
        } else {
            DxUint32_t outsize;
            DxBool_t mac_mode = false;
            if (mac_mode)
                outsize = SEP_AES_BLOCK_SIZE;
            else
                outsize = args[2] ? args[2] : SEP_AES_BLOCK_SIZE;
            ACCESS_CHECK_A64(args[3], outsize);
            ACCESS_WRITE_RIGHT_CHECK(args[3], outsize);
        }

        ret = CRYS_AES_Finish((CRYS_AESUserContext_t *)(uintptr_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                              (DxUint32_t)args[2], (DxUint8_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_AESCCM_INIT, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_AESCCM_UserContext_t));
        ACCESS_CHECK_A64(args[2], sizeof(CRYS_AESCCM_Key_t));
        ACCESS_CHECK_A64(args[6], args[7]);
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_AESCCM_UserContext_t));
        ACCESS_READ_RIGHT_CHECK(args[2], sizeof(CRYS_AESCCM_Key_t));
        ACCESS_READ_RIGHT_CHECK(args[6], args[7]);
        ret = CRYS_AESCCM_Init((CRYS_AESCCM_UserContext_t *)(uintptr_t)args[0], (CRYS_AES_EncryptMode_t)args[1],
                               (DxUint8_t *)(uintptr_t)args[2], (CRYS_AESCCM_KeySize_t)args[3], (DxUint32_t)args[4],
                               (DxUint32_t)args[5], (DxUint8_t *)(uintptr_t)args[6], (DxUint8_t)args[7],
                               (DxUint8_t)args[8]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_AESCCM_BLOCKADATA, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_AESCCM_UserContext_t));
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_AESCCM_UserContext_t));
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ret    = CRYS_AESCCM_BlockAdata((CRYS_AESCCM_UserContext_t *)(uintptr_t)args[0],
                                        (DxUint8_t *)(uintptr_t)args[1], (DxUint32_t)args[2]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_AESCCM_BLOCK_TEXTDATA, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_AESCCM_UserContext_t));
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], args[2]);
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_AESCCM_UserContext_t));
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_WRITE_RIGHT_CHECK(args[3], args[2]);
        ret = CRYS_AESCCM_BlockTextData((CRYS_AESCCM_UserContext_t *)(uintptr_t)args[0],
                                        (DxUint8_t *)(uintptr_t)args[1],
                                        (DxUint32_t)args[2], (DxUint8_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_AESCCM_FINISH, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_AESCCM_UserContext_t));
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], args[2]);
        ACCESS_CHECK_A64(args[4], sizeof(CRYS_AESCCM_Mac_Res_t));
        ACCESS_CHECK_A64(args[5], sizeof(DxUint8_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_AESCCM_UserContext_t));
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_WRITE_RIGHT_CHECK(args[3], args[2]);
        ACCESS_WRITE_RIGHT_CHECK(args[4], sizeof(CRYS_AESCCM_Mac_Res_t));
        ACCESS_WRITE_RIGHT_CHECK(args[5], sizeof(DxUint8_t));
        ret = CRYS_AESCCM_Finish((CRYS_AESCCM_UserContext_t *)(uintptr_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                                 (DxUint32_t)args[2], (DxUint8_t *)(uintptr_t)args[3],
                                 (DxUint8_t *)(uintptr_t)args[4], (DxUint8_t *)(uintptr_t)args[5]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_KDF_KEYDERIVFUNC, permissions, GENERAL_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], args[1]);
        ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
        ACCESS_CHECK_A64(args[2], sizeof(CRYS_KDF_OtherInfo_t));
        ACCESS_READ_RIGHT_CHECK(args[2], sizeof(CRYS_KDF_OtherInfo_t));
        ACCESS_CHECK_A64(args[5], args[6]);
        ACCESS_WRITE_RIGHT_CHECK(args[5], args[6]);
        ret = CRYS_KDF_KeyDerivFunc((DxUint8_t *)(uintptr_t)args[0], (DxUint32_t)args[1],
                                    (CRYS_KDF_OtherInfo_t *)(uintptr_t)args[2],
                                    (CRYS_KDF_HASH_OpMode_t)args[3], (CRYS_KDF_DerivFuncMode_t)args[4],
                                    (DxUint8_t *)(uintptr_t)args[5], (DxUint32_t)args[6]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_DH_GET_SECRETKEY, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], args[1]);
        ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
        ACCESS_CHECK_A64(args[2], args[3]);
        ACCESS_READ_RIGHT_CHECK(args[2], args[3]);
        ACCESS_CHECK_A64(args[4], args[5]);
        ACCESS_READ_RIGHT_CHECK(args[4], args[5]);
        ACCESS_CHECK_A64(args[6], sizeof(CRYS_DHUserPubKey_t));
        ACCESS_READ_RIGHT_CHECK(args[6], sizeof(CRYS_DHUserPubKey_t));
        ACCESS_CHECK_A64(args[7], sizeof(CRYS_DHPrimeData_t));
        ACCESS_READ_RIGHT_CHECK(args[7], sizeof(CRYS_DHPrimeData_t));
        /* should first check args5(its size of args[8]) */
        ACCESS_CHECK_A64(args[9], sizeof(DxUint16_t));
        ACCESS_WRITE_RIGHT_CHECK(args[9], sizeof(DxUint16_t));
        if (args[9]) {
            ACCESS_CHECK_A64(args[8], *((DxUint16_t *)(uintptr_t)args[9]));
            ACCESS_WRITE_RIGHT_CHECK(args[8], *((DxUint16_t *)(uintptr_t)args[9]));
        }
        ret = CRYS_DH_GetSecretKey((DxUint8_t *)(uintptr_t)args[0], (DxUint16_t)args[1],
                                   (DxUint8_t *)(uintptr_t)args[2],
                                   (DxUint16_t)args[3], (DxUint8_t *)(uintptr_t)args[4], (DxUint16_t)args[5],
                                   (CRYS_DHUserPubKey_t *)(uintptr_t)args[6], (CRYS_DHPrimeData_t *)(uintptr_t)args[7],
                                   (DxUint8_t *)(uintptr_t)args[8], (DxUint16_t *)(uintptr_t)args[9]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_DH_X942_GETSECRET_DATA, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], args[1]);
        ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
        ACCESS_CHECK_A64(args[2], args[3]);
        ACCESS_READ_RIGHT_CHECK(args[2], args[3]);
        ACCESS_CHECK_A64(args[4], args[5]);
        ACCESS_READ_RIGHT_CHECK(args[4], args[5]);
        ACCESS_CHECK_A64(args[6], sizeof(CRYS_DH_OtherInfo_t));
        ACCESS_READ_RIGHT_CHECK(args[6], sizeof(CRYS_DH_OtherInfo_t));
        ACCESS_CHECK_A64(args[9], sizeof(CRYS_DH_Temp_t));
        ACCESS_READ_RIGHT_CHECK(args[9], sizeof(CRYS_DH_Temp_t));
        ACCESS_CHECK_A64(args[10], args[11]);
        ACCESS_WRITE_RIGHT_CHECK(args[10], args[11]);
        ret = CRYS_DH_X942_GetSecretData(
            (DxUint8_t *)(uintptr_t)args[0], (DxUint16_t)args[1], (DxUint8_t *)(uintptr_t)args[2], (DxUint16_t)args[3],
            (DxUint8_t *)(uintptr_t)args[4], (DxUint16_t)args[5], (CRYS_DH_OtherInfo_t *)(uintptr_t)args[6],
            (CRYS_DH_HASH_OpMode_t)args[7],
            (CRYS_DH_DerivationFunc_Mode)args[8], (CRYS_DH_Temp_t *)(uintptr_t)args[9],
            (DxUint8_t *)(uintptr_t)args[10], (DxUint16_t)args[11]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_DX_UTIL_CMACDERIVEKEY, permissions, CC_KEY_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], sizeof(DX_UTIL_AES_CmacResult_t));
        ACCESS_WRITE_RIGHT_CHECK(args[3], sizeof(DX_UTIL_AES_CmacResult_t));
        ret = DX_UTIL_CmacDeriveKey((DX_UTIL_KeyType_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                                    (DxUint32_t)args[2], (DxUint8_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END;

#if defined(TESTSUITE_RTOSck_UT) || defined(TESTSUITE_RTOSck_PT) || defined(TESTSUITE_RTOSck_IT)
        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RND_INSTANTIATION, permissions, CC_RNG_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_RND_WorkBuff_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_RND_WorkBuff_t));
        ret = CRYS_RND_Instantiation((CRYS_RND_WorkBuff_t *)args[0]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RND_UNINSTANTIATION, permissions, CC_RNG_GROUP_PERMISSION)
        ret = CRYS_RND_UnInstantiation();
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RND_RESEEDING, permissions, CC_RNG_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_RND_WorkBuff_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_RND_WorkBuff_t));
        ret    = CRYS_RND_Reseeding((CRYS_RND_WorkBuff_t *)(uintptr_t)args[0]);
        args[0] = ret;
        SYSCALL_END;
#endif

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RND_GENERATEVECTOR, permissions, CC_RNG_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[0]);
        ACCESS_WRITE_RIGHT_CHECK(args[1], args[0]);
        ret = CRYS_RND_GenerateVector((DxUint16_t)args[0], (DxUint8_t *)(uintptr_t)args[1]);
        args[0] = ret;
        SYSCALL_END;

#if defined(TESTSUITE_RTOSck_UT) || defined(TESTSUITE_RTOSck_PT) || defined(TESTSUITE_RTOSck_IT)
        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RND_GENERATEVECTORINRANGE, permissions, CC_RNG_GROUP_PERMISSION)
        if (!args[1]) {
            ACCESS_CHECK_A64(args[2], ((args[0] + 7) / 8));
            ACCESS_WRITE_RIGHT_CHECK(args[2], ((args[0] + 7) / 8));
        } else {
            ACCESS_CHECK_A64(args[1], ((args[0] + 7) / 8));
            ACCESS_READ_RIGHT_CHECK(args[1], ((args[0] + 7) / 8));
            ACCESS_CHECK_A64(args[2], ((args[0] + 7) / 8));
            ACCESS_WRITE_RIGHT_CHECK(args[2], ((args[0] + 7) / 8));
        }
        ret = CRYS_RND_GenerateVectorInRange((DxUint32_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                                             (DxUint8_t *)(uintptr_t)args[2]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RND_ADDADDITIONALINPUT, permissions, CC_RNG_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], args[1]);
        ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
        ret = CRYS_RND_AddAdditionalInput((DxUint8_t *)(uintptr_t)args[0], (DxUint16_t)args[1]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RND_ENTERKATMODE, permissions, CC_RNG_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], args[1]);
        ACCESS_CHECK_A64(args[2], args[3]);
        ACCESS_CHECK_A64(args[4], sizeof(CRYS_RND_WorkBuff_t));
        ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
        ACCESS_READ_RIGHT_CHECK(args[2], args[3]);
        ACCESS_WRITE_RIGHT_CHECK(args[4], sizeof(CRYS_RND_WorkBuff_t));
        ret = CRYS_RND_EnterKatMode((DxUint8_t *)(uintptr_t)args[0], (DxUint32_t)args[1],
                                    (DxUint8_t *)(uintptr_t)args[2],
                                    (DxUint32_t)args[3], (CRYS_RND_WorkBuff_t *)(uintptr_t)args[4]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RND_DISABLEKATMODE, permissions, CC_RNG_GROUP_PERMISSION)
        CRYS_RND_DisableKatMode();
        SYSCALL_END;
#endif

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RSA_KG_GENERATEKEYPAIR, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], args[1]);
        ACCESS_CHECK_A64(args[3], sizeof(CRYS_RSAUserPrivKey_t));
        ACCESS_CHECK_A64(args[4], sizeof(CRYS_RSAUserPubKey_t));
        ACCESS_CHECK_A64(args[5], sizeof(CRYS_RSAKGData_t));
        ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
        ACCESS_WRITE_RIGHT_CHECK(args[3], sizeof(CRYS_RSAUserPrivKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[4], sizeof(CRYS_RSAUserPubKey_t));
        ACCESS_READ_RIGHT_CHECK(args[5], sizeof(CRYS_RSAKGData_t));
        ret = CRYS_RSA_KG_GenerateKeyPair((DxUint8_t *)(uintptr_t)args[0], (DxUint16_t)args[1],
                                          (DxUint32_t)args[2], (CRYS_RSAUserPrivKey_t *)(uintptr_t)args[3],
                                          (CRYS_RSAUserPubKey_t *)(uintptr_t)args[4],
                                          (CRYS_RSAKGData_t *)(uintptr_t)args[5]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RSA_BUILD_PUBKEY, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_RSAUserPubKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_RSAUserPubKey_t));
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], args[4]);
        ACCESS_READ_RIGHT_CHECK(args[3], args[4]);
        ret = CRYS_RSA_Build_PubKey((CRYS_RSAUserPubKey_t *)(uintptr_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                                    (DxUint16_t)args[2], (DxUint8_t *)(uintptr_t)args[3], (DxUint16_t)args[4]);

        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RSA_BUILD_PRIVKEY, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_RSAUserPrivKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_RSAUserPrivKey_t));
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], args[4]);
        ACCESS_READ_RIGHT_CHECK(args[3], args[4]);
        ACCESS_CHECK_A64(args[5], args[6]);
        ACCESS_READ_RIGHT_CHECK(args[5], args[6]);
        ret = CRYS_RSA_Build_PrivKey((CRYS_RSAUserPrivKey_t *)(uintptr_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                                     (DxUint16_t)args[2], (DxUint8_t *)(uintptr_t)args[3], (DxUint16_t)args[4],
                                     (DxUint8_t *)(uintptr_t)args[5], (DxUint16_t)args[6]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RSA_BUILD_PRIVKEYCRT, permissions, CC_CRYPTO_GROUP_PERMISSION)
        if (args[6] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[6], sizeof(private_key_crt_size_t));
        ACCESS_READ_RIGHT_CHECK(args[6], sizeof(private_key_crt_size_t));
        private_key_crt_size_t *all_size_ptr = (private_key_crt_size_t*)(uintptr_t)args[6];
        uint32_t psize = all_size_ptr->p_size;
        uint32_t qsize = all_size_ptr->q_size;
        uint32_t dpsize = all_size_ptr->dp_size;
        uint32_t dqsize = all_size_ptr->dq_size;
        uint32_t qinvsize = all_size_ptr->q_inv_size;
        if (args[0] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_RSAUserPrivKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_RSAUserPrivKey_t));
        if (args[1] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[1], psize);
        ACCESS_READ_RIGHT_CHECK(args[1], psize);
        if (args[2] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[2], qsize);
        ACCESS_READ_RIGHT_CHECK(args[2], qsize);
        if (args[3] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[3], dpsize);
        ACCESS_READ_RIGHT_CHECK(args[3], dpsize);
        if (args[4] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[4], dqsize);
        ACCESS_READ_RIGHT_CHECK(args[4], dqsize);
        if (args[5] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[5], qinvsize);
        ACCESS_READ_RIGHT_CHECK(args[5], qinvsize);
        ret = CRYS_RSA_Build_PrivKeyCRT(
            (CRYS_RSAUserPrivKey_t *)(uintptr_t)args[0], (DxUint8_t *)(uintptr_t)args[1], (DxUint16_t)psize,
            (DxUint8_t *)(uintptr_t)args[2], (DxUint16_t)qsize, (DxUint8_t *)(uintptr_t)args[3], (DxUint16_t)dpsize,
            (DxUint8_t *)(uintptr_t)args[4], (DxUint16_t)dqsize, (DxUint8_t *)(uintptr_t)args[5],
            (DxUint16_t)qinvsize);
        args[0] = ret;
        SYSCALL_END;

#if defined(TESTSUITE_RTOSck_UT) || defined(TESTSUITE_RTOSck_PT) || defined(TESTSUITE_RTOSck_IT)
        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RSA_BUILD_CONVERTPRIVKEYTOCRT, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_RSAUserPrivKey_t));
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_RSAConvertKeyToCrtBuffers_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_RSAUserPrivKey_t));
        ACCESS_READ_RIGHT_CHECK(args[1], sizeof(CRYS_RSAConvertKeyToCrtBuffers_t));
        ret = CRYS_RSA_Build_ConvertPrivKeyToCRT((CRYS_RSAUserPrivKey_t *)(uintptr_t)args[0],
                                                 (CRYS_RSAConvertKeyToCrtBuffers_t *)(uintptr_t)args[1]);
        args[0] = ret;
        SYSCALL_END;
#endif
        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RSA_GET_PUBKEY, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_RSAUserPubKey_t));
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(CRYS_RSAUserPubKey_t));
        ACCESS_CHECK_A64(args[2], sizeof(uint16_t));
        ACCESS_WRITE_RIGHT_CHECK(args[2], sizeof(uint16_t));
        if (args[2]) {
            ACCESS_CHECK_A64(args[1], *((DxUint16_t *)(uintptr_t)args[2]));
            ACCESS_WRITE_RIGHT_CHECK(args[1], *((DxUint16_t *)(uintptr_t)args[2]));
        }
        ACCESS_CHECK_A64(args[4], sizeof(uint16_t));
        ACCESS_WRITE_RIGHT_CHECK(args[4], sizeof(uint16_t));
        if (args[4]) {
            ACCESS_CHECK_A64(args[3], *((DxUint16_t *)(uintptr_t)args[4]));
            ACCESS_WRITE_RIGHT_CHECK(args[3], *((DxUint16_t *)(uintptr_t)args[4]));
        }
        ret = CRYS_RSA_Get_PubKey((CRYS_RSAUserPubKey_t *)(uintptr_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                                  (DxUint16_t *)(uintptr_t)args[2],
                                  (DxUint8_t *)(uintptr_t)args[3], (DxUint16_t *)(uintptr_t)args[4]);
        args[0] = ret;
        SYSCALL_END;

#if defined(TESTSUITE_RTOSck_UT) || defined(TESTSUITE_RTOSck_PT) || defined(TESTSUITE_RTOSck_IT)
        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RSA_GET_MODSIZEFROMPUBKEY, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_RSAUserPubKey_t));
        ACCESS_CHECK_A64(args[1], sizeof(DxUint16_t));
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(CRYS_RSAUserPubKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[1], sizeof(DxUint16_t));
        ret = CRYS_RSA_Get_ModSizeFromPubKey((CRYS_RSAUserPubKey_t *)(uintptr_t)args[0],
                                             (DxUint16_t *)(uintptr_t)args[1]);
        args[0] = ret;
        SYSCALL_END;
#endif

        SYSCALL_PERMISSION(SW_SYSCALL_CC__DX_RSA_SCHEMES_ENCRYPT, permissions, CC_CRYPTO_GROUP_PERMISSION)
        /* all ptrs mmu attr has been checked by DxCcAcl_IsBuffAccessOk */
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_RSAUserPubKey_t));
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(CRYS_RSAUserPubKey_t));
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_RSAPrimeData_t));
        ACCESS_READ_RIGHT_CHECK(args[1], sizeof(CRYS_RSAPrimeData_t));
        bool check = (!args[3] && (args[4] == 0));
        if (!check) {
            ACCESS_CHECK_A64(args[3], args[4]);
            ACCESS_READ_RIGHT_CHECK(args[3], args[4]);
        }
        ACCESS_CHECK_A64(args[6], args[7]);
        ACCESS_READ_RIGHT_CHECK(args[6], args[7]);
        CRYS_RSAUserPubKey_t *tmp_ptr = (CRYS_RSAUserPubKey_t *)(uintptr_t)args[0];
        if (tmp_ptr == NULL) {
            args[0] = OS_ERROR;
            goto out;
        }
        CRYSRSAPubKey_t *pubkey_ptr = (CRYSRSAPubKey_t *)tmp_ptr->PublicKeyDbBuff;
        uint16_t output_size = ((uint16_t)pubkey_ptr->nSizeInBits + 7) / 8;
        ACCESS_CHECK_A64(args[8], output_size);
        ACCESS_WRITE_RIGHT_CHECK(args[8], output_size);
        ret = _DX_RSA_SCHEMES_Encrypt(
            (CRYS_RSAUserPubKey_t *)(uintptr_t)args[0], (CRYS_RSAPrimeData_t *)(uintptr_t)args[1],
            (CRYS_RSA_HASH_OpMode_t)args[2], (DxUint8_t *)(uintptr_t)args[3], (DxUint16_t)args[4],
            (CRYS_PKCS1_MGF_t)args[5], (DxUint8_t *)(uintptr_t)args[6], (DxUint16_t)args[7],
            (DxUint8_t *)(uintptr_t)args[8], (CRYS_PKCS1_version)args[9]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC__DX_RSA_SCHEMES_DECRYPT, permissions, CC_CRYPTO_GROUP_PERMISSION)
        if (args[6] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[6], sizeof(decrypt_wraper_t));
        ACCESS_READ_RIGHT_CHECK(args[6], sizeof(decrypt_wraper_t));
        decrypt_wraper_t *param_wraper = (decrypt_wraper_t*)(uintptr_t)args[6];
        uint32_t hashfunc = param_wraper->hash_func;
        uint32_t l_len = param_wraper->l_len;
        uint32_t mgf = param_wraper->mgf;
        uint32_t data_in_size = param_wraper->data_in_size;
        uint32_t pkcs1_ver = param_wraper->pkcs1_ver;
        if (args[0] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_RSAUserPrivKey_t));
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(CRYS_RSAUserPrivKey_t));
        if (args[1] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_RSAPrimeData_t));
        ACCESS_READ_RIGHT_CHECK(args[1], sizeof(CRYS_RSAPrimeData_t));
        bool check = (!args[2] && (l_len == 0));
        if (!check) {
            if (args[2] == 0) {
                args[0] = OS_ERROR;
                goto out;
            }
            ACCESS_CHECK_A64(args[2], l_len);
            ACCESS_READ_RIGHT_CHECK(args[2], l_len);
        }
        if (args[3] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[3], data_in_size);
        ACCESS_READ_RIGHT_CHECK(args[3], data_in_size);
        if (args[5] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[5], sizeof(DxUint16_t));
        ACCESS_WRITE_RIGHT_CHECK(args[5], sizeof(DxUint16_t));
        if (args[4] == 0 || *(DxUint16_t *)(uintptr_t)args[5] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        if (args[5]) {
            ACCESS_CHECK_A64(args[4], *(DxUint16_t *)(uintptr_t)args[5]);
            ACCESS_WRITE_RIGHT_CHECK(args[4], *(DxUint16_t *)(uintptr_t)args[5]);
        }
        ret = _DX_RSA_SCHEMES_Decrypt(
            (CRYS_RSAUserPrivKey_t *)(uintptr_t)args[0], (CRYS_RSAPrimeData_t *)(uintptr_t)args[1],
            (CRYS_RSA_HASH_OpMode_t)hashfunc, (DxUint8_t *)(uintptr_t)args[2], (DxUint16_t)l_len,
            (CRYS_PKCS1_MGF_t)mgf, (DxUint8_t *)(uintptr_t)args[3], (DxUint16_t)data_in_size,
            (DxUint8_t *)(uintptr_t)args[4], (DxUint16_t *)(uintptr_t)args[5], (CRYS_PKCS1_version)pkcs1_ver);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC__DX_RSA_SIGN, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_RSAPrivUserContext_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_RSAPrivUserContext_t));
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_RSAUserPrivKey_t));
        ACCESS_READ_RIGHT_CHECK(args[1], sizeof(CRYS_RSAUserPrivKey_t));
        ACCESS_CHECK_A64(args[5], args[6]);
        ACCESS_READ_RIGHT_CHECK(args[5], args[6]);
        ACCESS_CHECK_A64(args[8], sizeof(DxUint16_t));
        ACCESS_READ_RIGHT_CHECK(args[8], sizeof(DxUint16_t));
        if (args[8]) {
            ACCESS_CHECK_A64(args[7], *(DxUint16_t *)(uintptr_t)args[8]);
            ACCESS_WRITE_RIGHT_CHECK(args[7], *(DxUint16_t *)(uintptr_t)args[8]);
        }
        ret = _DX_RSA_Sign((CRYS_RSAPrivUserContext_t *)(uintptr_t)args[0],
                           (CRYS_RSAUserPrivKey_t *)(uintptr_t)args[1], (CRYS_RSA_HASH_OpMode_t)args[2],
                           (CRYS_PKCS1_MGF_t)args[3], (DxUint16_t)args[4], (DxUint8_t *)(uintptr_t)args[5],
                           (DxUint32_t)args[6], (DxUint8_t *)(uintptr_t)args[7], (DxUint16_t *)(uintptr_t)args[8],
                           (CRYS_PKCS1_version)args[9]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC__DX_RSA_VERIFY, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_RSAPubUserContext_t));
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(CRYS_RSAPubUserContext_t));
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_RSAUserPubKey_t));
        ACCESS_READ_RIGHT_CHECK(args[1], sizeof(CRYS_RSAUserPubKey_t));
        if (!args[1]) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[5], args[6]);
        ACCESS_READ_RIGHT_CHECK(args[5], args[6]);
        if (args[1]) {
            /* check signature against size of pubkey in bytes */
            CRYS_RSAUserPubKey_t *tmp_ptr = (CRYS_RSAUserPubKey_t *)(uintptr_t)args[1];
            CRYSRSAPubKey_t *pubkey       = (CRYSRSAPubKey_t *)tmp_ptr->PublicKeyDbBuff;
            unsigned int sig_len          = (pubkey->nSizeInBits + 7) / 8;
            ACCESS_CHECK_A64(args[7], sig_len);
            ACCESS_READ_RIGHT_CHECK(args[7], sig_len);
        } else {
            ACCESS_CHECK_A64(args[7], CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * 4);
            ACCESS_READ_RIGHT_CHECK(args[7], sizeof(DxUint8_t));
        }
        ret = _DX_RSA_Verify((CRYS_RSAPubUserContext_t *)(uintptr_t)args[0],
                             (CRYS_RSAUserPubKey_t *)(uintptr_t)args[1], (CRYS_RSA_HASH_OpMode_t)args[2],
                             (CRYS_PKCS1_MGF_t)args[3], (DxUint16_t)args[4], (DxUint8_t *)(uintptr_t)args[5],
                             (DxUint32_t)args[6], (DxUint8_t *)(uintptr_t)args[7], (CRYS_PKCS1_version)args[8]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RSA_PRIM_ENCRYPT, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_RSAUserPubKey_t));
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(CRYS_RSAUserPubKey_t));
        if (!args[0]) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_RSAPrimeData_t));
        ACCESS_READ_RIGHT_CHECK(args[1], sizeof(CRYS_RSAPrimeData_t));
        ACCESS_CHECK_A64(args[2], args[3]);
        ACCESS_READ_RIGHT_CHECK(args[2], args[3]);
        /* Output_ptr and Data_ptr shares a size parameter in this function,
         * However, the real size of Output_ptr may smaller which cause map failed.
         * We assign a new upper bound size to Output_ptr */
        CRYSRSAPubKey_t *pubkey_ptr = (CRYSRSAPubKey_t *)((CRYS_RSAUserPubKey_t *)(uintptr_t)args[0])->PublicKeyDbBuff;
        uint16_t output_size = ((uint16_t)pubkey_ptr->nSizeInBits + 7) / 8;
        ACCESS_CHECK_A64(args[4], output_size);
        ACCESS_WRITE_RIGHT_CHECK(args[4], output_size);
        ret = CRYS_RSA_PRIM_Encrypt((CRYS_RSAUserPubKey_t *)(uintptr_t)args[0],
                                    (CRYS_RSAPrimeData_t *)(uintptr_t)args[1],
                                    (DxUint8_t *)(uintptr_t)args[2], (DxUint16_t)args[3],
                                    (DxUint8_t *)(uintptr_t)args[4]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RSA_PRIM_DECRYPT, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_RSAUserPrivKey_t));
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(CRYS_RSAUserPrivKey_t));
        if (!args[0]) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_RSAPrimeData_t));
        ACCESS_READ_RIGHT_CHECK(args[1], sizeof(CRYS_RSAPrimeData_t));
        ACCESS_CHECK_A64(args[2], args[3]);
        ACCESS_READ_RIGHT_CHECK(args[2], args[3]);
        CRYSRSAPrivKey_t *privkey_ptr =
            (CRYSRSAPrivKey_t *)((CRYS_RSAUserPrivKey_t *)(uintptr_t)args[0])->PrivateKeyDbBuff;
        uint16_t output_size = ((uint16_t)privkey_ptr->nSizeInBits + 7) / 8;
        ACCESS_CHECK_A64(args[4], output_size);
        ACCESS_WRITE_RIGHT_CHECK(args[4], output_size);
        ret = CRYS_RSA_PRIM_Decrypt((CRYS_RSAUserPrivKey_t *)(uintptr_t)args[0],
                                    (CRYS_RSAPrimeData_t *)(uintptr_t)args[1],
                                    (DxUint8_t *)(uintptr_t)args[2], (DxUint16_t)args[3],
                                    (DxUint8_t *)(uintptr_t)args[4]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_DX_UTIL_OEMASSETUNPACK, permissions, CC_OEM_KEY_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(DX_UTIL_OemKey_t));
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(DX_UTIL_OemKey_t));
        ACCESS_CHECK_A64(args[2], args[3]);
        ACCESS_READ_RIGHT_CHECK(args[2], args[3]);
        ACCESS_CHECK_A64(args[5], sizeof(DxUint32_t));
        ACCESS_READ_RIGHT_CHECK(args[5], sizeof(DxUint32_t));
        if (args[5]) {
            ACCESS_CHECK_A64(args[4], *(DxUint32_t *)(uintptr_t)args[5]);
            ACCESS_WRITE_RIGHT_CHECK(args[4], *(DxUint32_t *)(uintptr_t)args[5]);
        }
        ACCESS_CHECK_A64(args[6], sizeof(DxUint32_t));
        ACCESS_WRITE_RIGHT_CHECK(args[6], sizeof(DxUint32_t));
        ret = DX_UTIL_OemAssetUnpack((DxUint8_t *)(uintptr_t)args[0], (DxUint32_t)args[1],
                                     (DxUint8_t *)(uintptr_t)args[2],
                                     (DxUint32_t)args[3], (DxUint8_t *)(uintptr_t)args[4],
                                     (DxUint32_t *)(uintptr_t)args[5],
                                     (DxUint32_t *)(uintptr_t)args[6]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_ECPKI_BUILD_PUBLKEY, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[3], sizeof(CRYS_ECPKI_UserPublKey_t));
        ret = CRYS_ECPKI_BuildPublKey((CRYS_ECPKI_DomainID_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                                      (DxUint32_t)args[2], (CRYS_ECPKI_UserPublKey_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_ECPKI_BUILDPUBLKEY_FULLCHECK, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[3], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_CHECK_A64(args[4], sizeof(CRYS_ECPKI_BUILD_TempData_t));
        ACCESS_READ_RIGHT_CHECK(args[4], sizeof(CRYS_ECPKI_BUILD_TempData_t));
        ret = CRYS_ECPKI_BuildPublKeyFullCheck((CRYS_ECPKI_DomainID_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                                               (DxUint32_t)args[2], (CRYS_ECPKI_UserPublKey_t *)(uintptr_t)args[3],
                                               (CRYS_ECPKI_BUILD_TempData_t *)(uintptr_t)args[4]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_ECPKI_BUILD_PRIVKEY, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[3], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ret = CRYS_ECPKI_BuildPrivKey((CRYS_ECPKI_DomainID_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                                      (DxUint32_t)args[2], (CRYS_ECPKI_UserPrivKey_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_ECPKI_EXPORTPUBLKEY, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_CHECK_A64(args[3], sizeof(DxUint32_t));
        ACCESS_WRITE_RIGHT_CHECK(args[3], sizeof(DxUint32_t));
        if (args[3]) {
            if (*((DxUint32_t *)(uintptr_t)args[3]) == 0) {
                printf("WARNING: CCMgr map size = 0, force set size to 1\n");
                ACCESS_CHECK_A64(args[2], sizeof(DxUint8_t));
                ACCESS_WRITE_RIGHT_CHECK(args[2], sizeof(DxUint8_t));
            } else {
                ACCESS_CHECK_A64(args[2], *((DxUint32_t *)(uintptr_t)args[3]));
                ACCESS_WRITE_RIGHT_CHECK(args[2], *((DxUint32_t *)(uintptr_t)args[3]));
            }
        }
        ret = CRYS_ECPKI_ExportPublKey((CRYS_ECPKI_UserPublKey_t *)(uintptr_t)args[0],
                                       (CRYS_ECPKI_PointCompression_t)args[1],
                                       (DxUint8_t *)(uintptr_t)args[2], (DxUint32_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_ECDH_SVDP_DH, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ACCESS_READ_RIGHT_CHECK(args[1], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ACCESS_CHECK_A64(args[3], sizeof(DxUint32_t));
        ACCESS_WRITE_RIGHT_CHECK(args[3], sizeof(DxUint32_t));
        if (args[3]) {
            ACCESS_CHECK_A64(args[2], *(DxUint32_t *)(uintptr_t)args[3]);
            ACCESS_WRITE_RIGHT_CHECK(args[2], *((DxUint32_t *)(uintptr_t)args[3]));
        }
        ACCESS_CHECK_A64(args[4], sizeof(CRYS_ECDH_TempData_t));
        ACCESS_READ_RIGHT_CHECK(args[4], sizeof(CRYS_ECDH_TempData_t));
        ret = CRYS_ECDH_SVDP_DH((CRYS_ECPKI_UserPublKey_t *)(uintptr_t)args[0],
                                (CRYS_ECPKI_UserPrivKey_t *)(uintptr_t)args[1],
                                (DxUint8_t *)(uintptr_t)args[2], (DxUint32_t *)(uintptr_t)args[3],
                                (CRYS_ECDH_TempData_t *)(uintptr_t)args[4]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_ECDSA_SIGN, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_ECDSA_SignUserContext_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_ECDSA_SignUserContext_t));
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ACCESS_READ_RIGHT_CHECK(args[1], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ACCESS_CHECK_A64(args[3], args[4]);
        ACCESS_READ_RIGHT_CHECK(args[3], args[4]);
        ACCESS_CHECK_A64(args[6], sizeof(DxUint32_t));
        ACCESS_WRITE_RIGHT_CHECK(args[6], sizeof(DxUint32_t));
        if (args[6]) {
            ACCESS_CHECK_A64(args[5], *(DxUint32_t *)(uintptr_t)args[6]);
            ACCESS_WRITE_RIGHT_CHECK(args[5], *(DxUint32_t *)(uintptr_t)args[6]);
        }
        ret = CRYS_ECDSA_Sign((CRYS_ECDSA_SignUserContext_t *)(uintptr_t)args[0],
                              (CRYS_ECPKI_UserPrivKey_t *)(uintptr_t)args[1],
                              (CRYS_ECPKI_HASH_OpMode_t)args[2], (DxUint8_t *)(uintptr_t)args[3], (DxUint32_t)args[4],
                              (DxUint8_t *)(uintptr_t)args[5], (DxUint32_t *)(uintptr_t)args[6]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_ECDSA_VERIFY, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_ECDSA_VerifyUserContext_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_ECDSA_VerifyUserContext_t));
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_READ_RIGHT_CHECK(args[1], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_CHECK_A64(args[3], args[4]);
        ACCESS_READ_RIGHT_CHECK(args[3], args[4]);
        ACCESS_CHECK_A64(args[5], args[6]);
        ACCESS_READ_RIGHT_CHECK(args[5], args[6]);
        ret = CRYS_ECDSA_Verify((CRYS_ECDSA_VerifyUserContext_t *)(uintptr_t)args[0],
                                (CRYS_ECPKI_UserPublKey_t *)(uintptr_t)args[1],
                                (CRYS_ECPKI_HASH_OpMode_t)args[2], (DxUint8_t *)(uintptr_t)args[3], (DxUint32_t)args[4],
                                (DxUint8_t *)(uintptr_t)args[5], (DxUint32_t)args[6]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_ECPKI_GENKEY_PAIR, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[1], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ACCESS_CHECK_A64(args[2], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[2], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_CHECK_A64(args[3], sizeof(CRYS_ECPKI_KG_TempData_t));
        ACCESS_READ_RIGHT_CHECK(args[3], sizeof(CRYS_ECPKI_KG_TempData_t));
        ret = CRYS_ECPKI_GenKeyPair((CRYS_ECPKI_DomainID_t)args[0], (CRYS_ECPKI_UserPrivKey_t *)(uintptr_t)args[1],
                                    (CRYS_ECPKI_UserPublKey_t *)(uintptr_t)args[2],
                                    (CRYS_ECPKI_KG_TempData_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END;

    default:
        return -1;
    }

    return 0;
}

DECLARE_TC_DRV(
    cc_syscall_init,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    cc_driver_syscall,
    NULL,
    NULL
);
