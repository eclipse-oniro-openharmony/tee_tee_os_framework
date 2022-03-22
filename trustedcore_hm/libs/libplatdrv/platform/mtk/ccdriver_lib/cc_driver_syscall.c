/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: cc driver syscall
 * Author: wangcong48@huawei.com
 * Create: 2019-12
 */
#include <stdint.h>
#include <errno.h>
#include <crypto_syscal_types.h>
#include "sre_syscalls_ext.h"
#include "sre_syscalls_id.h"
#include "sre_access_control.h"
#include "param_check.h"
#include "drv_module.h"
#include "cc_driver_stub.h"

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
#include <sep_ctx.h>

#include "crys_ecpki_types.h"
#include "crys_ecpki_build.h"
#include "crys_ecpki_ecdsa.h"
#include "crys_ecpki_dh.h"
#include "crys_ecpki_kg.h"
#include "crys_rsa_kg.h"
#include "tem_sasi.h"

static int aes_key_size(CRYS_AES_KeySize_t KeySizeID)
{
    switch (KeySizeID) {
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

int32_t cc_power_on(void)
{
    return 0;
}

int32_t cc_power_down(void)
{
    return 0;
}

/*
 * CODEREVIEW CHECKLIST
 * CALLER: platdrv_handle_message
 * ARG: regs: stack variable from platdrv_handle_message
 *        swi_id, ullPermissions always valid
 * RIGHTS: N/A
 * BUFOVF: N/A
 * LOG: N/A
 * RET: all error return for called functions are processed
 *        by unique caller platdrv_handle_message
 * RACING: N/A
 * LEAK: N/A
 * ARITHOVF: N/A
 * CODEREVIEW CHECKLIST by Wang Shiwei <wangshiwei5@huawei.com>
 */
int cc_driver_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t ret;
    if (params == NULL || params->args == 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    /* HMOS extended */
    char *data = (char *)(uintptr_t)params->data;
    char *rdata = (char *)(uintptr_t)params->rdata;
    size_t rdata_len = (size_t)params->rdata_len;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_CC_SECS_POWER_ON, permissions, CC_POWEROPER_GROUP_PERMISSION)
        ret = cc_power_on();
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_SECS_POWER_DOWN, permissions, CC_POWEROPER_GROUP_PERMISSION)
        ret = cc_power_down();
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_HMAC_INIT, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_HMACUserContext_t));
        ACCESS_CHECK_A64(args[2], args[3]);
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_HMACUserContext_t));
        ACCESS_READ_RIGHT_CHECK(args[2], args[3]);
        ret = CRYS_HMAC_Init((CRYS_HMACUserContext_t *)(uintptr_t)args[0], (CRYS_HASH_OperationMode_t)args[1],
                             (DxUint8_t *)(uintptr_t)args[2], (DxUint16_t)args[3]);
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_HMAC_UPDATE, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_HMACUserContext_t));
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_HMACUserContext_t));
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ret = CRYS_HMAC_Update((CRYS_HMACUserContext_t *)(uintptr_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                               (DxUint32_t)args[2]);
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_HMAC_FINISH, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_HMACUserContext_t));
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_HASH_Result_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_HMACUserContext_t));
        ACCESS_WRITE_RIGHT_CHECK(args[1], sizeof(CRYS_HASH_Result_t));
        ret = CRYS_HMAC_Finish((CRYS_HMACUserContext_t *)(uintptr_t)args[0], (DxUint32_t *)(uintptr_t)args[1]);
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_HMAC_FREE, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_HMACUserContext_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_HMACUserContext_t));
        ret = CRYS_HMAC_Free((CRYS_HMACUserContext_t *)(uintptr_t)args[0]);
        args[0] = ret;
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_DES_FREE, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_DESUserContext_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(CRYS_DESUserContext_t));
        ret = CRYS_DES_Free((CRYS_DESUserContext_t *)(uintptr_t)args[0]);
        args[0] = ret;
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

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
            ret = crys_aes_is_mac_mode((CRYS_AESUserContext_t *)(uintptr_t)args[0], &mac_mode);
            if (ret != 0) {
                args[0] = ret;
                goto out;
            }
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
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_DX_UTIL_CMACDERIVEKEY, permissions, CC_KEY_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], sizeof(DX_UTIL_AES_CmacResult_t));
        ACCESS_WRITE_RIGHT_CHECK(args[3], sizeof(DX_UTIL_AES_CmacResult_t));
        ret = DX_UTIL_CmacDeriveKey((DX_UTIL_KeyType_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                                    (DxUint32_t)args[2], (DxUint8_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RND_GENERATEVECTOR, permissions, CC_RNG_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[0]);
        ACCESS_WRITE_RIGHT_CHECK(args[1], args[0]);
        ret = CRYS_RND_GenerateVector((DxUint16_t)args[0], (DxUint8_t *)(uintptr_t)args[1]);
        args[0] = ret;
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RSA_BUILD_PRIVKEYCRT, permissions, CC_CRYPTO_GROUP_PERMISSION)
        if (args[6] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[6], sizeof(struct private_key_crt_size_t));
        ACCESS_READ_RIGHT_CHECK(args[6], sizeof(struct private_key_crt_size_t));
        struct private_key_crt_size_t *all_size_ptr = (struct private_key_crt_size_t*)(uintptr_t)args[6];
        uint32_t PSize = all_size_ptr->p_size;
        uint32_t QSize = all_size_ptr->q_size;
        uint32_t dPSize = all_size_ptr->dp_size;
        uint32_t dQSize = all_size_ptr->dq_size;
        uint32_t qInvSize = all_size_ptr->q_inv_size;
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
        ACCESS_CHECK_A64(args[1], PSize);
        ACCESS_READ_RIGHT_CHECK(args[1], PSize);
        if (args[2] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[2], QSize);
        ACCESS_READ_RIGHT_CHECK(args[2], QSize);
        if (args[3] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[3], dPSize);
        ACCESS_READ_RIGHT_CHECK(args[3], dPSize);
        if (args[4] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[4], dQSize);
        ACCESS_READ_RIGHT_CHECK(args[4], dQSize);
        if (args[5] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[5], qInvSize);
        ACCESS_READ_RIGHT_CHECK(args[5], qInvSize);
        ret = CRYS_RSA_Build_PrivKeyCRT(
            (CRYS_RSAUserPrivKey_t *)(uintptr_t)args[0], (DxUint8_t *)(uintptr_t)args[1], (DxUint16_t)PSize,
            (DxUint8_t *)(uintptr_t)args[2], (DxUint16_t)QSize, (DxUint8_t *)(uintptr_t)args[3], (DxUint16_t)dPSize,
            (DxUint8_t *)(uintptr_t)args[4], (DxUint16_t)dQSize, (DxUint8_t *)(uintptr_t)args[5],
            (DxUint16_t)qInvSize);
        args[0] = ret;
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

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
        CRYSRSAPubKey_t *PubKey_ptr = (CRYSRSAPubKey_t *)tmp_ptr->PublicKeyDbBuff;
        uint16_t output_size = ((uint16_t)PubKey_ptr->nSizeInBits + 7) / 8;
        ACCESS_CHECK_A64(args[8], output_size);
        ACCESS_WRITE_RIGHT_CHECK(args[8], output_size);
        ret = _DX_RSA_SCHEMES_Encrypt(
            (CRYS_RSAUserPubKey_t *)(uintptr_t)args[0], (CRYS_RSAPrimeData_t *)(uintptr_t)args[1],
            (CRYS_RSA_HASH_OpMode_t)args[2], (DxUint8_t *)(uintptr_t)args[3], (DxUint16_t)args[4],
            (CRYS_PKCS1_MGF_t)args[5], (DxUint8_t *)(uintptr_t)args[6], (DxUint16_t)args[7],
            (DxUint8_t *)(uintptr_t)args[8], (CRYS_PKCS1_version)args[9]);
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC__DX_RSA_SCHEMES_DECRYPT, permissions, CC_CRYPTO_GROUP_PERMISSION)
        if (args[6] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[6], sizeof(struct decrypt_wraper_t));
        ACCESS_READ_RIGHT_CHECK(args[6], sizeof(struct decrypt_wraper_t));
        struct decrypt_wraper_t *param_wraper = (struct decrypt_wraper_t*)(uintptr_t)args[6];
        uint32_t hashFunc = param_wraper->hash_func;
        uint32_t Llen = param_wraper->l_len;
        uint32_t MGF = param_wraper->mgf;
        uint32_t DataInSize = param_wraper->data_in_size;
        uint32_t PKCS1_ver = param_wraper->pkcs1_ver;
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

        bool check = (!args[2] && (Llen == 0));
        if (!check) {
            if (args[2] == 0) {
                args[0] = OS_ERROR;
                goto out;
            }
            ACCESS_CHECK_A64(args[2], Llen);
            ACCESS_READ_RIGHT_CHECK(args[2], Llen);
        }
        if (args[3] == 0) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[3], DataInSize);
        ACCESS_READ_RIGHT_CHECK(args[3], DataInSize);
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
            (CRYS_RSA_HASH_OpMode_t)hashFunc, (DxUint8_t *)(uintptr_t)args[2], (DxUint16_t)Llen,
            (CRYS_PKCS1_MGF_t)MGF, (DxUint8_t *)(uintptr_t)args[3], (DxUint16_t)DataInSize,
            (DxUint8_t *)(uintptr_t)args[4], (DxUint16_t *)(uintptr_t)args[5], (CRYS_PKCS1_version)PKCS1_ver);
        args[0] = ret;
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

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
        CRYSRSAPubKey_t *PubKey_ptr = (CRYSRSAPubKey_t *)((CRYS_RSAUserPubKey_t *)(uintptr_t)args[0])->PublicKeyDbBuff;
        uint16_t output_size = ((uint16_t)PubKey_ptr->nSizeInBits + 7)/8;
        ACCESS_CHECK_A64(args[4], output_size);
        ACCESS_WRITE_RIGHT_CHECK(args[4], output_size);
        ret = CRYS_RSA_PRIM_Encrypt((CRYS_RSAUserPubKey_t *)(uintptr_t)args[0],
                                    (CRYS_RSAPrimeData_t *)(uintptr_t)args[1],
                                    (DxUint8_t *)(uintptr_t)args[2], (DxUint16_t)args[3],
                                    (DxUint8_t *)(uintptr_t)args[4]);
        args[0] = ret;
        SYSCALL_END_DMA;

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
        CRYSRSAPrivKey_t *PrivKey_ptr =
            (CRYSRSAPrivKey_t *)((CRYS_RSAUserPrivKey_t *)(uintptr_t)args[0])->PrivateKeyDbBuff;
        uint16_t output_size = ((uint16_t)PrivKey_ptr->nSizeInBits + 7) / 8;
        ACCESS_CHECK_A64(args[4], output_size);
        ACCESS_WRITE_RIGHT_CHECK(args[4], output_size);
        ret = CRYS_RSA_PRIM_Decrypt((CRYS_RSAUserPrivKey_t *)(uintptr_t)args[0],
                                    (CRYS_RSAPrimeData_t *)(uintptr_t)args[1],
                                    (DxUint8_t *)(uintptr_t)args[2], (DxUint16_t)args[3],
                                    (DxUint8_t *)(uintptr_t)args[4]);
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_ECPKI_BUILD_PUBLKEY, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[3], sizeof(CRYS_ECPKI_UserPublKey_t));
        ret = CRYS_ECPKI_BuildPublKey((CRYS_ECPKI_DomainID_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                                      (DxUint32_t)args[2], (CRYS_ECPKI_UserPublKey_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_ECPKI_BUILD_PRIVKEY, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[3], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ret = CRYS_ECPKI_BuildPrivKey((CRYS_ECPKI_DomainID_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                                      (DxUint32_t)args[2], (CRYS_ECPKI_UserPrivKey_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

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
        SYSCALL_END_DMA;

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
