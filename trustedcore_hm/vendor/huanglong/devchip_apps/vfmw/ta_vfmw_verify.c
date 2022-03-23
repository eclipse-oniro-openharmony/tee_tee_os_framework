/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: decoder
 * Author: sdk
 * Create: 2019-06-06
 */

#include "hi_tee_klad.h"
#include "hi_tee_cipher.h"
#include "hi_tee_mem.h"
#include "hi_tee_ssm.h"
#include "tee_drv_vfmw_ioctl.h"
#include "hi_tee_drv_syscall_id.h"
#include "ta_vfmw_verify.h"

static hi_u8 g_sm2_id[VFMW_SG_SM2_ID_LEN] = {"\x31\x32\x33\x34\x35\x36\x37\x38\x31\x32\x33\x34\x35\x36\x37\x38"};
static hi_handle g_klad_handle = HI_INVALID_HANDLE;
static hi_handle g_cipher_handle = HI_INVALID_HANDLE;

static hi_s32 vfmw_verify_decrypt_process(hi_mem_handle_t fd, hi_mem_size_t addr_offset, hi_u32 size)
{
    hi_s32 ret;
    hi_tee_ssm_buffer_attach_info attach_info = {0};
    hi_u64 sec_info_addr;
    hi_mem_handle fw_mem_handle;

    fw_mem_handle.mem_handle = fd;
    fw_mem_handle.addr_offset = addr_offset;

    attach_info.session_handle = HI_INVALID_HANDLE;
    attach_info.buf_id        = BUFFER_ID_INTERNAL_BUF_MCIPHER;
    attach_info.buf_smmu_handle = fw_mem_handle.mem_handle;
    attach_info.buf_len       = size;
    attach_info.module_handle = g_cipher_handle;

    ret = hi_tee_ssm_attach_buffer(&attach_info, &sec_info_addr);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("hi_tee_ssm_attach_buffer error 0x%x", ret);
        return HI_FAILURE;
    }

    ret = hi_tee_cipher_decrypt(g_cipher_handle, fw_mem_handle, fw_mem_handle, size, HI_TEE_CIPHER_DATA_DIR_TEE2TEE);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("hi_tee_cipher_decrypt error 0x%x", ret);
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

static hi_s32 vfmw_verify_config_cipher_attr(hi_u32 decrypt_alg)
{
    hi_tee_cipher_config cipher_ctrl;
    hi_tee_cipher_config_aes  aes_cbc;
    hi_tee_cipher_config_sm4 sm4_cbc;
    hi_tee_cipher_config_aes_ccm_gcm aes_gcm;
    hi_s32 ret;

    ta_vfmw_check_sec_func(memset_s(&cipher_ctrl, sizeof(hi_tee_cipher_config), 0, sizeof(hi_tee_cipher_config)));
    ta_vfmw_check_sec_func(memset_s(&aes_cbc, sizeof(hi_tee_cipher_config_aes), 0, sizeof(hi_tee_cipher_config_aes)));
    ta_vfmw_check_sec_func(memset_s(&sm4_cbc, sizeof(hi_tee_cipher_config_sm4), 0, sizeof(hi_tee_cipher_config_sm4)));
    ta_vfmw_check_sec_func(memset_s(&aes_gcm, sizeof(hi_tee_cipher_config_aes_ccm_gcm), 0,
        sizeof(hi_tee_cipher_config_aes_ccm_gcm)));

    switch (decrypt_alg) {
        case VFMW_SG_DECRYPT_AES_CBC: {
            cipher_ctrl.alg = HI_TEE_CIPHER_ALG_AES;
            cipher_ctrl.work_mode   = HI_TEE_CIPHER_WORK_MODE_CBC;
            cipher_ctrl.param = &aes_cbc;
            aes_cbc.bit_width   = HI_TEE_CIPHER_BIT_WIDTH_128BIT;
            aes_cbc.key_len     = HI_TEE_CIPHER_KEY_AES_128BIT;
            aes_cbc.change_flags.iv_change_flag = 1;
            break;
        }
        case VFMW_SG_DECRYPT_SM4_CBC: {
            cipher_ctrl.alg = HI_TEE_CIPHER_ALG_SM4;
            cipher_ctrl.work_mode   = HI_TEE_CIPHER_WORK_MODE_CBC;
            cipher_ctrl.param = &sm4_cbc;
            sm4_cbc.change_flags.iv_change_flag = 1;
            break;
        }
        case VFMW_SG_DECRYPT_AES_GCM: {
            cipher_ctrl.alg = HI_TEE_CIPHER_ALG_AES;
            cipher_ctrl.work_mode   = HI_TEE_CIPHER_WORK_MODE_GCM;
            cipher_ctrl.param = &aes_gcm;
            aes_gcm.key_len = HI_TEE_CIPHER_KEY_AES_128BIT;
            aes_gcm.iv_len = VFMW_SG_IV_LEN;
            break;
        }
        default: {
            ta_vfmw_prn("** not supported decrypt alg in cipher ! **");
            return HI_FAILURE;
        }
    }

    ret = hi_tee_cipher_set_config(g_cipher_handle, &cipher_ctrl);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("hi_tee_cipher_set_config error 0x%x", ret);
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

static hi_s32 vfmw_verify_config_klad_attr(hi_u32 decrypt_alg, hi_u32 key_type)
{
    hi_tee_klad_attr klad_attr = {0};
    hi_s32 ret;

    HI_UNUSED(key_type);

    klad_attr.klad_cfg.klad_type = HI_TEE_KLAD_TYPE_VMCU;
    klad_attr.klad_cfg.owner_id = 0x0F000000; /* */
    klad_attr.key_cfg.decrypt_support = HI_TRUE;
    klad_attr.key_cfg.encrypt_support = HI_FALSE;
    klad_attr.key_sec_cfg.dest_buf_sec_support = HI_TRUE;
    klad_attr.key_sec_cfg.src_buf_sec_support = HI_TRUE;
    klad_attr.key_sec_cfg.dest_buf_non_sec_support = HI_FALSE;
    klad_attr.key_sec_cfg.src_buf_non_sec_support = HI_FALSE;
    klad_attr.key_sec_cfg.key_sec = HI_TEE_KLAD_SEC_ENABLE;

    if (decrypt_alg == VFMW_SG_DECRYPT_AES_CBC) {
        klad_attr.key_cfg.engine = HI_TEE_CRYPTO_ALG_RAW_AES;
    } else if (decrypt_alg == VFMW_SG_DECRYPT_SM4_CBC) {
        klad_attr.key_cfg.engine = HI_TEE_CRYPTO_ALG_RAW_SM4;
    } else if (decrypt_alg == VFMW_SG_DECRYPT_AES_GCM) {
        klad_attr.key_cfg.engine = HI_TEE_CRYPTO_ALG_RAW_AES;
    } else {
        ta_vfmw_prn("** not supported klad_attr.key_cfg.engine ");
        return HI_FAILURE;
    }
    ret = hi_tee_klad_set_attr(g_klad_handle, &klad_attr);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("hi_tee_klad_set_attr error 0x%x", ret);
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

static hi_s32 vfmw_verify_set_klad_cipher_handle(hi_u32 decrypt_alg, hi_u32 key_type)
{
    hi_handle handle_ks;
    hi_s32 ret;

    ret = vfmw_verify_config_klad_attr(decrypt_alg, key_type);
    ta_vfmw_check_ret(ret == HI_SUCCESS, HI_FAILURE);

    ret = hi_tee_cipher_get_keyslot_handle(g_cipher_handle, &handle_ks);
    ta_vfmw_check_ret(ret == HI_SUCCESS, HI_FAILURE);

    ret = hi_tee_klad_attach(g_klad_handle, handle_ks);
    ta_vfmw_check_ret(ret == HI_SUCCESS, HI_FAILURE);

    return HI_SUCCESS;
}

static hi_s32 vfmw_verify_decrypt_config(const hi_u8 *protect_key, hi_u32 decrypt_alg)
{
    hi_tee_klad_content_key content_key = {0};
    hi_s32 ret;
    hi_u32 key_type;

    ta_vfmw_check_ret(protect_key != HI_NULL, HI_FAILURE);

    ret = vfmw_verify_set_klad_cipher_handle(decrypt_alg, key_type);
    ta_vfmw_check_ret(ret == HI_SUCCESS, HI_FAILURE);

    ret = memcpy_s(content_key.key, sizeof(content_key.key), protect_key, VFMW_SG_PROTECT_KEY_LEN);
    if (ret != EOK) {
        ta_vfmw_prn("memcpy_s fail ret %d", ret);
        ta_vfmw_check_func(hi_tee_klad_detach(g_klad_handle, g_cipher_handle));
        return HI_FAILURE;
    }

    if (decrypt_alg == VFMW_SG_DECRYPT_AES_CBC) {
        content_key.alg = HI_TEE_KLAD_ALG_TYPE_AES;
    } else if (decrypt_alg == VFMW_SG_DECRYPT_SM4_CBC) {
        content_key.alg = HI_TEE_KLAD_ALG_TYPE_SM4;
    } else if (decrypt_alg == VFMW_SG_DECRYPT_AES_GCM) {
        content_key.alg = HI_TEE_KLAD_ALG_TYPE_AES;
    } else {
        ta_vfmw_prn("** not supported decrypt alg %d", decrypt_alg);
        ta_vfmw_check_func(hi_tee_klad_detach(g_klad_handle, g_cipher_handle));
        return HI_FAILURE;
    }

    content_key.key_size = VFMW_SG_PROTECT_KEY_LEN;
    ret = hi_tee_klad_set_content_key(g_klad_handle, &content_key);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("hi_tee_klad_set_content_key fail ret 0x%x", ret);
        ta_vfmw_check_func(hi_tee_klad_detach(g_klad_handle, g_cipher_handle));
        return HI_FAILURE;
    }

    ret = vfmw_verify_config_cipher_attr(decrypt_alg);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("vfmw_config_cipher_attr fail  ret %d", ret);
        ta_vfmw_check_func(hi_tee_klad_detach(g_klad_handle, g_cipher_handle));
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_s32 vfmw_verify_decrypt(vfmw_sign_head *fw_head, hi_mem_handle_t mem_fd, hi_mem_size_t addr_offset)
{
    hi_s32 ret;

    ta_vfmw_check_ret(fw_head != HI_NULL, HI_FAILURE);

    ret = vfmw_verify_decrypt_config(fw_head->revocation_protection_key, fw_head->sym_algorithm);
    ta_vfmw_check_ret(ret == HI_SUCCESS, HI_FAILURE);

    ret = vfmw_verify_decrypt_process(mem_fd, addr_offset, fw_head->signed_image_len);
    ta_vfmw_check_ret(ret == HI_SUCCESS, HI_FAILURE);

    return HI_SUCCESS;
}

static hi_s32 vfmw_verify_rsa(hi_u8 *buffer, hi_u32 size, hi_u8 *signature,
    hi_u32 signature_size, vfmw_rsa_key *rsa_key)
{
    hi_tee_cipher_rsa_verify_param rsa_verify = {0};
    hi_s32 ret;
    hi_tee_cipher_rsa_sign_verify_data rsa_verify_data = {0};

    ta_vfmw_check_ret(buffer != HI_NULL, HI_FAILURE);
    ta_vfmw_check_ret(signature != HI_NULL, HI_FAILURE);
    ta_vfmw_check_ret(rsa_key != HI_NULL, HI_FAILURE);
    ta_vfmw_check_ret(size != 0, HI_FAILURE);
    ta_vfmw_check_ret(signature_size != 0, HI_FAILURE);

    rsa_verify.pub_key.e    = (hi_u8 *)rsa_key->rsa_key_e;
    rsa_verify.pub_key.n    = (hi_u8 *)rsa_key->rsa_key_n;
    rsa_verify.pub_key.e_len = VFMW_SG_RSA_PUBLIC_KEY_E_LEN;
    rsa_verify.pub_key.n_len = VFMW_SG_RSA_PUBLIC_KEY_N_LEN;
    rsa_verify.sign_scheme   = HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA256;

    rsa_verify_data.input = buffer;
    rsa_verify_data.input_len = size;
    rsa_verify_data.hash_data = HI_NULL;
    rsa_verify_data.sign = signature;
    rsa_verify_data.sign_len = &signature_size;
    ret = hi_tee_cipher_rsa_verify(&rsa_verify, &rsa_verify_data);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("hi_tee_cipher_rsa_verify error 0x%x", ret);
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

static hi_s32 vfmw_verify_sm2(hi_u8 *buffer, hi_u32 buffer_size, hi_u8 *signature,
    hi_u32 signature_size, const hi_u8 *public_key_ptr)
{
    hi_tee_cipher_sm2_verify_param sm2_verify_param = {0};
    hi_s32 ret;
    hi_tee_cipher_sm2_sign_verify_data sm2_verify_data = {0};

    HI_UNUSED(signature_size);

    ret = memcpy_s(sm2_verify_param.px, sizeof(sm2_verify_param.px), public_key_ptr, HI_TEE_CIPHER_SM2_LEN_IN_BYTE);
    if (ret != EOK) {
        ta_vfmw_prn("vfmw_verify_sm2 error 0x%x", ret);
        return HI_FAILURE;
    }
    ret = memcpy_s(sm2_verify_param.py, sizeof(sm2_verify_param.py),
                   public_key_ptr + HI_TEE_CIPHER_SM2_LEN_IN_BYTE, HI_TEE_CIPHER_SM2_LEN_IN_BYTE);
    if (ret != EOK) {
        ta_vfmw_prn("vfmw_verify_sm2 error 0x%x", ret);
        return HI_FAILURE;
    }
    sm2_verify_param.id = g_sm2_id;
    sm2_verify_param.id_len = VFMW_SG_SM2_ID_LEN;
    sm2_verify_data.msg = buffer;
    sm2_verify_data.msg_len = buffer_size;
    sm2_verify_data.sign_r = signature;
    sm2_verify_data.sign_s = signature + VFMW_SG_WORD_LEN;
    sm2_verify_data.sign_buf_len = HI_TEE_CIPHER_SM2_LEN_IN_BYTE;
    ret = hi_tee_cipher_sm2_verify(&sm2_verify_param, &sm2_verify_data);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("hi_tee_cipher_sm2_verify error 0x%x", ret);
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_s32 vfmw_verify_signature(vfmw_verify *verify_info)
{
    hi_s32 ret;

    ta_vfmw_check_ret(verify_info != HI_NULL, HI_FAILURE);
    ta_vfmw_check_ret(verify_info->verify_data != HI_NULL, HI_FAILURE);
    ta_vfmw_check_ret(verify_info->signature_data != HI_NULL, HI_FAILURE);
    ta_vfmw_check_ret(verify_info->signature_data_len != 0, HI_FAILURE);
    ta_vfmw_check_ret(verify_info->verify_data_len != 0, HI_FAILURE);

    if (verify_info->asym_alg == VFMW_SG_SM2) {
        ret = vfmw_verify_sm2(verify_info->verify_data, verify_info->verify_data_len,
            verify_info->signature_data, verify_info->signature_data_len,
            verify_info->rsa_key.rsa_key_n);
        if (ret != HI_SUCCESS) {
            ta_vfmw_prn("vfmw_verify_sm2 error 0x%x", ret);
            return HI_FAILURE;
        }
    } else if (verify_info->asym_alg == VFMW_SG_RSA2048) {
        ret = vfmw_verify_rsa(verify_info->verify_data, verify_info->verify_data_len,
            verify_info->signature_data, verify_info->signature_data_len,
            &verify_info->rsa_key);
        if (ret != HI_SUCCESS) {
            ta_vfmw_prn("vfmw_verify_rsa error 0x%x", ret);
            return HI_FAILURE;
        }
    } else {
        ta_vfmw_prn("asym_alg fail \n ");
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_s32 vfmw_verify_init(hi_void)
{
    hi_tee_cipher_attr cipher_attr = {0};
    hi_s32 ret;

    ret = hi_tee_cipher_init();
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("hi_tee_cipher_init error 0x%x", ret);
        return HI_FAILURE;
    }

    ret = hi_tee_klad_init();
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("hi_tee_klad_init error 0x%x", ret);
        ta_vfmw_check_func(hi_tee_cipher_deinit());
        return HI_FAILURE;
    }

    ret = hi_tee_klad_create(&g_klad_handle);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("hi_tee_klad_create error 0x%x", ret);
        ta_vfmw_check_func(hi_tee_klad_deinit());
        ta_vfmw_check_func(hi_tee_cipher_deinit());
        return HI_FAILURE;
    }

    cipher_attr.cipher_type = HI_TEE_CIPHER_TYPE_NORMAL;
    cipher_attr.is_create_keyslot = HI_TRUE;
    ret = hi_tee_cipher_create(&g_cipher_handle, &cipher_attr);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("hi_tee_cipher_create error 0x%x", ret);
        ta_vfmw_check_func(hi_tee_klad_destroy(g_klad_handle));
        g_klad_handle = HI_INVALID_HANDLE;
        ta_vfmw_check_func(hi_tee_klad_deinit());
        ta_vfmw_check_func(hi_tee_cipher_deinit());
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_void vfmw_verify_deinit(hi_void)
{
    ta_vfmw_check_func(hi_tee_klad_destroy(g_klad_handle));
    g_klad_handle = HI_INVALID_HANDLE;

    ta_vfmw_check_func(hi_tee_cipher_destroy(g_cipher_handle));
    g_cipher_handle = HI_INVALID_HANDLE;

    ta_vfmw_check_func(hi_tee_klad_deinit());
    ta_vfmw_check_func(hi_tee_cipher_deinit());

    return;
}

