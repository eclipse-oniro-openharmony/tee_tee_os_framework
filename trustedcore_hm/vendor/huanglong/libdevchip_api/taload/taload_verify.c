/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: decrypt and verify function
 * Author: BSP group
 * Create: 2020-01-17
 */
#include "taload_verify.h"
#include "hi_tee_klad.h"
#include "hi_tee_cipher.h"
#include "hi_tee_mem.h"
#include "hi_tee_ssm.h"
#include "hi_tee_errcode.h"
#include "hi_log.h"
#include "securec.h"

hi_u8 g_sm2_id[TALOAD_SM2_ID_LEN] = {"\x31\x32\x33\x34\x35\x36\x37\x38\x31\x32\x33\x34\x35\x36\x37\x38"};
typedef struct {
    hi_u8 *buffer;
    hi_u32 buffer_size;
    hi_u8 *signature;
    hi_u32 signature_size;
    hi_u8 *public_key_ptr;
    hi_u32 public_key_len;
} sm2_verify;

static hi_handle g_klad_handle = HI_INVALID_HANDLE;
static hi_handle g_cipher_handle = HI_INVALID_HANDLE;
static hi_handle g_ssm_handle = HI_INVALID_HANDLE;

static hi_s32 cipher_ssm_init(const hi_u32 *ssm_handle, hi_handle cipher_handle)
{
    hi_s32 ret;
    hi_tee_ssm_module_info res_handle;

    ret = hi_tee_ssm_create(HI_TEE_SSM_INTENT_WATCH, (hi_u32 *)ssm_handle);
    if (ret != HI_SUCCESS) {
        hi_log_err("hi_tee_ssm_create failed, ret:%x\n", ret);
        return ret;
    }
    res_handle.module_handle = cipher_handle;
    ret = hi_tee_ssm_add_resource(*ssm_handle, &res_handle);
    if (ret != HI_SUCCESS) {
        hi_log_err("hi_tee_ssm_add_resource failed, ret:%x\n", ret);
        hi_tee_ssm_destroy(*ssm_handle);
        return ret;
    }

    return HI_SUCCESS;
}

static void cipher_ssm_deinit(void)
{
    hi_s32 ret;

    if (g_ssm_handle == HI_INVALID_HANDLE) {
        return;
    }
    ret = hi_tee_ssm_destroy(g_ssm_handle);
    if (ret != HI_SUCCESS) {
        hi_log_err("hi_tee_ssm_destroy failed ret:0x%x\n", ret);
    }

    return;
}

static hi_s32 taload_decrypt_process(hi_handle handle, hi_u8 *buffer, hi_u32 size)
{
    void *vir_addr = HI_NULL_PTR;
    hi_tee_ssm_buffer_attach_info attach_info;
    hi_u64 sec_info_addr;
    hi_s32 ret;
    hi_mem_handle mem_handle;

    hi_dbg_func_enter();
    ret = hi_tee_mmz_alloc_and_map("taload_in", size, &vir_addr, &(mem_handle.mem_handle));
    if (ret != HI_SUCCESS || vir_addr == HI_NULL_PTR) {
        hi_err_print_call_fun_err(hi_tee_mmz_alloc_and_map, HI_FAILURE);
        return HI_TEE_ERR_MEM;
    }
    attach_info.session_handle = g_ssm_handle;
    attach_info.buf_id        = BUFFER_ID_INTERNAL_BUF_MCIPHER;
    attach_info.buf_smmu_handle = mem_handle.mem_handle;
    attach_info.buf_len       = size;
    attach_info.module_handle = g_cipher_handle;
    mem_handle.addr_offset = 0;
    ret = hi_tee_ssm_attach_buffer(&attach_info, &sec_info_addr);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_ssm_attach_buffer, ret);
        hi_tee_mmz_unmap_and_free(vir_addr, mem_handle.mem_handle);
        return ret;
    }

    ret = memcpy_s(vir_addr, size, buffer, size);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        hi_check_result(hi_tee_mmz_unmap_and_free(vir_addr, mem_handle.mem_handle));
        return HI_TEE_ERR_MEM;
    }
    ret = hi_tee_cipher_decrypt(g_cipher_handle, mem_handle, mem_handle, size, HI_TEE_CIPHER_DATA_DIR_TEE2TEE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_cipher_decrypt, ret);
        goto exit;
    }

    ret = memcpy_s(buffer, size, vir_addr, size);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        goto exit;
    }
exit:
    hi_check_result(hi_tee_mmz_unmap_and_free(vir_addr, mem_handle.mem_handle));
    hi_dbg_func_exit();

    return ret;
}

static hi_s32 taload_config_cipher_attr(hi_u32 decrypt_alg)
{
    hi_tee_cipher_config cipher_ctrl;
    hi_tee_cipher_config_aes  aes_cbc;
    hi_tee_cipher_config_sm4 sm4_cbc;
    hi_tee_cipher_config_aes_ccm_gcm aes_gcm;
    hi_s32 ret;

    memset_s(&cipher_ctrl, sizeof(hi_tee_cipher_config), 0, sizeof(hi_tee_cipher_config));
    memset_s(&aes_cbc, sizeof(hi_tee_cipher_config_aes), 0, sizeof(hi_tee_cipher_config_aes));
    memset_s(&sm4_cbc, sizeof(hi_tee_cipher_config_sm4), 0, sizeof(hi_tee_cipher_config_sm4));
    memset_s(&aes_gcm, sizeof(hi_tee_cipher_config_aes_ccm_gcm), 0, sizeof(hi_tee_cipher_config_aes_ccm_gcm));

    switch (decrypt_alg) {
        case TALOAD_TA_DECRYPT_AES_CBC: {
            cipher_ctrl.alg = HI_TEE_CIPHER_ALG_AES;
            cipher_ctrl.work_mode   = HI_TEE_CIPHER_WORK_MODE_CBC;
            cipher_ctrl.param = &aes_cbc;
            aes_cbc.bit_width   = HI_TEE_CIPHER_BIT_WIDTH_128BIT;
            aes_cbc.key_len     = HI_TEE_CIPHER_KEY_AES_128BIT;
            aes_cbc.change_flags.iv_change_flag = 1;
            break;
        }
        case TALOAD_TA_DECRYPT_SM4_CBC: {
            cipher_ctrl.alg = HI_TEE_CIPHER_ALG_SM4;
            cipher_ctrl.work_mode   = HI_TEE_CIPHER_WORK_MODE_CBC;
            cipher_ctrl.param = &sm4_cbc;
            sm4_cbc.change_flags.iv_change_flag = 1;
            break;
        }
        case TALOAD_TA_DECRYPT_AES_GCM: {
            cipher_ctrl.alg = HI_TEE_CIPHER_ALG_AES;
            cipher_ctrl.work_mode   = HI_TEE_CIPHER_WORK_MODE_GCM;
            cipher_ctrl.param = &aes_gcm;
            aes_gcm.key_len = HI_TEE_CIPHER_KEY_AES_128BIT;
            aes_gcm.iv_len = TALOAD_TA_IV_LEN;
            break;
        }
        default: {
            hi_log_warn("** not supported decrypt alg in cipher ! **");
            return HI_TEE_ERR_UNSUPPORTED;
        }
    }

    ret = hi_tee_cipher_set_config(g_cipher_handle, &cipher_ctrl);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_cipher_set_config, ret);
        return HI_TEE_ERR_EXTERNAL;
    }

    return HI_SUCCESS;
}

static hi_s32 taload_config_klad_attr(hi_u32 decrypt_alg, hi_u32 key_type, hi_u32 ta_owner_id)
{
    hi_tee_klad_attr klad_attr;
    hi_s32 ret;

    hi_dbg_func_enter();

    if (key_type == TALOAD_TA_KLAD_TYPE_CATA) {
        klad_attr.klad_cfg.klad_type = HI_TEE_KLAD_TYPE_CA_TA;
    } else if (key_type == TALOAD_TA_KLAD_TYPE_HISITA) {
        klad_attr.klad_cfg.klad_type = HI_TEE_KLAD_TYPE_HISI_TA;
    } else if (key_type == TALOAD_TA_KLAD_TYPE_STBTA) {
        klad_attr.klad_cfg.klad_type = HI_TEE_KLAD_TYPE_OEM_TA;
    } else {
        hi_log_warn("** not supported keyladder type ! **");
        return HI_TEE_ERR_UNSUPPORTED;
    }

    klad_attr.klad_cfg.owner_id = ta_owner_id;
    klad_attr.key_cfg.decrypt_support = HI_TRUE;
    klad_attr.key_cfg.encrypt_support = HI_FALSE;
    klad_attr.key_sec_cfg.dest_buf_sec_support = HI_TRUE;
    klad_attr.key_sec_cfg.src_buf_sec_support = HI_TRUE;
    klad_attr.key_sec_cfg.dest_buf_non_sec_support = HI_FALSE;
    klad_attr.key_sec_cfg.src_buf_non_sec_support = HI_FALSE;
    klad_attr.key_sec_cfg.key_sec = HI_TEE_KLAD_SEC_ENABLE;

    if (decrypt_alg == TALOAD_TA_DECRYPT_AES_CBC) {
        klad_attr.key_cfg.engine = HI_TEE_CRYPTO_ALG_RAW_AES;
    } else if (decrypt_alg == TALOAD_TA_DECRYPT_SM4_CBC) {
        klad_attr.key_cfg.engine = HI_TEE_CRYPTO_ALG_RAW_SM4;
    } else if (decrypt_alg == TALOAD_TA_DECRYPT_AES_GCM) {
        klad_attr.key_cfg.engine = HI_TEE_CRYPTO_ALG_RAW_AES;
    } else {
        hi_log_warn("** not supported klad_attr.key_cfg.engine ! **");
        return HI_TEE_ERR_UNSUPPORTED;
    }
    ret = hi_tee_klad_set_attr(g_klad_handle, &klad_attr);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_klad_set_attr, ret);
        return HI_TEE_ERR_EXTERNAL;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

static hi_s32 taload_set_klad_cipher_handle(hi_u32 decrypt_alg, hi_u32 key_type, hi_u32 ta_owner_id)
{
    hi_handle handle_ks;
    hi_s32 ret;

    ret = taload_config_klad_attr(decrypt_alg, key_type, ta_owner_id);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_config_klad_attr, ret);
        return ret;
    }

    ret = hi_tee_cipher_get_keyslot_handle(g_cipher_handle, &handle_ks);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_cipher_get_keyslot_handle, ret);
        return ret;
    }

    ret = hi_tee_klad_attach(g_klad_handle, handle_ks);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_klad_attach, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 taload_decrypt_config(const decrypt_param *param)
{
    hi_tee_klad_content_key content_key;
    hi_s32 ret;

    ret = taload_set_klad_cipher_handle(param->decrypt_alg, param->root_key_cfg, param->ta_owner_id);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_set_klad_cipher_handle, ret);
        return ret;
    }

    ret = memcpy_s(content_key.key, TALOAD_PROTECT_KEY_LEN, param->protect_key, TALOAD_PROTECT_KEY_LEN);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        hi_check_result(hi_tee_klad_detach(g_klad_handle, g_cipher_handle));
        return HI_TEE_ERR_MEM;
    }

    if (param->decrypt_alg == TALOAD_TA_DECRYPT_AES_CBC) {
        content_key.alg = HI_TEE_KLAD_ALG_TYPE_AES;
    } else if (param->decrypt_alg == TALOAD_TA_DECRYPT_SM4_CBC) {
        content_key.alg = HI_TEE_KLAD_ALG_TYPE_SM4;
    } else if (param->decrypt_alg == TALOAD_TA_DECRYPT_AES_GCM) {
        content_key.alg = HI_TEE_KLAD_ALG_TYPE_AES;
    } else {
        hi_log_err("** not supported decrypt alg ! **");
        return HI_TEE_ERR_UNSUPPORTED;
    }

    content_key.odd = HI_FALSE;
    content_key.key_size = TALOAD_PROTECT_KEY_LEN;
    ret = hi_tee_klad_set_content_key(g_klad_handle, &content_key);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_klad_set_content_key, ret);
        hi_check_result(hi_tee_klad_detach(g_klad_handle, g_cipher_handle));
        return HI_TEE_ERR_EXTERNAL;
    }

    ret = taload_config_cipher_attr(param->decrypt_alg);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_config_cipher_attr, ret);
        hi_check_result(hi_tee_klad_detach(g_klad_handle, g_cipher_handle));
        return HI_TEE_ERR_EXTERNAL;
    }

    return HI_SUCCESS;
}

hi_s32 taload_decrypt(const hi_u8 *buffer, hi_u32 size, const decrypt_param *param)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    if ((buffer == HI_NULL_PTR) || (param == HI_NULL_PTR) || (param->protect_key == HI_NULL_PTR) ||
        (size == 0)) {
        hi_log_err("invalid params\n");
        return HI_TEE_ERR_INVALID_PARAM;
    }

    ret = taload_decrypt_config(param);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_decrypt_config, ret);
        return ret;
    }

    ret = taload_decrypt_process(g_cipher_handle, (hi_u8 *)buffer, size);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_decrypt_process, ret);
        return ret;
    }

    hi_dbg_func_exit();

    return HI_SUCCESS;
}

hi_s32 taload_rsa_verify(const hi_u8 *buffer, hi_u32 size, const hi_u8 *signature,
    hi_u32 signature_size, const taload_rsa_key *rsa_key)
{
    hi_tee_cipher_rsa_verify_param rsa_verify;
    hi_s32 ret;
    hi_tee_cipher_rsa_sign_verify_data rsa_verify_data;
    hi_dbg_func_enter();

    if ((buffer == HI_NULL_PTR) || (signature == HI_NULL_PTR) || (rsa_key == HI_NULL_PTR) ||
        (size == 0) || (signature_size == 0)) {
        hi_log_err("invalid params\n");
        return HI_TEE_ERR_INVALID_PARAM;
    }

    rsa_verify.pub_key.e    = (hi_u8 *)rsa_key->rsa_key_e;
    rsa_verify.pub_key.n    = (hi_u8 *)rsa_key->rsa_key_n;
    rsa_verify.pub_key.e_len = TALOAD_RSA_PUBLIC_KEY_E_LEN;
    rsa_verify.pub_key.n_len = TALOAD_RSA_PUBLIC_KEY_N_LEN;
    rsa_verify.sign_scheme     = HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA256;

    rsa_verify_data.input = (hi_u8 *)buffer;
    rsa_verify_data.input_len = size;
    rsa_verify_data.hash_data = HI_NULL_PTR;
    rsa_verify_data.sign = (hi_u8 *)signature;
    rsa_verify_data.sign_len = &signature_size;
    ret = hi_tee_cipher_rsa_verify(&rsa_verify, &rsa_verify_data);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_cipher_rsa_verify, ret);
        return HI_TEE_ERR_VERIFY;
    }

    hi_dbg_func_exit();

    return HI_SUCCESS;
}

static hi_s32 taload_sm2_verify(const sm2_verify *param)
{
    hi_tee_cipher_sm2_verify_param sm2_verify_param = {0};
    hi_s32 ret;
    hi_tee_cipher_sm2_sign_verify_data sm2_verify_data;
    hi_dbg_func_enter();

    if (param->public_key_len < HI_TEE_CIPHER_SM2_LEN_IN_BYTE * 2) { /* 2 key */
        hi_log_err("invalid params\n");
        return HI_TEE_ERR_INVALID_PARAM;
    }

    ret = memcpy_s(sm2_verify_param.px, HI_TEE_CIPHER_SM2_LEN_IN_BYTE,
        param->public_key_ptr, HI_TEE_CIPHER_SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return HI_TEE_ERR_MEM;
    }
    ret = memcpy_s(sm2_verify_param.py, HI_TEE_CIPHER_SM2_LEN_IN_BYTE,
                   param->public_key_ptr + HI_TEE_CIPHER_SM2_LEN_IN_BYTE, HI_TEE_CIPHER_SM2_LEN_IN_BYTE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return HI_TEE_ERR_MEM;
    }
    sm2_verify_param.id = g_sm2_id;
    sm2_verify_param.id_len = TALOAD_SM2_ID_LEN;
    sm2_verify_data.msg = (hi_u8 *)param->buffer;
    sm2_verify_data.msg_len = param->buffer_size;
    sm2_verify_data.sign_r = (hi_u8 *)param->signature;
    sm2_verify_data.sign_s = (hi_u8 *)param->signature + TALOAD_WORD_LEN;
    sm2_verify_data.sign_buf_len = HI_TEE_CIPHER_SM2_LEN_IN_BYTE;
    ret = hi_tee_cipher_sm2_verify(&sm2_verify_param, &sm2_verify_data);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(HI_TEE_CIPHER_RsaVerify, ret);
        return HI_TEE_ERR_VERIFY;
    }

    hi_dbg_func_exit();

    return HI_SUCCESS;
}

hi_s32 taload_verify_signature(const taload_verify *taload_verify_info)
{
    hi_s32 ret;
    sm2_verify param;

    hi_dbg_func_enter();

    if ((taload_verify_info == HI_NULL_PTR) || (taload_verify_info->verify_data == HI_NULL_PTR) ||
        (taload_verify_info->signature_data == HI_NULL_PTR) || (taload_verify_info->signature_data_len == 0) ||
        (taload_verify_info->verify_data_len == 0)) {
        hi_log_err("invalid params\n");
        return HI_TEE_ERR_INVALID_PARAM;
    }

    if (taload_verify_info->asym_alg == TALOAD_SM2) {
        param.buffer = taload_verify_info->verify_data;
        param.buffer_size = taload_verify_info->verify_data_len;
        param.signature = taload_verify_info->signature_data;
        param.signature_size = taload_verify_info->signature_data_len;
        param.public_key_ptr = (hi_u8 *)taload_verify_info->rsa_key.rsa_key_n;
        param.public_key_len = HI_TEE_CIPHER_SM2_LEN_IN_BYTE * TALOAD_SM2_DATA_LEN;
        ret = taload_sm2_verify(&param);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(taload_sm2_verify, ret);
            return ret;
        }
    } else if (taload_verify_info->asym_alg == TALOAD_RSA2048) {
        ret = taload_rsa_verify(taload_verify_info->verify_data, taload_verify_info->verify_data_len,
            taload_verify_info->signature_data, taload_verify_info->signature_data_len,
            &taload_verify_info->rsa_key);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(taload_rsa_verify, ret);
            return ret;
        }
    } else {
        hi_err_print_call_fun_err(taload_rsa_verify, HI_FAILURE);
        return HI_FAILURE;
    }

    hi_dbg_func_exit();

    return HI_SUCCESS;
}

hi_s32 taload_verify_init(hi_void)
{
    hi_tee_cipher_attr cipher_attr;
    hi_s32 ret;

    hi_dbg_func_enter();

    ret = hi_tee_cipher_init();
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_cipher_init, ret);
        return HI_TEE_ERR_EXTERNAL;
    }

    ret = hi_tee_klad_init();
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_klad_init, ret);
        hi_check_result(hi_tee_cipher_deinit());
        return HI_TEE_ERR_EXTERNAL;
    }

    ret = hi_tee_klad_create(&g_klad_handle);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_klad_create, ret);
        hi_check_result(hi_tee_klad_deinit());
        hi_check_result(hi_tee_cipher_deinit());
        return HI_TEE_ERR_EXTERNAL;
    }

    cipher_attr.cipher_type = HI_TEE_CIPHER_TYPE_NORMAL;
    cipher_attr.is_create_keyslot = HI_TRUE;
    ret = hi_tee_cipher_create(&g_cipher_handle, &cipher_attr);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_cipher_create, ret);
        hi_check_result(hi_tee_klad_destroy(g_klad_handle));
        g_klad_handle = HI_INVALID_HANDLE;
        hi_check_result(hi_tee_klad_deinit());
        hi_check_result(hi_tee_cipher_deinit());
        return HI_TEE_ERR_EXTERNAL;
    }

    ret = cipher_ssm_init(&g_ssm_handle, g_cipher_handle);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(cipher_ssm_init, ret);
        hi_check_result(hi_tee_klad_destroy(g_klad_handle));
        g_klad_handle = HI_INVALID_HANDLE;
        g_cipher_handle = HI_INVALID_HANDLE;
        g_ssm_handle = HI_INVALID_HANDLE;
        hi_check_result(hi_tee_klad_deinit());
        hi_check_result(hi_tee_cipher_deinit());
        return ret;
    }

    hi_dbg_func_exit();

    return HI_SUCCESS;
}

hi_s32 taload_verify_deinit(hi_void)
{
    hi_dbg_func_enter();

    hi_check_result(hi_tee_klad_destroy(g_klad_handle));
    g_klad_handle = HI_INVALID_HANDLE;

    hi_check_result(hi_tee_cipher_destroy(g_cipher_handle));
    g_cipher_handle = HI_INVALID_HANDLE;

    hi_check_result(hi_tee_klad_deinit());
    hi_check_result(hi_tee_cipher_deinit());

    cipher_ssm_deinit();
    g_ssm_handle = HI_INVALID_HANDLE;

    hi_dbg_func_exit();

    return HI_SUCCESS;
}

