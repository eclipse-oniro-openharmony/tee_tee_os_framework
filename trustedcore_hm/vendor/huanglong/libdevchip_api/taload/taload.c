/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: taload authentication file
 * Author: BSP group
 * Create: 2020-01-17
 */
#include "taload.h"

#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_hal.h"
#include "hi_tee_otp.h"
#include "hi_tee_cipher.h"
#include "tee_ta_load.h"
#include "hi_tee_log.h"
#include "hi_tee_errcode.h"

#include "securec.h"
#include "string.h"

#undef SUPPORT_TA_REVOCATION_LIST

#ifdef SUPPORT_TA_REVOCATION_LIST
#define CFG_HI_TEE_STORAGE_DIR "/mnt/trusted_storage/ta_revocation_list.sec"
static hi_char *g_revocation_list = HI_NULL_PTR;
#endif
static hi_u8 *g_ext_pub_key = HI_NULL_PTR;
static hi_u8 *g_root_pub_key = HI_NULL_PTR;
static hi_u8 *g_tarootcert_double_sign = HI_NULL_PTR;

static hi_s32 taload_check_uuid(const hi_u8 *ta_data, const hi_u8 *uuid, hi_u32 uuid_len)
{
    HISI_TA_MANIFEST *ta_manifest = HI_NULL_PTR;

    hi_dbg_func_enter();

    if ((ta_data == HI_NULL) || (uuid == HI_NULL)) {
        return HI_TEE_ERR_INVALID_PTR;
    }

    ta_manifest = (HISI_TA_MANIFEST *)ta_data;
    if (memcmp((hi_void *)&(ta_manifest->srv_uuid), (hi_void *)uuid, uuid_len) != HI_SUCCESS) {
        hi_err_print_err_code(HI_TEE_ERR_ILLEGAL_UUID);
        return HI_TEE_ERR_ILLEGAL_UUID;
    }
    hi_dbg_func_exit();

    return HI_SUCCESS;
}

static hi_s32 taload_check_ta_sig_header_cpy(const ta_body_head *ta_body_header)
{
    hi_u8 *ta_header_hisi_sign = HI_NULL;
    hi_u8 *ta_payload_hisi_sign_cpy = HI_NULL;

    hi_dbg_func_enter();
    ta_header_hisi_sign = (hi_u8 *)ta_body_header + ta_body_header->code_offset - \
        TALOAD_SIGNATURE_LEN * 2; /* 2: multiple of taload signa len */
    ta_payload_hisi_sign_cpy = (hi_u8 *)ta_body_header + ta_body_header->signature_offset - TALOAD_SIGNATURE_LEN;

    if ((ta_header_hisi_sign == HI_NULL) || (ta_payload_hisi_sign_cpy == HI_NULL)) {
        return HI_TEE_ERR_INVALID_PTR;
    }

    if (memcmp(ta_header_hisi_sign, ta_payload_hisi_sign_cpy, TALOAD_SIGNATURE_LEN) != HI_SUCCESS) {
        hi_err_print_err_code(HI_TEE_ERR_ILLEGAL_IMAGE);
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }
    hi_dbg_func_exit();

    return HI_SUCCESS;
}

static hi_s32 taload_set_taid_and_segmentid(hi_u32 ta_id, hi_u32 segment_id, hi_u32 *ta_index)
{
    hi_u32 index;
    hi_s32 ret;

    hi_dbg_func_enter();
    ret = hi_tee_otp_get_ta_index(ta_id, &index);
    if (ret == HI_SUCCESS) {
        hi_log_info("** TA_ID already exists in OTP **\n");
        hi_warn_print_h32(index);
    } else if (ret == HI_TEE_ERR_INVALID_TAID) {
        ret = hi_tee_otp_get_available_ta_index(&index);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(hi_tee_otp_get_available_ta_index, ret);
            return HI_TEE_ERR_NOEXIST;
        }
        hi_warn_print_h32(index);
        ret = hi_tee_otp_set_taid_and_msid(index, ta_id, segment_id);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(hi_tee_otp_set_taid_and_msid, ret);
            return ret;
        }
    } else {
        hi_log_warn("** TAID is unavailable \n**");
        return HI_TEE_ERR_UNAVAILABLE;
    }
    *ta_index = index;
    hi_dbg_func_exit();

    return HI_SUCCESS;
}

static hi_s32 taload_check_segmentid(hi_u32 ta_index, hi_u32 ta_id,
                                     hi_u32 segmentid_in_tacert, hi_u32 segmentid_in_ta)
{
    hi_u32 ta_segment_id_ref;
    hi_u32 ta_id_ref;
    hi_s32 ret;

    hi_dbg_func_enter();
    ret = hi_tee_otp_get_taid_and_msid(ta_index, &ta_id_ref, &ta_segment_id_ref);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_otp_get_taid_and_msid, ret);
        return ret;
    }
    hi_warn_print_h32(segmentid_in_tacert);
    hi_warn_print_h32(segmentid_in_ta);
    hi_warn_print_h32(ta_segment_id_ref);

    if ((segmentid_in_tacert != ta_segment_id_ref || segmentid_in_ta != ta_segment_id_ref) || (ta_id != ta_id_ref)) {
        hi_err_print_err_code(HI_TEE_ERR_ILLEGAL_IMAGE);
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }

    hi_dbg_func_exit();

    return HI_SUCCESS;
}

static hi_s32 check_ta_version(hi_u32 ta_index, hi_u32 ta_sec_version)
{
    hi_u32 ta_sec_version_ref;
    hi_s32 ret;

    hi_dbg_func_enter();
    ret = hi_tee_otp_get_ta_secure_version(ta_index, &ta_sec_version_ref);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_otp_get_ta_secure_version, ret);
        return ret;
    }

    hi_warn_print_h32(ta_sec_version);
    hi_warn_print_h32(ta_sec_version_ref);

    if (ta_sec_version > ta_sec_version_ref) {
        ret = hi_tee_otp_set_ta_secure_version(ta_index, ta_sec_version);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(hi_tee_otp_set_ta_secure_version, ret);
            return ret;
        }
    } else if (ta_sec_version < ta_sec_version_ref) {
        hi_err_print_err_code(HI_TEE_ERR_ILLEGAL_IMAGE);
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }
    hi_dbg_func_exit();

    return HI_SUCCESS;
}

static hi_s32 check_ta_cert_version(hi_u32 ta_index, hi_u32 ta_cert_sec_version)
{
    hi_u32 ta_cert_sec_version_ref;
    hi_s32 ret;

    hi_dbg_func_enter();
    ret = hi_tee_otp_get_ta_certificate_version(ta_index, &ta_cert_sec_version_ref);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_otp_get_ta_certificate_version, ret);
        return ret;
    }

    hi_warn_print_h32(ta_cert_sec_version);
    hi_warn_print_h32(ta_cert_sec_version_ref);

    if (ta_cert_sec_version > ta_cert_sec_version_ref) {
        ret = hi_tee_otp_set_ta_certificate_version(ta_index, ta_cert_sec_version);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(hi_tee_otp_set_ta_certificate_version, ret);
            return ret;
        }
    } else if (ta_cert_sec_version < ta_cert_sec_version_ref) {
        hi_log_warn(" TA Certificate image version is less than the reference version in OTP **");
        hi_err_print_err_code(HI_TEE_ERR_ILLEGAL_IMAGE);
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }
    hi_dbg_func_exit();

    return HI_SUCCESS;
}

static hi_s32 taload_antirollback(hi_u32 ta_index, hi_u32 ta_cert_sec_version, hi_u32 ta_sec_version)
{
    hi_s32 ret;

    hi_dbg_func_enter();
    ret = check_ta_cert_version(ta_index, ta_cert_sec_version);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(check_ta_cert_version, ret);
        return ret;
    }
    ret = check_ta_version(ta_index, ta_sec_version);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(check_ta_version, ret);
        return ret;
    }
    hi_dbg_func_exit();

    return HI_SUCCESS;
}

static hi_s32 taload_check_right(const ta_root_cert *ta_root_cert_image, const ta_cert *ta_cert_image,
                                 const ta_body_head  *ta_body_head_image)
{
    hi_s32 ret;
    hi_u32 ta_index = 0;

    if ((ta_root_cert_image == HI_NULL_PTR) || (ta_cert_image == HI_NULL_PTR) ||
        (ta_body_head_image == HI_NULL_PTR)) {
        hi_log_err("Invalid Params\n");
        return HI_ERR_INVALID_PARAM;
    }

    hi_dbg_func_enter();
    if (ta_cert_image->ta_version_check_flag != TALOAD_TA_VERSION_CHECK_DISABLE) {
        if (ta_cert_image->auto_add_new_ta_flag == TALOAD_TA_UPDATE_TAG) {
            ret = taload_set_taid_and_segmentid(ta_cert_image->ta_id,
                ta_cert_image->segment_id & ta_cert_image->segment_id_mask, &ta_index);
            if (ret != HI_SUCCESS) {
                hi_err_print_call_fun_err(taload_set_taid_and_segmentid, ret);
                return ret;
            }
        } else {
            ret = hi_tee_otp_get_ta_index(ta_cert_image->ta_id, &ta_index);
            if (ret != HI_SUCCESS) {
                hi_err_print_call_fun_err(hi_tee_otp_get_ta_index, ret);
                return ret;
            }
        }
    }
    ret = taload_check_segmentid(ta_index, ta_cert_image->ta_id,
        ta_cert_image->segment_id & ta_cert_image->segment_id_mask,
        ta_body_head_image->segment_id & ta_body_head_image->segment_id_mask);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_check_segmentid, ret);
        return ret;
    }
    if (ta_cert_image->ta_version_check_flag != TALOAD_TA_VERSION_CHECK_DISABLE) {
        ret = taload_antirollback(ta_index, ta_cert_image->sec_version,
            ta_body_head_image->sec_version);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(taload_antirollback, ret);
            return ret;
        }
    }
    hi_dbg_func_exit();

    return HI_SUCCESS;
}

static hi_s32 tee_taload_ioctl(unsigned long cmd, const hi_void *pri_args, hi_u32 size)
{
    hi_u32 args[] = {
        (hi_u32)cmd,
        (hi_u32)(uintptr_t)pri_args,
        (hi_u32)size,
    };
    return hm_drv_call(HI_TEE_SYSCALL_TALOAD, args, ARRAY_SIZE(args));
}

static hi_s32 taload_get_tee_ext_pub_key(taload_rsa_key *rsa_key)
{
    hi_s32 ret;

    hi_dbg_func_enter();
    if (g_ext_pub_key != HI_NULL_PTR) {
        ret = memcpy_s(rsa_key, sizeof(taload_rsa_key), g_ext_pub_key, sizeof(taload_rsa_key));
        if (ret != HI_SUCCESS) {
            hi_log_err("memcpy_s failed\n");
            return HI_TEE_ERR_MEM;
        }
    }
    g_ext_pub_key = (hi_u8 *)TEE_Malloc(sizeof(taload_rsa_key), 0);
    if (g_ext_pub_key == HI_NULL_PTR) {
        hi_err_print_call_fun_err(TEE_Malloc, HI_TEE_ERR_MEM);
        return HI_TEE_ERR_MEM;
    }
    ret = tee_taload_ioctl(TALOAD_IOCTL_GET_EXT_PUB_KEY, (hi_void *)rsa_key, sizeof(taload_rsa_key));
    if (ret != HI_SUCCESS) {
        TEE_Free(g_ext_pub_key);
        g_ext_pub_key = HI_NULL_PTR;
        hi_log_err("get ext_pub_key failed\n");
        return HI_FAILURE;
    }
    hi_dbg_func_exit();

    return HI_SUCCESS;
}

static hi_s32 taload_get_tarootcert_double_sign(hi_u32 *value)
{
    hi_s32 ret;
    double_sign_en sign_en;

    hi_dbg_func_enter();
    ret = hi_tee_otp_read_word(TALOAD_DOBULE_SIGN_OTP_ADDR, &sign_en.u32);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_otp_read_word, ret);
        return ret;
    }
    if (sign_en.bits.tee_double_sign_en == TALOAD_DOBULE_SIGN_OTP_DISABLE) {
        *value = TALOAD_TA_DOBULE_SIGN_DISABLE;
        return HI_SUCCESS;
    }

    if (g_tarootcert_double_sign != HI_NULL_PTR) {
        ret = memcpy_s(value, sizeof(hi_u32), g_tarootcert_double_sign, sizeof(hi_u32));
        if (ret != HI_SUCCESS) {
            hi_log_err("memcpy_s failed\n");
            return HI_TEE_ERR_MEM;
        }
    }
    g_tarootcert_double_sign = (hi_u8 *)TEE_Malloc(sizeof(hi_u32), 0);
    if (g_tarootcert_double_sign == HI_NULL_PTR) {
        hi_err_print_call_fun_err(TEE_Malloc, HI_TEE_ERR_MEM);
        return HI_TEE_ERR_MEM;
    }
    ret = tee_taload_ioctl(TALOAD_IOCTL_GET_TAROOTCERT_DOUBLEL_SIGN, (hi_void *)g_tarootcert_double_sign,
        sizeof(hi_u32));
    if (ret != HI_SUCCESS) {
        TEE_Free(g_tarootcert_double_sign);
        g_tarootcert_double_sign = HI_NULL_PTR;
        hi_log_err("get tarootcert_double_sign failed\n");
        return HI_FAILURE;
    }

    if (g_tarootcert_double_sign != HI_NULL_PTR) {
        ret = memcpy_s(value, sizeof(hi_u32), g_tarootcert_double_sign, sizeof(hi_u32));
        if (ret != HI_SUCCESS) {
            hi_log_err("memcpy_s failed\n");
            return HI_TEE_ERR_MEM;
        }
    }

    hi_dbg_func_exit();

    return HI_SUCCESS;
}

static hi_s32 taload_get_hisi_tee_rootpub_key(taload_rsa_key *rsa_key)
{
    hi_s32 ret;

    hi_dbg_func_enter();
    if (g_root_pub_key != HI_NULL_PTR) {
        ret = memcpy_s(rsa_key, sizeof(taload_rsa_key), g_root_pub_key, sizeof(taload_rsa_key));
        if (ret != HI_SUCCESS) {
            hi_log_err("memcpy_s failed\n");
            return HI_TEE_ERR_MEM;
        }
    }
    g_root_pub_key = (hi_u8 *)TEE_Malloc(sizeof(taload_rsa_key), 0);
    if (g_root_pub_key == HI_NULL_PTR) {
        hi_err_print_call_fun_err(TEE_Malloc, HI_TEE_ERR_MEM);
        return HI_TEE_ERR_MEM;
    }
    ret = tee_taload_ioctl(TALOAD_IOCTL_GET_ROOT_PUB_KEY, (hi_void *)rsa_key, sizeof(taload_rsa_key));
    if (ret != HI_SUCCESS) {
        TEE_Free(g_root_pub_key);
        g_root_pub_key = HI_NULL_PTR;
        hi_log_err("get root_pub_key failed\n");
        return HI_FAILURE;
    }
    hi_dbg_func_exit();

    return HI_SUCCESS;
}

static hi_s32 taload_check_ta(const ta_root_cert *ta_root_cert_image, const ta_cert *ta_cert_image,
    const ta_body_head *ta_body_header)
{
    hi_u8  *ta_owner_addr = HI_NULL;
    hi_s32 ret;

    /* check TA owner string in TA and TA root cert */
    ta_owner_addr = ((hi_u8 *)ta_body_header + ta_body_header->signature_offset -
        TALOAD_SIGNATURE_LEN - TALOAD_TA_OWNER_LEN);
    if (strncmp((char *)ta_root_cert_image->ta_owner, (char *)ta_owner_addr, TALOAD_TA_OWNER_LEN) != 0) {
        hi_log_err("Check TA owner failure in TA and TA root cert area\n");
        hi_err_print_err_code(HI_TEE_ERR_ILLEGAL_IMAGE);
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }

    /* check TA_ID, TA_MSID, TA_version, etc */
    ret = taload_check_right(ta_root_cert_image, ta_cert_image, ta_body_header);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_check_right, ret);
        return ret;
    }

    /* check signature header copy in payload area */
    ret = taload_check_ta_sig_header_cpy(ta_body_header);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_check_ta_sig_header_cpy, ret);
        hi_check_result(taload_verify_deinit());
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 taload_verify_ta_payload_hisi(const ta_cert *ta_cert_image, const ta_body_head *ta_body_header)
{
    taload_verify taload_verify_info;
    hi_s32 ret;

    taload_verify_info.asym_alg = ta_body_header->asym_alg;
    taload_verify_info.verify_data = (hi_u8 *)ta_body_header + ta_body_header->code_offset;
    taload_verify_info.verify_data_len = ta_body_header->signed_image_len;
    taload_verify_info.signature_data = (hi_u8 *)ta_body_header + ta_body_header->signature_offset;
    taload_verify_info.signature_data_len = TALOAD_SIGNATURE_LEN;

    ret = memcpy_s(taload_verify_info.rsa_key.rsa_key_n, TALOAD_RSA_PUBLIC_KEY_N_LEN,
        ta_cert_image->ta_pub_key_n, TALOAD_RSA_PUBLIC_KEY_N_LEN);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return HI_TEE_ERR_MEM;
    }
    ret = memcpy_s(taload_verify_info.rsa_key.rsa_key_e, TALOAD_RSA_PUBLIC_KEY_E_LEN,
        ta_cert_image->ta_pub_key_e, TALOAD_RSA_PUBLIC_KEY_E_LEN);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return HI_TEE_ERR_MEM;
    }
    ret = taload_verify_signature(&taload_verify_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("Verify TA payload with TA public Key failed\n");
        hi_err_print_call_fun_err(taload_verify_signature, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 taload_verify_ta_payload_third(const ta_body_head *ta_body_header)
{
    taload_verify taload_verify_info;
    hi_s32 ret;

    ret = taload_get_tee_ext_pub_key(&taload_verify_info.rsa_key);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_get_tee_ext_pub_key, ret);
        return ret;
    }
    taload_verify_info.asym_alg = ta_body_header->asym_alg;
    taload_verify_info.verify_data = (hi_u8 *)ta_body_header + ta_body_header->code_offset;
    taload_verify_info.verify_data_len = ta_body_header->signed_image_len + TALOAD_SIGNATURE_LEN;
    taload_verify_info.signature_data = (hi_u8 *)ta_body_header + ta_body_header->signature_offset +
        ta_body_header->signature_len;
    taload_verify_info.signature_data_len = TALOAD_SIGNATURE_LEN;
    ret = taload_verify_signature(&taload_verify_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("Verify TA header image wiht TEE_External_Public_Key failed\n");
        hi_err_print_call_fun_err(taload_verify_signature, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 taload_verify_ta_head_hisi(const ta_cert *ta_cert_image, const ta_body_head *ta_body_header)
{
    taload_verify taload_verify_info;
    hi_s32 ret;

    ret = memcpy_s(taload_verify_info.rsa_key.rsa_key_n, TALOAD_RSA_PUBLIC_KEY_N_LEN,
        ta_cert_image->ta_pub_key_n, TALOAD_RSA_PUBLIC_KEY_N_LEN);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return HI_TEE_ERR_MEM;
    }
    ret = memcpy_s(taload_verify_info.rsa_key.rsa_key_e, TALOAD_RSA_PUBLIC_KEY_E_LEN,
        ta_cert_image->ta_pub_key_e, TALOAD_RSA_PUBLIC_KEY_E_LEN);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return HI_TEE_ERR_MEM;
    }
    taload_verify_info.asym_alg = ta_body_header->asym_alg;
    taload_verify_info.verify_data = (hi_u8 *)ta_body_header;
    taload_verify_info.verify_data_len = TALOAD_TA_CODE_OFFSET - TALOAD_SIGNATURE_LEN * 2; /* over 2 signature area */
    taload_verify_info.signature_data = (hi_u8 *)ta_body_header + TALOAD_TA_CODE_OFFSET -
        TALOAD_SIGNATURE_LEN * 2; /* over 2 signature area */
    taload_verify_info.signature_data_len = TALOAD_SIGNATURE_LEN;
    ret = taload_verify_signature(&taload_verify_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("Verify TA header image wiht TaPublicKey failed\n");
        hi_err_print_call_fun_err(taload_verify_signature, ret);
        return ret;
    }

    return  HI_SUCCESS;
}

static hi_s32 taload_verify_ta_head_third(const ta_body_head *ta_body_header)
{
    taload_verify taload_verify_info;
    hi_s32 ret;

    ret = taload_get_tee_ext_pub_key(&taload_verify_info.rsa_key);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_get_tee_ext_pub_key, ret);
        return ret;
    }
    taload_verify_info.asym_alg = ta_body_header->asym_alg;
    taload_verify_info.verify_data = (hi_u8 *)ta_body_header;
    taload_verify_info.verify_data_len = TALOAD_TA_CODE_OFFSET - TALOAD_SIGNATURE_LEN;
    taload_verify_info.signature_data = (hi_u8 *)ta_body_header + TALOAD_TA_CODE_OFFSET - TALOAD_SIGNATURE_LEN;
    taload_verify_info.signature_data_len = TALOAD_SIGNATURE_LEN;
    ret = taload_verify_signature(&taload_verify_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("Verify TA header image wiht TEE_External_Public_Key failed\n");
        hi_err_print_call_fun_err(taload_verify_signature, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 taload_verify_ta(const ta_root_cert *ta_root_cert_image, const ta_cert *ta_cert_image,
    const ta_body_head *ta_body_header)
{
    hi_u32 ta_rootcert_double_sign_en;
    hi_s32 ret;
    decrypt_param decrypt_param;

    ret = taload_get_tarootcert_double_sign(&ta_rootcert_double_sign_en);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_get_tarootcert_double_sign, ret);
        return ret;
    }

    /* Verify TA header image wiht TEE_External_Public_Key if need */
    if (ta_rootcert_double_sign_en != TALOAD_TA_DOBULE_SIGN_DISABLE &&
            ta_root_cert_image->ta_double_sign_en != TALOAD_TA_DOBULE_SIGN_DISABLE) {
        ret = taload_verify_ta_head_third(ta_body_header);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(taload_verify_ta_head_third, ret);
            return ret;
        }
    }

    /* Verify TA header image with TaPublicKey */
    if (ta_cert_image->ta_signed_flag != TALOAD_TA_VERIFY_DISABLE) {
        ret = taload_verify_ta_head_hisi(ta_cert_image, ta_body_header);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(taload_verify_ta_head_hisi, ret);
            return ret;
        }
    }

    /* verify TA Payload wiht TEE_External_Public_Key if need */
    if (ta_rootcert_double_sign_en != TALOAD_TA_DOBULE_SIGN_DISABLE &&
            ta_root_cert_image->ta_double_sign_en != TALOAD_TA_DOBULE_SIGN_DISABLE) {
        ret = taload_verify_ta_payload_third(ta_body_header);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(taload_verify_ta_payload_third, ret);
            return ret;
        }
    }

    /* decrypt TA if ta_encrypted_flag is set */
    if (ta_cert_image->ta_encrypted_flag != TALOAD_TA_ENCRYPTED_DISABLE) {
        decrypt_param.protect_key = ta_cert_image->ta_protection_key;
        decrypt_param.decrypt_alg = ta_body_header->sym_alg;
        decrypt_param.root_key_cfg = ta_cert_image->root_key_cfg;
        decrypt_param.ta_owner_id = ta_cert_image->ta_owner_id;
        ret = taload_decrypt((hi_u8 *)ta_body_header + ta_body_header->code_offset, ta_body_header->signed_image_len,
            &decrypt_param);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(taload_decrypt, ret);
            return ret;
        }
    }

    /* Verify TA payload with TA public Key if need */
    if (ta_cert_image->ta_signed_flag != TALOAD_TA_VERIFY_DISABLE) {
        ret = taload_verify_ta_payload_hisi(ta_cert_image, ta_body_header);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(taload_verify_ta_payload_hisi, ret);
            return ret;
        }
    }

    ret = taload_check_ta(ta_root_cert_image, ta_cert_image, ta_body_header);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_check_ta, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 taload_verify_tacert_hisi(const ta_root_cert *ta_root_cert_image, const ta_cert *ta_cert_image)
{
    taload_verify taload_verify_info;
    hi_s32 ret;

    ret = memcpy_s(taload_verify_info.rsa_key.rsa_key_n, TALOAD_RSA_PUBLIC_KEY_N_LEN,
        ta_root_cert_image->ta_root_pub_key_n, TALOAD_RSA_PUBLIC_KEY_N_LEN);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return HI_TEE_ERR_MEM;
    }

    ret = memcpy_s(taload_verify_info.rsa_key.rsa_key_e, TALOAD_RSA_PUBLIC_KEY_E_LEN,
        ta_root_cert_image->ta_root_pub_key_e, TALOAD_RSA_PUBLIC_KEY_E_LEN);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return HI_TEE_ERR_MEM;
    }
    taload_verify_info.asym_alg = ta_cert_image->asym_alg;
    taload_verify_info.verify_data = (hi_u8 *)ta_cert_image;
    taload_verify_info.verify_data_len = TALOAD_TA_OWNER_SIGNATURE_OFFSET;
    taload_verify_info.signature_data = (hi_u8 *)ta_cert_image + TALOAD_TA_OWNER_SIGNATURE_OFFSET;
    taload_verify_info.signature_data_len = TALOAD_SIGNATURE_LEN;

    ret = taload_verify_signature(&taload_verify_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("Verify TA certificate with TaRootPublicKey failed\n");
        hi_err_print_call_fun_err(taload_verify_signature, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 taload_verify_tacert_third(const ta_cert *ta_cert_image)
{
    taload_verify taload_verify_info;
    hi_s32 ret;

    ret = taload_get_tee_ext_pub_key(&taload_verify_info.rsa_key);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_get_tee_ext_pub_key, ret);
        return ret;
    }
    taload_verify_info.asym_alg = ta_cert_image->asym_alg;
    taload_verify_info.verify_data = (hi_u8 *)ta_cert_image;
    taload_verify_info.verify_data_len = TALOAD_TACERT_IMG_SIZE - TALOAD_SIGNATURE_LEN;
    taload_verify_info.signature_data = (hi_u8 *)ta_cert_image + TALOAD_TACERT_IMG_SIZE - TALOAD_SIGNATURE_LEN;
    taload_verify_info.signature_data_len = TALOAD_SIGNATURE_LEN;
    ret = taload_verify_signature(&taload_verify_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("Verify TA certificate with TEE_External_Public_Key failed\n");
        hi_err_print_call_fun_err(taload_verify_signature, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 taload_verify_tacert(const ta_root_cert *ta_root_cert_image, const ta_cert *ta_cert_image)
{
    hi_u32 ta_rootcert_double_sign_en;
    hi_s32 ret;

    if ((ta_cert_image == HI_NULL_PTR) || (ta_root_cert_image == HI_NULL_PTR)) {
        hi_log_err("Invalid Params\n");
        return HI_ERR_INVALID_PARAM;
    }

    ret = taload_get_tarootcert_double_sign(&ta_rootcert_double_sign_en);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_get_tarootcert_double_sign, ret);
        return ret;
    }

    /* Verify TA certificate with TEE_External_Public_Key if need */
    if (ta_rootcert_double_sign_en != TALOAD_TA_DOBULE_SIGN_DISABLE &&
            ta_root_cert_image->ta_double_sign_en != TALOAD_TA_DOBULE_SIGN_DISABLE) {
        ret = taload_verify_tacert_third(ta_cert_image);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(taload_verify_tacert_third, ret);
            return ret;
        }
    }

    /* Verify TA certificate with TaRootPublicKey */
    ret = taload_verify_tacert_hisi(ta_root_cert_image, ta_cert_image);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_verify_tacert_hisi, ret);
        return HI_TEE_ERR_MEM;
    }

    /* check TA owner string in TA and TA root cert */
    if (strncmp((char *)ta_root_cert_image->ta_owner, (char *)ta_cert_image->ta_owner, TALOAD_TA_OWNER_LEN) != 0) {
        hi_log_err("Check TA owner in TA cert and TA root cert area failed\n");
        hi_err_print_err_code(HI_TEE_ERR_ILLEGAL_IMAGE);
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }
    hi_dbg_func_exit();

    return HI_SUCCESS;
}

#ifdef SUPPORT_TA_REVOCATION_LIST

static hi_s32 taload_get_revo_list_double_sign(hi_u32 *value)
{
    tee_ca_key *ca_key = HI_NULL_PTR;
    hi_u32 virt_addr;
    hi_s32 ret;

    hi_dbg_func_enter();
    ret = __task_map_from_ns_page(0, TEE_CA_KEY_ADDRESS, TEE_CA_KEY_SIZE, &virt_addr, 0);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(map_from_ns_page, ret);
        return ret;
    }
    ca_key = (tee_ca_key *)virt_addr;
    *value = ca_key->revolist_double_sign_en;
    hi_dbg_print_u32(ca_key->revolist_double_sign_en);
    unmap_from_ns_page(virt_addr, TEE_CA_KEY_SIZE);

    hi_dbg_func_exit();

    return HI_SUCCESS;
}

static hi_s32 check_revocation_list(const hi_u8 *buf, hi_u32 size)
{
    ta_revo_list_head *ta_revo_list_header = HI_NULL_PTR;

    hi_dbg_func_enter();
    hi_log_dbg("** [TRACE] Check TA Revocation List Image ! **");
    ta_revo_list_header = (ta_revo_list_head *)buf;
    if (strncmp((hi_char *)ta_revo_list_header->magic_number, HISI_MAGIC_NUMBER,
        TALOAD_TA_IMG_HEADER_MAGINNUMBER_LEN) != 0) {
        hi_log_err("Invalid magic_number in revocation TA list image!\n");
        hi_err_print_err_code(HI_TEE_ERR_ILLEGAL_IMAGE);
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }
    if (strncmp((hi_char *)ta_revo_list_header->header_version, HISI_REVO_LIST_HEADER_VERSION,
        TALOAD_TA_IMG_HEADER_HEADERVERSION_LEN) != 0) {
        hi_log_err("Invalid header_version in revocation TA list image!\n");
        hi_err_print_err_code(HI_TEE_ERR_ILLEGAL_IMAGE);
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }
    if (ta_revo_list_header->image_type != TALOAD_REVO_LIST_IMAGE_TYPE) {
        hi_log_err("Invalid image_type in revocation TA list image!\n");
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }
    hi_dbg_func_exit();

    return HI_SUCCESS;
}

static hi_s32 verify_revocation_head_third(ta_revo_list_head *ta_revo_list_header)
{
    taload_verify revo_list_verify_info;
    hi_s32 ret;

    ret = taload_get_tee_ext_pub_key(&revo_list_verify_info.rsa_key);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_get_tee_ext_pub_key, ret);
        return ret;
    }
    revo_list_verify_info.asym_alg = ta_revo_list_header->asym_alg;
    revo_list_verify_info.verify_data = (hi_u8 *)ta_revo_list_header;
    revo_list_verify_info.verify_data_len = TALOAD_REVO_LIST_OFFSET - TALOAD_SIGNATURE_LEN;
    revo_list_verify_info.signature_data = (hi_u8 *)ta_revo_list_header + TALOAD_REVO_LIST_OFFSET -
        TALOAD_SIGNATURE_LEN;
    revo_list_verify_info.signature_data_len = TALOAD_SIGNATURE_LEN;
    ret = taload_verify_signature(&revo_list_verify_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("Verify revocation list with TEE_External_Public_Key failed\n");
        hi_err_print_call_fun_err(taload_verify_signature, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 verify_revocation_head_hisi(ta_revo_list_head *ta_revo_list_header)
{
    taload_verify revo_list_verify_info;
    hi_s32 ret;

    ret = taload_get_hisi_tee_rootpub_key(&revo_list_verify_info.rsa_key);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_get_hisi_tee_rootpub_key, ret);
        return ret;
    }
    revo_list_verify_info.asym_alg = ta_revo_list_header->asym_alg;
    revo_list_verify_info.verify_data = (hi_u8 *)ta_revo_list_header;
    revo_list_verify_info.verify_data_len = TALOAD_REVO_LIST_OFFSET -
        TALOAD_SIGNATURE_LEN * 2; /* over 2 signature area */
    revo_list_verify_info.signature_data = (hi_u8 *)ta_revo_list_header + TALOAD_REVO_LIST_OFFSET -
        TALOAD_SIGNATURE_LEN * 2; /* over 2 signature area */
    revo_list_verify_info.signature_data_len = TALOAD_SIGNATURE_LEN;
    ret = taload_verify_signature(&revo_list_verify_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("Verify revocation list with Hisi_TEE_RootPubKey failed\n");
        hi_err_print_call_fun_err(taload_verify_signature, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 verify_revocation_payload_third(ta_revo_list_head *ta_revo_list_header)
{
    taload_verify revo_list_verify_info;
    hi_s32 ret;

    ret = taload_get_tee_ext_pub_key(&revo_list_verify_info.rsa_key);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_get_tee_ext_pub_key, ret);
        return ret;
    }
    revo_list_verify_info.asym_alg = ta_revo_list_header->asym_alg;
    revo_list_verify_info.verify_data = (hi_u8 *)ta_revo_list_header + TALOAD_REVO_LIST_OFFSET;
    revo_list_verify_info.verify_data_len = ta_revo_list_header->signed_image_len + TALOAD_SIGNATURE_LEN;
    revo_list_verify_info.signature_data = (hi_u8 *)ta_revo_list_header + ta_revo_list_header->signed_image_len +
        TALOAD_SIGNATURE_LEN;

    revo_list_verify_info.signature_data_len = TALOAD_SIGNATURE_LEN;
    ret = taload_verify_signature(&revo_list_verify_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("Verify revocation list payload with TEE_External_Public_Key failed\n");
        hi_err_print_call_fun_err(taload_verify_signature, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 verify_revocation_payload_hisi(ta_revo_list_head *ta_revo_list_header)
{
    taload_verify revo_list_verify_info;
    hi_s32 ret;

    ret = taload_get_hisi_tee_rootpub_key(&revo_list_verify_info.rsa_key);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_get_hisi_tee_rootpub_key, ret);
        return ret;
    }
    revo_list_verify_info.asym_alg = ta_revo_list_header->asym_alg;
    revo_list_verify_info.verify_data = (hi_u8 *)ta_revo_list_header + TALOAD_REVO_LIST_OFFSET;
    revo_list_verify_info.verify_data_len = ta_revo_list_header->signed_image_len;
    revo_list_verify_info.signature_data = (hi_u8 *)ta_revo_list_header + ta_revo_list_header->signed_image_len;
    revo_list_verify_info.signature_data_len = TALOAD_SIGNATURE_LEN;
    ret = taload_verify_signature(&revo_list_verify_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("Verify plaintext revocation list payload with Hisi_TEE_RootPubKey failed\n");
        hi_err_print_call_fun_err(taload_verify_signature, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 verify_revocation_list(const hi_u8 *buf, hi_u32 size)
{
    ta_revo_list_head *ta_revo_list_header = (ta_revo_list_head *)buf;
    taload_verify revo_list_verify_info;
    hi_s32 ret;
    hi_u32 ta_revo_list_double_sign_en;

    ret = taload_get_revo_list_double_sign(&ta_revo_list_double_sign_en);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_get_revo_list_double_sign, ret);
        return ret;
    }

    /* Verify revocation list header with TEE_External_Public_Key if need */
    if (ta_revo_list_double_sign_en != TALOAD_REVO_LIST_DOBULE_SIGN_DISABLE) {
        ret = verify_revocation_head_third(ta_revo_list_header);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(verify_revocation_list_third, ret);
            return ret;
        }
    }
    /* Verify revocation list header with Hisi_TEE_RootPubKey */
    ret = verify_revocation_head_hisi(ta_revo_list_header);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(verify_revocation_list_hisi, ret);
        return ret;
    }

    /* Verify revocation list payload with TEE_External_Public_Key if need */
    if (ta_revo_list_double_sign_en != TALOAD_REVO_LIST_DOBULE_SIGN_DISABLE) {
        ret = verify_revocation_payload_third(ta_revo_list_header);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(verify_revocation_list_hisi, ret);
            return ret;
        }
    }

    /* decrypt revocation list with hisi slot key */
    ret = taload_decrypt((hi_u8 *)ta_revo_list_header + TALOAD_REVO_LIST_OFFSET, ta_revo_list_header->signed_image_len,
        ta_revo_list_header->revo_list_protection_key, ta_revo_list_header->sym_alg, TALOAD_TA_KLAD_TYPE_HISITA);
    if (ret != HI_SUCCESS) {
        hi_log_err("Decrypt revocation list failed\n");
        hi_err_print_call_fun_err(taload_decrypt, ret);
        return ret;
    }
    /* Verify plaintext revocation list payload with Hisi_TEE_RootPubKey */
    ret = verify_revocation_payload_hisi(ta_revo_list_header);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(verify_revocation_list_hisi, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 check_revo_list_sig_header_cpy(hi_u8 *buf, hi_u32 size)
{
    ta_revo_list_head *ta_revo_list_header = HI_NULL_PTR;
    hi_u8 *revo_list_header_hisi_sign = HI_NULL;
    hi_u8 *revo_list_payload_hisi_sign_cpy = HI_NULL;

    hi_dbg_func_enter();
    ta_revo_list_header = (ta_revo_list_head *)buf;
    revo_list_header_hisi_sign = (hi_u8 *)(buf + TALOAD_REVO_LIST_OFFSET -
        TALOAD_SIGNATURE_LEN * 2); /* over 2 signature area */
    revo_list_payload_hisi_sign_cpy = (hi_u8 *)(buf + TALOAD_REVO_LIST_OFFSET + ta_revo_list_header->signed_image_len -
        TALOAD_SIGNATURE_LEN);

    if (memcmp(revo_list_header_hisi_sign, revo_list_payload_hisi_sign_cpy, TALOAD_SIGNATURE_LEN) != HI_SUCCESS) {
        hi_err_print_err_code(HI_TEE_ERR_ILLEGAL_IMAGE);
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }
    hi_dbg_func_exit();

    return HI_SUCCESS;
}

static hi_s32 get_taload_revocation_list(hi_u8 *buf, hi_s32 size)
{
    hi_s32 ret;
    hi_u32 revocation_list_len;
    ta_revo_list_head *ta_revo_list_header = HI_NULL_PTR;

    if ((buf == HI_NULL_PTR) || (size < TALOAD_TA_REVO_LIST_IMG_HEADER_LEN)) {
        hi_log_err("Invalid Params\n");
        return HI_ERR_INVALID_PARAM;
    }

    hi_log_dbg("** [TRACE] check revocation list ! **");
    ret = check_revocation_list(buf, size);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(check_revocation_list, ret);
        return ret;
    }
    hi_log_dbg("** [TRACE] verify revocation list ! **");
    ret = verify_revocation_list(buf, size);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(verify_revocation_list, ret);
        return ret;
    }
    hi_log_dbg("** [TRACE] verify sign copy in revocation list ! **");
    ret = check_revo_list_sig_header_cpy(buf, size);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(check_revo_list_sig_header_cpy, ret);
        return ret;
    }
    hi_log_dbg("** [TRACE] verify revocation list Success! **");

    ta_revo_list_header = (ta_revo_list_head *)buf;
    revocation_list_len = ta_revo_list_header->signed_image_len;
    g_revocation_list = (hi_char *)TEE_Malloc(revocation_list_len, 0);
    if (g_revocation_list == HI_NULL_PTR) {
        hi_err_print_call_fun_err(TEE_Malloc, HI_TEE_ERR_MEM);
        return HI_TEE_ERR_MEM;
    }
    ret = memcpy_s(g_revocation_list, revocation_list_len, buf + TALOAD_REVO_LIST_OFFSET, revocation_list_len);
    if (ret != HI_SUCCESS) {
        TEE_Free(g_revocation_list);
        g_revocation_list = HI_NULL_PTR;
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 handle_taload_revocation_list(void)
{
    hi_s32 fd;
    hi_s32 file_size;
    hi_u8 *file = HI_NULL;
    hi_u32 count;
    hi_s32 ret;

    fd = fopen(CFG_HI_TEE_STORAGE_DIR, "r");
    if (fd == -1) {
        hi_log_err("fail to open TA revocation list in %s\n", CFG_HI_TEE_STORAGE_DIR);
        return -1;
    }
    file_size = get_file_size(CFG_HI_TEE_STORAGE_DIR);
    if (file_size < 0) {
        hi_log_err("get %s size failed\n", CFG_HI_TEE_STORAGE_DIR);
        fclose(fd);
        return HI_FAILURE;
    }
    file = (hi_u8 *)TEE_Malloc(file_size, 0);
    if (file == HI_NULL_PTR) {
        hi_err_print_call_fun_err(TEE_Malloc, HI_TEE_ERR_MEM);
        fclose(fd);
        return HI_TEE_ERR_MEM;
    }
    count = fread(file, file_size, fd, &ret);
    if (count != file_size) {
        hi_log_err("fread %s failed:count %d/%d", CFG_HI_TEE_STORAGE_DIR, count, file_size);
        TEE_Free(file);
        fclose(fd);
        return ret;
    }
    ret = get_taload_revocation_list(file, file_size);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(get_taload_revocation_list, ret);
        TEE_Free(file);
        fclose(fd);
        return ret;
    }
    TEE_Free(file);
    fclose(fd);

    return HI_SUCCESS;
}

static hi_bool taload_find_revocation_ta(hi_u32 ta_owner_id, hi_u8 *ta_owner, hi_u32 ta_root_pub_key_id)
{
    hi_u32 i;
    hi_s32 ret;
    revo_list *p_revo_list = (revo_list *)g_revocation_list;

    if (p_revo_list == HI_NULL_PTR) {
        return HI_TRUE;
    }

    for (i = 0; i < p_revo_list->item_num; i++) {
        if (p_revo_list->revo_item[i].ta_owner_id == ta_owner_id) {
            continue;
        }
        ret = memcpy_s(ta_owner, TALOAD_TA_OWNER_LEN, p_revo_list->revo_item[i].ta_owner, TALOAD_TA_OWNER_LEN);
        if (ret != HI_SUCCESS) {
            return HI_FALSE;
        }
        /* only support to match with ta root public key id */
        if (p_revo_list->revo_item[i].key_type == 0) {
            if (p_revo_list->revo_item[i].key != ta_root_pub_key_id) {
                return HI_FALSE;
            }
        }
        return HI_TRUE;
    }

    return HI_FALSE;
}
#endif

static hi_s32 taload_verify_tarootcert_third(const ta_root_cert *ta_root_cert_image)
{
    taload_verify taload_verify_info;
    hi_s32 ret;

    ret = taload_get_tee_ext_pub_key(&taload_verify_info.rsa_key);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_get_tee_ext_pub_key, ret);
        return ret;
    }
    taload_verify_info.asym_alg = ta_root_cert_image->asym_alg;
    taload_verify_info.verify_data = (hi_u8 *)ta_root_cert_image;
    taload_verify_info.verify_data_len = TALOAD_TAROOTCERT_IMG_SIZE - TALOAD_SIGNATURE_LEN;
    taload_verify_info.signature_data = (hi_u8 *)ta_root_cert_image + TALOAD_TAROOTCERT_IMG_SIZE -
        TALOAD_SIGNATURE_LEN;
    taload_verify_info.signature_data_len = TALOAD_SIGNATURE_LEN;
    ret = taload_verify_signature(&taload_verify_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("Verify TA root certificate with TEE_External_Public_Key failed\n");
        hi_err_print_call_fun_err(taload_verify_signature, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 taload_verify_tarootcert(const ta_root_cert *ta_root_cert_image)
{
    taload_verify taload_verify_info;
    hi_u32 ta_rootcert_double_sign_en;
    hi_s32 ret;

    ret = taload_get_tarootcert_double_sign(&ta_rootcert_double_sign_en);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_get_tarootcert_double_sign, ret);
        return ret;
    }

    /* Verify TA root certificate with TEE_External_Public_Key if need */
    if (ta_rootcert_double_sign_en != TALOAD_TA_DOBULE_SIGN_DISABLE) {
        ret = taload_verify_tarootcert_third(ta_root_cert_image);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(taload_verify_tarootcert_third, ret);
            return ret;
        }
    }

    /* Verify TA root certificate with Hisi_TEE_RootPubKey */
    ret = taload_get_hisi_tee_rootpub_key(&taload_verify_info.rsa_key);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_get_hisi_tee_rootpub_key, ret);
        return ret;
    }
    taload_verify_info.asym_alg = ta_root_cert_image->asym_alg;
    taload_verify_info.verify_data = (hi_u8 *)ta_root_cert_image;
    taload_verify_info.verify_data_len = TALOAD_TA_OWNER_SIGNATURE_OFFSET;
    taload_verify_info.signature_data = (hi_u8 *)ta_root_cert_image + TALOAD_TA_OWNER_SIGNATURE_OFFSET;
    taload_verify_info.signature_data_len = TALOAD_SIGNATURE_LEN;
    ret = taload_verify_signature(&taload_verify_info);
    if (ret != HI_SUCCESS) {
        hi_log_err("Verify TA root certificate with Hisi_TEE_RootPubKey failed\n");
        hi_err_print_call_fun_err(taload_verify_signature, ret);
        return ret;
    }

#ifdef SUPPORT_TA_REVOCATION_LIST
    ret = taload_find_revocation_ta(ta_root_cert_image->ta_owner_id, ta_root_cert_image->ta_owner,
        ta_root_cert_image->ta_root_pub_key_id);
    if (ret == HI_TRUE) {
        hi_log_err("********* Not allow that TA *************\n");
        return HI_FAILURE;
    }
#endif

    return HI_SUCCESS;
}

static hi_s32 taload_authentication(const hi_u8 *buffer, hi_u32 size, hi_u32 *ta_data_offset, hi_u32 *ta_data_size)
{
    hi_s32 ret;
    ta_root_cert *ta_root_cert_image = (ta_root_cert *)buffer;
    ta_cert *ta_cert_image = (ta_cert *)(buffer + TALOAD_TAROOTCERT_IMG_SIZE);;
    ta_body_head *ta_body_header = (ta_body_head *)(buffer + TALOAD_TAROOTCERT_IMG_SIZE + TALOAD_TACERT_IMG_SIZE);

    if (size <= TALOAD_IMG_MIN_SIZE) {
        return HI_ERR_INVALID_PARAM;
    }

    ret = taload_verify_init();
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_verify_init, ret);
        return ret;
    }
#ifdef SUPPORT_TA_REVOCATION_LIST
    if (g_revocation_list == HI_NULL_PTR) {
        ret = handle_taload_revocation_list();
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(handle_taload_revocation_list, ret);
            g_revocation_list = HI_NULL_PTR;
            goto exit;
        }
    }
#endif
    ret = taload_verify_tarootcert(ta_root_cert_image);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_verify_tarootcert, ret);
        goto exit;
    }

    ret = taload_verify_tacert(ta_root_cert_image, ta_cert_image);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_verify_tarootcert, ret);
        goto exit;
    }

    ret = taload_verify_ta(ta_root_cert_image, ta_cert_image, ta_body_header);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_verify_ta, ret);
        goto exit;
    }

    *ta_data_offset = TALOAD_TAROOTCERT_IMG_SIZE + TALOAD_TACERT_IMG_SIZE + TALOAD_TA_CODE_OFFSET;
    *ta_data_size = ta_body_header->signed_image_len - TALOAD_TA_PAYLOAD_TAIL_LEN;

    ret = taload_check_uuid(buffer + *ta_data_offset, ta_cert_image->ta_uuid, TALOAD_UUID_LEN);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_check_uuid, ret);
        goto exit;
    }

exit:
    taload_verify_deinit();
    return ret;
}

static int check_ta_image(const char *buf, unsigned int size)
{
    ta_root_cert *ta_root_cert_image = (ta_root_cert *)buf;
    ta_cert *ta_cert_image = (ta_cert *)(buf + TALOAD_TAROOTCERT_IMG_SIZE);
    ta_body_head *ta_body_header = (ta_body_head *)(buf + TALOAD_TAROOTCERT_IMG_SIZE + TALOAD_TACERT_IMG_SIZE);

    if (ta_root_cert_image->image_type != TALOAD_TA_ROOT_CERT_IMAGE_TYPE) {
        hi_log_err("Invalid image_type in ta root certificate!\n");
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }
    if (ta_root_cert_image->struct_version != TALOAD_TA_ROOT_CERT_STRUCT_VER) {
        hi_log_err("Invalid struct_version in ta root certificate!\n");
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }

    if (ta_cert_image->image_type != TALOAD_TA_CERT_IMAGE_TYPE) {
        hi_log_err("Invalid image_type in ta certificate!\n");
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }
    if (ta_cert_image->struct_version != TALOAD_TA_CERT_STRUCT_VER) {
        hi_log_err("Invalid struct_version in ta certificate!\n");
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }
    if (TALOAD_IMG_HEADER_CHECK(ta_body_header)) {
        hi_err_print_err_code(HI_TEE_ERR_ILLEGAL_IMAGE);
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }
    if (strncmp((hi_char *)ta_body_header->magic_number, HISI_MAGIC_NUMBER,
        TALOAD_TA_IMG_HEADER_MAGINNUMBER_LEN) != 0) {
        hi_log_err("Invalid magic_number in ta image!\n");
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }
    if (strncmp((hi_char *)ta_body_header->header_version, HISI_IMAGE_HEADER_VERSION,
        TALOAD_TA_IMG_HEADER_HEADERVERSION_LEN) != 0) {
        hi_log_err("Invalid header_version in ta image!\n");
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }
    if (ta_body_header->image_type != TALOAD_TA_IMAGE_TYPE) {
        hi_log_err("Invalid image_type in ta image!\n");
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }

    return HI_SUCCESS;
}

hi_s32 hisi_check_header(const char *buf, unsigned int size)
{
    if ((buf == HI_NULL_PTR) || (size <= TALOAD_IMG_MIN_SIZE)) {
        hi_log_err("Invalid Params\n");
        return HI_ERR_INVALID_PARAM;
    }

    hi_log_dbg("** [TRACE] Check TA Header ! **");

    return check_ta_image(buf, size);
}

hi_s32 hisi_get_total_len(const char *buf, unsigned int size, unsigned int *total_len)
{
    ta_body_head *ta_body_header = HI_NULL_PTR;
    char *tmp_buf = HI_NULL;
    hi_s32 ret;

    hi_dbg_func_enter();

    if ((buf == HI_NULL_PTR) || (total_len == HI_NULL_PTR) || (size < TALOAD_IMG_MIN_SIZE)) {
        hi_log_err("Invalid Params\n");
        return HI_ERR_INVALID_PARAM;
    }

    hi_log_dbg("** [TRACE] Get total length ! **");

    tmp_buf = (char *)TEE_Malloc(TALOAD_IMG_MIN_SIZE, 0);
    if (tmp_buf == HI_NULL_PTR) {
        hi_err_print_call_fun_err(TEE_Malloc, HI_TEE_ERR_MEM);
        return HI_TEE_ERR_MEM;
    }
    ret = memset_s(tmp_buf, TALOAD_IMG_MIN_SIZE, 0x00, TALOAD_IMG_MIN_SIZE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        TEE_Free(tmp_buf);
        return HI_TEE_ERR_MEM;
    }

    ret = memcpy_s(tmp_buf, TALOAD_IMG_MIN_SIZE, buf, TALOAD_IMG_MIN_SIZE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        TEE_Free(tmp_buf);
        return HI_TEE_ERR_MEM;
    }
    ret = check_ta_image(tmp_buf, size);
    if (ret != HI_SUCCESS) {
        hi_log_err("check image failed\n");
        TEE_Free(tmp_buf);
        return HI_TEE_ERR_ILLEGAL_IMAGE;
    }

    ta_body_header = (ta_body_head *)(tmp_buf + TALOAD_TAROOTCERT_IMG_SIZE + TALOAD_TACERT_IMG_SIZE);
    if (TALOAD_TAROOTCERT_IMG_SIZE + TALOAD_TACERT_IMG_SIZE > (TALOAD_UINT_MAX - ta_body_header->total_len)) {
        hi_err_print_err_code(HI_TEE_ERR_OVERFLOW);
        TEE_Free(tmp_buf);
        return HI_TEE_ERR_OVERFLOW;
    }
    *total_len = TALOAD_TAROOTCERT_IMG_SIZE + TALOAD_TACERT_IMG_SIZE + ta_body_header->total_len;

    TEE_Free(tmp_buf);
    hi_dbg_func_exit();

    return HI_SUCCESS;
}

int hisi_get_private_data(const char *buf, unsigned int size,
                          const unsigned int *data_size, const unsigned int *data_offest)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    if ((buf == HI_NULL_PTR) || (data_size == HI_NULL_PTR) || (data_offest == HI_NULL_PTR) ||
        (size <= TALOAD_IMG_MIN_SIZE + TALOAD_SIGNATURE_LEN * 2)) { /* 2 signature len */
        hi_log_err("Invalid Params\n");
        return HI_ERR_INVALID_PARAM;
    }

    ret = taload_authentication((hi_u8 *)buf, size, (hi_u32 *)data_offest, (hi_u32 *)data_size);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(taload_authentication, ret);
        return ret;
    }
    hi_dbg_func_exit();

    return HI_SUCCESS;
}

