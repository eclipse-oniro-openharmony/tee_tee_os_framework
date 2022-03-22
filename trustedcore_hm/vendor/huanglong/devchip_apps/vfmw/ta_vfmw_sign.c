/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: decoder
 * Author: sdk
 * Create: 2019-06-06
 */

#include "ta_vfmw_sign.h"
#include "hi_tee_otp.h"

static hi_s32 vfmw_common_ioctl(unsigned long cmd, hi_void *pri_args)
{
    unsigned int args[] = {
        (unsigned int)cmd,
        (unsigned int)(uintptr_t)pri_args,
    };

    return hm_drv_call(HI_TEE_SYSCALL_VFMW_CMD, args, ARRAY_SIZE(args));
}

static hi_s32 vfmw_sign_verify_head_hisi(vfmw_sign_head *fw_head, vfmw_verify *verify_info)
{
    hi_s32 ret;

    ta_vfmw_check_ret(fw_head != HI_NULL, HI_FAILURE);
    ta_vfmw_check_ret(verify_info != HI_NULL, HI_FAILURE);

    if (fw_head->image_type != VFMW_SG_IMAGE_TYPE) {
        return HI_FAILURE;
    }

    verify_info->asym_alg = fw_head->asym_algorithm;
    verify_info->verify_data = (hi_u8 *)fw_head;
    verify_info->verify_data_len = VFMW_SG_CODE_OFFSET - VFMW_SG_SIGNATURE_LEN * 2; /* over 2 signature area */
    verify_info->signature_data = (hi_u8 *)fw_head + VFMW_SG_CODE_OFFSET - VFMW_SG_SIGNATURE_LEN * 2; /* over 2 */
    verify_info->signature_data_len = VFMW_SG_SIGNATURE_LEN;
    ret = vfmw_verify_signature(verify_info);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("vfmw_verify_signature fail");
        return HI_FAILURE;
    }

    return  HI_SUCCESS;
}

static hi_s32 vfmw_sign_verify_payload_hisi(vfmw_sign_info *sign_info)
{
    hi_s32 ret;
    vfmw_verify *verify_info = HI_NULL;
    vfmw_sign_head *fw_head = HI_NULL;

    ta_vfmw_check_ret(sign_info != HI_NULL, HI_FAILURE);

    fw_head = sign_info->fw_head;
    verify_info = sign_info->verify_para;

    verify_info->asym_alg = fw_head->asym_algorithm;
    verify_info->verify_data = (hi_u8 *)fw_head + VFMW_SG_CODE_OFFSET;
    verify_info->verify_data_len = fw_head->signed_image_len;
    verify_info->signature_data = (hi_u8 *)fw_head + fw_head->signature_offset;
    verify_info->signature_data_len = VFMW_SG_SIGNATURE_LEN;

    ret = vfmw_verify_signature(verify_info);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("vfmw_sign_verify_payload_hisi fail \n");
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

static hi_s32 vfmw_sign_verify_head_third(vfmw_sign_info *sign_info)
{
    hi_s32 ret;
    vfmw_verify verify_info = {0};
    vfmw_sign_head *fw_head = sign_info->fw_head;
    vfmw_sign_third *third_info = &sign_info->third;

    verify_info.asym_alg = fw_head->asym_algorithm;
    verify_info.verify_data = (hi_u8 *)fw_head;
    verify_info.verify_data_len = VFMW_SG_CODE_OFFSET - VFMW_SG_SIGNATURE_LEN;
    verify_info.signature_data = (hi_u8 *)fw_head + VFMW_SG_CODE_OFFSET - VFMW_SG_SIGNATURE_LEN;
    verify_info.signature_data_len = VFMW_SG_SIGNATURE_LEN;
    ret = memcpy_s(&verify_info.rsa_key, sizeof(verify_info.rsa_key),
        &third_info->rsa_key, sizeof(third_info->rsa_key));
    if (ret != EOK) {
        ta_vfmw_prn("memcpy_s third key fail\n");
        return HI_FAILURE;
    }

    ret = vfmw_verify_signature(&verify_info);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("vfmw verify third signature fail \n");
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

static hi_s32 vfmw_sign_verify_payload_third(vfmw_sign_info *sign_info)
{
    hi_s32 ret;
    vfmw_verify verify_info = {0};
    vfmw_sign_head *fw_head = sign_info->fw_head;
    vfmw_sign_third *third_info = &sign_info->third;

    verify_info.asym_alg = fw_head->asym_algorithm;
    verify_info.verify_data = (hi_u8 *)fw_head + VFMW_SG_CODE_OFFSET;
    verify_info.verify_data_len = fw_head->signed_image_len + VFMW_SG_SIGNATURE_LEN;
    verify_info.signature_data = (hi_u8 *)fw_head + fw_head->signature_offset + VFMW_SG_SIGNATURE_LEN;

    verify_info.signature_data_len = VFMW_SG_SIGNATURE_LEN;
    ret = memcpy_s(&verify_info.rsa_key, sizeof(verify_info.rsa_key),
        &third_info->rsa_key, sizeof(third_info->rsa_key));
    if (ret != EOK) {
        ta_vfmw_prn("memcpy_s third key fail\n");
        return HI_FAILURE;
    }

    ret = vfmw_verify_signature(&verify_info);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("vfmw verify third signature fail \n");
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

static hi_s32 vfmw_sign_get_sign_info(vfmw_sign_info *sign_info)
{
    hi_s32 ret;

    ret = vfmw_common_ioctl(VFMW_SG_IOCTL_GET_SIGN_INFO, (hi_void *)sign_info);
    ta_vfmw_check_ret(ret == HI_SUCCESS, HI_FAILURE);

    return HI_SUCCESS;
}

static hi_s32 vfmw_sign_get_opt_double_sign(vfmw_sign_info *sign_info)
{
    hi_s32 ret;
    vfmw_double_sign_en sign_en = {0};

    ta_vfmw_check_ret(sign_info != HI_NULL, HI_FAILURE);

    sign_info->third.opt_double_sign_en = HI_FALSE;

    ret = hi_tee_otp_read_word(VFMW_SG_DOBULE_SIGN_OTP_ADDR, &sign_en.u32);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("hi_tee_otp_read_word fail \n");
        return HI_FAILURE;
    }

    if (sign_en.bits.tee_double_sign_en != VFMW_SG_DOBULE_SIGN_OTP_DISABLE) {
        sign_info->third.opt_double_sign_en = HI_TRUE;
    }

    return HI_SUCCESS;
}

static hi_s32 vfmw_sign_pre_process(vfmw_sign_info *sign_info, hi_u32 *param, hi_u32 size)
{
    hi_s32 ret;
    hi_u32 length;

    ta_vfmw_check_ret(sign_info != HI_NULL, HI_FAILURE);
    ta_vfmw_check_ret(param != HI_NULL, HI_FAILURE);
    ta_vfmw_check_ret(size >= 2, HI_FAILURE); /* 2: param size */

    ret = vfmw_sign_get_opt_double_sign(sign_info);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("vfmw_sign_get_opt_double_sign fail\n");
        return HI_FAILURE;
    }

    length = param[0];
    sign_info->verify_para = (vfmw_verify *)TEE_Malloc(sizeof(vfmw_verify), 0);
    if (sign_info->verify_para == HI_NULL) {
        ta_vfmw_prn("TEE_Malloc fail \n");
        return HI_FAILURE;
    }

    ret = hi_tee_mmz_alloc_and_map("vfmw_in", length, (hi_void **)(&sign_info->fw_head), &(sign_info->mem_fd));
    ta_vfmw_check_goto(ret == HI_SUCCESS, err0);
    ta_vfmw_check_goto(sign_info->fw_head != HI_NULL, err0);

    sign_info->fw_total_len = length;
    ret = vfmw_sign_get_sign_info(sign_info);
    ta_vfmw_check_goto(ret == HI_SUCCESS, err1);

    sign_info->fw_payload = (hi_u8 *)sign_info->fw_head + VFMW_SG_CODE_OFFSET;
    param[1] = sign_info->fw_head->signed_image_len; /* 1: fw len before sign */
    ta_vfmw_check_goto(param[1] >= VFMW_IMAGE_MIN_LEN && param[1] <= VFMW_IMAGE_MAX_LEN, err1);

    return HI_SUCCESS;

err1:
    ta_vfmw_check_sec_func(memset_s(sign_info->fw_head, length, 0, length));
    ta_vfmw_check_func(hi_tee_mmz_unmap_and_free(sign_info->fw_head, sign_info->mem_fd));
    sign_info->fw_head = HI_NULL;

err0:
    ta_vfmw_check_sec_func(memset_s(sign_info->verify_para, sizeof(vfmw_verify), 0, sizeof(vfmw_verify)));
    TEE_Free(sign_info->verify_para);
    sign_info->verify_para = HI_NULL;

    return HI_FAILURE;
}

static hi_void vfmw_sign_post_process(vfmw_sign_info *sign_info)
{
    if (sign_info == HI_NULL) {
        ta_vfmw_prn("sign_info is null, maybe fail \n");
        return;
    }

    if (sign_info->verify_para != HI_NULL) {
        ta_vfmw_check_sec_func(memset_s(sign_info->verify_para, sizeof(sign_info->verify_para),
            0, sizeof(sign_info->verify_para)));
        TEE_Free(sign_info->verify_para);
        sign_info->verify_para = HI_NULL;
    }

    if (sign_info->fw_head != HI_NULL) {
        ta_vfmw_check_sec_func(memset_s(sign_info->fw_head, sign_info->fw_total_len, 0, sign_info->fw_total_len));
        ta_vfmw_check_func(hi_tee_mmz_unmap_and_free(sign_info->fw_head, sign_info->mem_fd));
        sign_info->fw_head = HI_NULL;
    }

    return;
}

static hi_s32 vfmw_sign_cpy_decrypt_to_sec_ddr(vfmw_sign_info *fw_sign_info)
{
    hi_s32 ret;

    ret = vfmw_common_ioctl(VFMW_SG_IOCTL_COPY_BIN, (hi_void *)fw_sign_info);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("VFMW_SG_IOCTL_COPY_BIN fail");
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

static hi_s32 vfmw_sign_decrypt(vfmw_sign_info *fw_sign_info)
{
    hi_s32 ret;
    ta_vfmw_check_ret(fw_sign_info != HI_NULL, HI_FAILURE);

    ret = vfmw_verify_decrypt(fw_sign_info->fw_head, fw_sign_info->mem_fd, VFMW_SG_CODE_OFFSET);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("vfmw_verify_decrypt fail");
        return HI_FAILURE;
    }

    ret = vfmw_sign_cpy_decrypt_to_sec_ddr(fw_sign_info);
    if (ret != HI_SUCCESS) {
        ta_vfmw_prn("vfmw_verify_cpy_decrypt_to_sec_ddr fail");
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_s32 vfmw_sign_verify(hi_u32 *param, hi_u32 size)
{
    hi_s32 ret = HI_FAILURE;
    vfmw_sign_info *fw_sign_info = HI_NULL;

    fw_sign_info = (vfmw_sign_info *)TEE_Malloc(sizeof(vfmw_sign_info), 0);
    ta_vfmw_check_ret(fw_sign_info != HI_NULL, ret);

    ret = vfmw_verify_init();
    ta_vfmw_check_goto(ret == HI_SUCCESS, err0);

    ret = vfmw_sign_pre_process(fw_sign_info, param, size);
    ta_vfmw_check_goto(ret == HI_SUCCESS, err1);

    ret = vfmw_sign_verify_head_hisi(fw_sign_info->fw_head, fw_sign_info->verify_para);
    ta_vfmw_check_goto(ret == HI_SUCCESS, err2);

    if (fw_sign_info->third.double_sign_en) {
        ret = vfmw_sign_verify_head_third(fw_sign_info);
        ta_vfmw_check_goto(ret == HI_SUCCESS, err2);

        ret = vfmw_sign_verify_payload_third(fw_sign_info);
        ta_vfmw_check_goto(ret == HI_SUCCESS, err2);
    }

    ret = vfmw_sign_decrypt(fw_sign_info);
    ta_vfmw_check_goto(ret == HI_SUCCESS, err2);

    ret = vfmw_sign_verify_payload_hisi(fw_sign_info);
    ta_vfmw_check_goto(ret == HI_SUCCESS, err2);

    ret = HI_SUCCESS;

    hi_tee_printf("vfmw decrypt success \n");

err2:
    vfmw_sign_post_process(fw_sign_info);
err1:
    vfmw_verify_deinit();
err0:
    TEE_Free(fw_sign_info);
    fw_sign_info = HI_NULL;

    return ret;
}
