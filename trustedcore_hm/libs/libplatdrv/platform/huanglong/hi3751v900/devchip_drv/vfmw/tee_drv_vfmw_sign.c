/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: decoder
 * Author: sdk
 * Create: 2019-04-22
 */

#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_mem.h"
#include "hi_type_dev.h"
#include "tee_drv_vfmw_sign.h"

#define tee_vfmw_check_ret(cond, ret) \
    do { \
        if (!(cond)) { \
            hi_tee_drv_hal_printf("[%s %d] fail \n", __func__, __LINE__); \
            return ret; \
        } \
    } while (0)

#define tee_drv_vfmw_prn(fmt, arg...)    hi_tee_drv_hal_printf("[%s %d] " fmt " \n", __func__, __LINE__, ##arg)

static hi_s32 tee_drv_vfmw_get_pub_key(vfmw_sign_info *sign_info)
{
    tee_key *key = HI_NULL;
    hi_s32 ret;
    void *virt_addr = HI_NULL;
    vfmw_verify *key_info = HI_NULL;
    vfmw_rsa_key *rsa_key = HI_NULL;

    tee_vfmw_check_ret(sign_info != HI_NULL, HI_FAILURE);

    key_info = sign_info->verify_para;
    ret = hi_tee_drv_hal_user_mmap((hi_void **)(&key_info), sizeof(vfmw_verify));
    if (ret != HI_SUCCESS) {
        tee_drv_vfmw_prn(" user_mmap key_info failed \n");
        return HI_FAILURE;
    }

    virt_addr = hi_tee_drv_hal_remap(TEE_KEY_ADDRESS, TEE_KEY_SIZE, TEE_SECURE_DDR, TEE_NON_CACHE);
    if (virt_addr == HI_NULL) {
        tee_drv_vfmw_prn("remap sec addr fail \n");
        hi_tee_drv_hal_user_munmap(key_info, sizeof(vfmw_verify));
        return HI_FAILURE;
    }

    key = (tee_key *)virt_addr;
    rsa_key = &key_info->rsa_key;
    ret = memcpy_s(rsa_key->rsa_key_e, sizeof(rsa_key->rsa_key_e), key->hisi_tee_root_pub_key_e,
        VFMW_RSA_PUBLIC_KEY_E_LEN);
    if (ret != EOK) {
        tee_drv_vfmw_prn(" memcpy_s get_pub_key rsa_key_e failed \n");
        hi_tee_drv_hal_user_munmap(key_info, sizeof(vfmw_verify));
        hi_tee_drv_hal_unmap(virt_addr, TEE_KEY_SIZE);
        return HI_FAILURE;
    }

    ret = memcpy_s(rsa_key->rsa_key_n, sizeof(rsa_key->rsa_key_n), key->hisi_tee_root_pub_key_n,
        VFMW_RSA_PUBLIC_KEY_N_LEN);
    if (ret != EOK) {
        tee_drv_vfmw_prn(" memcpy_s get_pub_key rsa_key_n failed \n");
        hi_tee_drv_hal_user_munmap(key_info, sizeof(vfmw_verify));
        hi_tee_drv_hal_unmap(virt_addr, TEE_KEY_SIZE);
        return HI_FAILURE;
    }

    hi_tee_drv_hal_user_munmap(key_info, sizeof(vfmw_verify));
    hi_tee_drv_hal_unmap(virt_addr, TEE_KEY_SIZE);

    return HI_SUCCESS;
}

static hi_s32 tee_drv_vfmw_cpy_encrypt_to_sec_buf(vfmw_sign_info *sign_info)
{
    hi_s32 ret = HI_FAILURE;
    vfmw_sign_head *fw_head = HI_NULL;
    hi_u8 *src_bin = HI_NULL;
    hi_u8 *dst_bin = HI_NULL;
    hi_u32 map_len;
    hi_s32 ret_map;

    tee_vfmw_check_ret(sign_info != HI_NULL, HI_FAILURE);

    map_len = sign_info->fw_total_len;
    dst_bin = (hi_u8 *)sign_info->fw_head;
    src_bin = hi_tee_drv_hal_remap(MCU_DAT_SRC_ADDR, map_len, FALSE, TRUE);
    if (src_bin == HI_NULL) {
        tee_drv_vfmw_prn(" map_len 0x%x failed\n", map_len);
        goto err0;
    }

    fw_head = (vfmw_sign_head *)src_bin;
    if (fw_head->total_len != map_len) {
        tee_drv_vfmw_prn(" fail map_len 0x%x != 0x%x, may not sign \n", map_len, fw_head->total_len);
        goto err1;
    }

    ret_map = hi_tee_drv_hal_user_mmap((hi_void **)&dst_bin, fw_head->total_len);
    if (ret_map != HI_SUCCESS) {
        tee_drv_vfmw_prn("user_mmap failed len 0x%x \n", fw_head->total_len);
        goto err1;
    }

    if (memcpy_s(dst_bin, fw_head->total_len, src_bin, map_len) != EOK) {
        tee_drv_vfmw_prn("memcpy_s %p to %p length 0x%x failed\n", src_bin, dst_bin, fw_head->total_len);
        goto err2;
    }

    ret =  HI_SUCCESS;

err2:
    hi_tee_drv_hal_user_munmap(dst_bin, fw_head->total_len);
err1:
    hi_tee_drv_hal_unmap(src_bin, map_len);
err0:

    return ret;
}

static hi_s32 tee_drv_vfmw_get_third_sign_info(vfmw_sign_info *sign_info)
{
    tee_ca_key *ca_key = HI_NULL;
    void *virt_addr = HI_NULL;
    hi_s32 ret;
    vfmw_rsa_key *rsa_key = &sign_info->third.rsa_key;

    if (sign_info->third.opt_double_sign_en != HI_TRUE) {
        sign_info->third.double_sign_en = HI_FALSE;
        return HI_SUCCESS;
    }

    virt_addr = hi_tee_drv_hal_remap(TEE_CA_KEY_ADDRESS, TEE_CA_KEY_SIZE, TEE_SECURE_DDR, TEE_NON_CACHE);
    if (virt_addr == HI_NULL) {
        tee_drv_vfmw_prn("hi_tee_drv_hal_remap failed\n");
        return HI_FAILURE;
    }
    ca_key = (tee_ca_key *)virt_addr;

    if (ca_key->vmcu_double_sign_en != VFMW_DOUBLE_SIG_DISABLE) {
        sign_info->third.double_sign_en = HI_TRUE;
        ret = memcpy_s(rsa_key->rsa_key_e, VFMW_RSA_PUBLIC_KEY_E_LEN,
            ca_key->ext_pub_key_e, sizeof(ca_key->ext_pub_key_e));
        if (ret != EOK) {
            tee_drv_vfmw_prn("memcpy_s failed\n");
            hi_tee_drv_hal_unmap(virt_addr, TEE_CA_KEY_SIZE);
            return HI_FAILURE;
        }

        ret = memcpy_s(rsa_key->rsa_key_n, VFMW_RSA_PUBLIC_KEY_N_LEN,
            ca_key->ext_pub_key_n, sizeof(ca_key->ext_pub_key_n));
        if (ret != EOK) {
            tee_drv_vfmw_prn("memcpy_s failed\n");
            hi_tee_drv_hal_unmap(virt_addr, TEE_CA_KEY_SIZE);
            return HI_FAILURE;
        }
    }

    hi_tee_drv_hal_unmap(virt_addr, TEE_CA_KEY_SIZE);

    return HI_SUCCESS;
}

static hi_s32 tee_drv_vfmw_init_sign_info(vfmw_sign_info *sign_info)
{
    hi_s32 ret;

    ret = tee_drv_vfmw_get_pub_key(sign_info);
    tee_vfmw_check_ret(ret == HI_SUCCESS, HI_FAILURE);

    ret = tee_drv_vfmw_cpy_encrypt_to_sec_buf(sign_info);
    tee_vfmw_check_ret(ret == HI_SUCCESS, HI_FAILURE);

    ret = tee_drv_vfmw_get_third_sign_info(sign_info);
    tee_vfmw_check_ret(ret == HI_SUCCESS, HI_FAILURE);

    return HI_SUCCESS;
}

static hi_s32 tee_drv_vfmw_cpy_decrypt_to_sec_ddr(vfmw_sign_info *sign_info)
{
    hi_u8 *src_bin = HI_NULL;
    hi_u8 *dst_bin = HI_NULL;
    vfmw_sign_head *fw_head = HI_NULL;
    hi_u32 map_len;
    hi_s32 ret = HI_FAILURE;
    hi_s32 ret_tmp;

    tee_vfmw_check_ret(sign_info != HI_NULL, HI_FAILURE);

    fw_head = sign_info->fw_head;
    src_bin = sign_info->fw_payload;
    ret_tmp = hi_tee_drv_hal_user_mmap((hi_void **)&fw_head, sizeof(vfmw_sign_head));
    if (ret_tmp != HI_SUCCESS) {
        goto clean_up0;
    }

    ret_tmp = hi_tee_drv_hal_user_mmap((hi_void **)&src_bin, fw_head->signed_image_len);
    if (ret_tmp != HI_SUCCESS) {
        goto clean_up1;
    }

    map_len = fw_head->signed_image_len;
    dst_bin = hi_tee_drv_hal_remap(MCU_DAT_AFT_DECRYPT_ADDR, map_len, TRUE, TRUE);
    if (dst_bin == HI_NULL) {
        goto clean_up2;
    }
    if (memcpy_s(dst_bin, map_len, src_bin, fw_head->signed_image_len) != EOK) {
        tee_drv_vfmw_prn(" memcpy_s %p to %p length 0x%x failed\n", src_bin, dst_bin, fw_head->signed_image_len);
        goto clean_up3;
    }
    ret = HI_SUCCESS;

clean_up3:
    hi_tee_drv_hal_unmap(dst_bin, map_len);
clean_up2:
    hi_tee_drv_hal_user_munmap(src_bin, fw_head->signed_image_len);
clean_up1:
    hi_tee_drv_hal_user_munmap(fw_head, sizeof(vfmw_sign_head));
clean_up0:

    return ret;
}

hi_s32 tee_drv_vfmw_cmd_ioctl(hi_u32 cmd, hi_u32 args)
{
    hi_s32 ret;

    if (args == 0) {
        tee_drv_vfmw_prn("tee_drv_vfmw_cmd_ioctl args fail \n");
        return HI_FAILURE;
    }

    switch (cmd) {
        case VFMW_SG_IOCTL_GET_SIGN_INFO: {
            vfmw_sign_info *sign_info = (vfmw_sign_info *)(uintptr_t)args;
            ret = hi_tee_drv_hal_user_mmap((hi_void **)(&sign_info), sizeof(vfmw_sign_info));
            tee_vfmw_check_ret(ret == HI_SUCCESS, HI_FAILURE);

            ret = tee_drv_vfmw_init_sign_info(sign_info);
            if (ret != HI_SUCCESS) {
                ret = HI_FAILURE;
                tee_drv_vfmw_prn("tee_drv_vfmw_init_sign_info fail \n");
            }
            hi_tee_drv_hal_user_munmap(sign_info, sizeof(vfmw_sign_info));
            break;
        }

        case VFMW_SG_IOCTL_COPY_BIN: {
            vfmw_sign_info *sign_info = (vfmw_sign_info *)(uintptr_t)args;
            ret = hi_tee_drv_hal_user_mmap((hi_void **)&sign_info, sizeof(vfmw_sign_info));
            tee_vfmw_check_ret(ret == HI_SUCCESS, HI_FAILURE);

            ret = tee_drv_vfmw_cpy_decrypt_to_sec_ddr(sign_info);
            if (ret != HI_SUCCESS) {
                ret = HI_FAILURE;
                tee_drv_vfmw_prn("tee_drv_vfmw_cpy_decrypt_to_sec_ddr fail \n");
            }

            hi_tee_drv_hal_user_munmap(sign_info, sizeof(vfmw_sign_info));
            break;
        }

        default:
            hi_tee_drv_hal_printf("vfmw_drv_cmd_ioctl cmd %d not find !\n", cmd);
            ret = HI_FAILURE;
            break;
    }

    return ret;
}

