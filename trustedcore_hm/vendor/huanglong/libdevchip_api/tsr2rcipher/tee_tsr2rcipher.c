/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: tee api tsr2rcipher impl.
 * Author: sdk
 * Create: 2019-08-02
 */

#include "hi_tee_hal.h"
#include "securec.h"
#include "hi_type_dev.h"
#include "hi_tee_tsr2rcipher.h"
#include "hi_tee_drv_syscall_id.h"
#include "tee_drv_ioctl_tsr2rcipher.h"

#undef LOG_MODULE_ID
#define LOG_MODULE_ID HI_ID_TSR2RCIPHER

static hi_s32 __tee_tsr2rcipher_ioctl(unsigned int cmd, hi_void *pri_args)
{
    unsigned int args[] = {
        (unsigned long)cmd,
        (unsigned long)(uintptr_t)pri_args,
    };

    return hm_drv_call(HI_TEE_SYSCALL_TSR2RCIPHER, args, ARRAY_SIZE(args));
}

hi_s32 hi_tee_tsr2rcipher_init(hi_void)
{
    return HI_SUCCESS;
}

hi_s32 hi_tee_tsr2rcipher_deinit(hi_void)
{
    return HI_SUCCESS;
}

hi_s32 hi_tee_tsr2rcipher_get_capability(hi_tee_tsr2rcipher_capability *cap)
{
    hi_s32 ret;
    tsr2rcipher_capability para = {0};

    TSC_CHECK_NULL_POINTER(cap);

    ret = __tee_tsr2rcipher_ioctl(TSR2RCIPHER_TEE_IOCTL_GET_CAP, (hi_void *)&para);
    if (ret == HI_SUCCESS) {
        cap->ts_chan_cnt = para.ts_chan_cnt;
    }

    return ret;
}

hi_s32 hi_tee_tsr2rcipher_get_default_attr(hi_tee_tsr2rcipher_attr *attr)
{
    TSC_CHECK_NULL_POINTER(attr);

    attr->alg               = HI_TEE_TSR2RCIPHER_ALG_AES_CBC;
    attr->mode              = HI_TEE_TSR2RCIPHER_MODE_PAYLOAD;
    attr->is_crc_check      = HI_FALSE;
    attr->is_create_keyslot = HI_TRUE;
    attr->is_odd_key        = HI_FALSE;

    return HI_SUCCESS;
}

hi_s32 hi_tee_tsr2rcipher_create(const hi_tee_tsr2rcipher_attr *attr, hi_handle *handle)
{
    hi_s32 ret;
    tsr2rcipher_create_info para = {0};

    TSC_CHECK_NULL_POINTER(attr);
    TSC_CHECK_NULL_POINTER(handle);

    para.tsc_attr.alg          = (tsr2rcipher_alg)attr->alg;
    para.tsc_attr.mode         = (tsr2rcipher_mode)attr->mode;
    para.tsc_attr.is_crc_check = attr->is_crc_check;
    para.tsc_attr.is_create_ks = attr->is_create_keyslot;
    para.tsc_attr.is_odd_key   = attr->is_odd_key;

    ret = __tee_tsr2rcipher_ioctl(TSR2RCIPHER_TEE_IOCTL_CREATE, (hi_void *)&para);
    if (ret == HI_SUCCESS) {
        *handle = para.handle;
    }

    return ret;
}

hi_s32 hi_tee_tsr2rcipher_destroy(hi_handle handle)
{
    hi_handle para = handle;

    return __tee_tsr2rcipher_ioctl(TSR2RCIPHER_TEE_IOCTL_DESTROY, (hi_void *)&para);
}

hi_s32 hi_tee_tsr2rcipher_get_attr(hi_handle handle, hi_tee_tsr2rcipher_attr *attr)
{
    hi_s32 ret;
    tsr2rcipher_attr_info para = {0};

    TSC_CHECK_NULL_POINTER(attr);

    para.handle = handle;

    ret = __tee_tsr2rcipher_ioctl(TSR2RCIPHER_TEE_IOCTL_GET_ATTR, (hi_void *)&para);
    if (ret == HI_SUCCESS) {
        attr->alg               = (hi_tee_tsr2rcipher_alg)para.tsc_attr.alg;
        attr->mode              = (hi_tee_tsr2rcipher_mode)para.tsc_attr.mode;
        attr->is_crc_check      = para.tsc_attr.is_crc_check;
        attr->is_create_keyslot = para.tsc_attr.is_create_ks;
        attr->is_odd_key        = para.tsc_attr.is_odd_key;
    }

    return ret;
}

hi_s32 hi_tee_tsr2rcipher_set_attr(hi_handle handle, const hi_tee_tsr2rcipher_attr *attr)
{
    tsr2rcipher_attr_info para = {0};

    TSC_CHECK_NULL_POINTER(attr);

    para.handle = handle;
    para.tsc_attr.alg          = (tsr2rcipher_alg)attr->alg;
    para.tsc_attr.mode         = (tsr2rcipher_mode)attr->mode;
    para.tsc_attr.is_crc_check = attr->is_crc_check;
    para.tsc_attr.is_create_ks = attr->is_create_keyslot;
    para.tsc_attr.is_odd_key   = attr->is_odd_key;

    return __tee_tsr2rcipher_ioctl(TSR2RCIPHER_TEE_IOCTL_SET_ATTR, (hi_void *)&para);
}

hi_s32 hi_tee_tsr2rcipher_get_keyslot_handle(hi_handle handle, hi_handle *ks_handle)
{
    hi_s32 ret;
    tsr2rcipher_get_ks_handle para = {0};

    TSC_CHECK_NULL_POINTER(ks_handle);

    para.tsc_handle = handle;

    ret = __tee_tsr2rcipher_ioctl(TSR2RCIPHER_TEE_IOCTL_GET_KS, (hi_void *)&para);
    if (ret == HI_SUCCESS) {
        *ks_handle = para.ks_handle;
    }

    return ret;
}

hi_s32 hi_tee_tsr2rcipher_attach_keyslot(hi_handle handle, hi_handle ks_handle)
{
    tsr2rcipher_associate_ks para = {0};

    para.tsc_handle = handle;
    para.ks_handle  = ks_handle;

    return __tee_tsr2rcipher_ioctl(TSR2RCIPHER_TEE_IOCTL_ATTACH_KS, (hi_void *)&para);
}

hi_s32 hi_tee_tsr2rcipher_detach_keyslot(hi_handle handle, hi_handle ks_handle)
{
    tsr2rcipher_associate_ks para = {0};

    para.tsc_handle = handle;
    para.ks_handle  = ks_handle;

    return __tee_tsr2rcipher_ioctl(TSR2RCIPHER_TEE_IOCTL_DETACH_KS, (hi_void *)&para);
}

hi_s32 hi_tee_tsr2rcipher_set_iv(hi_handle handle, hi_tee_tsr2rcipher_iv_type iv_type, const hi_u8 *iv, hi_u32 iv_len)
{
    hi_s32 ret;
    tsr2rcipher_set_iv_info para = {0};

    TSC_CHECK_NULL_POINTER(iv);

    if (iv_len < TSR2RCIPHER_MIN_IV_LEN || iv_len > TSR2RCIPHER_MAX_IV_LEN || iv_type >= HI_TEE_TSR2RCIPHER_IV_MAX) {
        hi_log_err("invalid para!\n");
        return HI_FAILURE;
    }

    para.handle = handle;
    para.type = (tsr2rcipher_iv_type)iv_type;
    para.len = iv_len;
    ret = memcpy_s(para.iv, TSR2RCIPHER_MAX_IV_LEN, iv, iv_len);
    if (ret != HI_SUCCESS) {
        hi_log_err("memcpy_s failed!\n");
        return HI_FAILURE;
    }

    return __tee_tsr2rcipher_ioctl(TSR2RCIPHER_TEE_IOCTL_SET_IV, (hi_void *)&para);
}

static hi_s32 __tee_tsr2rcipher_trim_data_args(hi_u64 src_addr, hi_u64 dst_addr, hi_u32 len)
{
    if ((len < TSR2RCIPHER_TS_PACKAGE_LEN) || (len > TSR2RCIPHER_MAX_SIZE_PRE_DESC) ||
        (len % TSR2RCIPHER_TS_PACKAGE_LEN)) {
        hi_log_err("data len = 0x%x is invalid, correct rang is (0x%x ~ 0x%x ), or not 188 times\n",
            len, TSR2RCIPHER_TS_PACKAGE_LEN, TSR2RCIPHER_MAX_SIZE_PRE_DESC);
        return HI_FAILURE;
    }

    if (src_addr % TSR2RCIPHER_ADDR_ALIGN || dst_addr % TSR2RCIPHER_ADDR_ALIGN) {
        hi_log_err("src_phy_addr[0x%llx] and dst_phy_addr[0x%llx] must be 0x%x align!\n",
            src_addr, dst_addr, TSR2RCIPHER_ADDR_ALIGN);
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_s32 hi_tee_tsr2rcipher_encrypt(hi_handle handle, hi_u64 src_buf, hi_u64 dst_buf, hi_u32 len)
{
    hi_s32 ret;
    tsr2rcipher_deal_data_info para = {0};

    ret = __tee_tsr2rcipher_trim_data_args(src_buf, dst_buf, len);
    if (ret != HI_SUCCESS) {
        hi_log_err("invalid para!\n");
        return HI_FAILURE;
    }

    para.handle   = handle;
    para.src_buf  = src_buf;
    para.dst_buf  = dst_buf;
    para.data_len = len;

    return __tee_tsr2rcipher_ioctl(TSR2RCIPHER_TEE_IOCTL_ENCRYPT, (hi_void *)&para);
}

hi_s32 hi_tee_tsr2rcipher_decrypt(hi_handle handle, hi_u64 src_buf, hi_u64 dst_buf, hi_u32 len)
{
    hi_s32 ret;
    tsr2rcipher_deal_data_info para = {0};

    ret = __tee_tsr2rcipher_trim_data_args(src_buf, dst_buf, len);
    if (ret != HI_SUCCESS) {
        hi_log_err("invalid para!\n");
        return HI_FAILURE;
    }

    para.handle   = handle;
    para.src_buf  = src_buf;
    para.dst_buf  = dst_buf;
    para.data_len = len;

    return __tee_tsr2rcipher_ioctl(TSR2RCIPHER_TEE_IOCTL_DECRYPT, (hi_void *)&para);
}

