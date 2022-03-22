/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee drv tsr2rcipher impl
 * Author: sdk
 * Create: 2020-01-23
 */

#include "hi_type_dev.h"

#include "hi_tee_drv_tsr2rcipher.h"
#include "tee_drv_ioctl_tsr2rcipher.h"

#include "tee_drv_tsr2rcipher_func.h"
#include "tee_drv_tsr2rcipher_define.h"

hi_s32 hi_drv_tsr2rcipher_get_capability(tsr2rcipher_capability *cap)
{
    TSC_CHECK_NULL_POINTER(cap);

    return tsr2rcipher_get_capability_impl(cap);
}

hi_s32 hi_drv_tsr2rcipher_create(const tsr2rcipher_attr *tsc_attr, hi_handle *handle)
{
    TSC_CHECK_NULL_POINTER(tsc_attr);
    TSC_CHECK_NULL_POINTER(handle);

    return tsr2rcipher_create_impl(tsc_attr, handle);
}

hi_s32 hi_drv_tsr2rcipher_destroy(hi_handle handle)
{
    tsc_check_handle(handle);

    return tsr2rcipher_destroy_impl(handle);
}

hi_s32 hi_drv_tsr2rcipher_get_attr(hi_handle handle, tsr2rcipher_attr *tsc_attr)
{
    tsc_check_handle(handle);
    TSC_CHECK_NULL_POINTER(tsc_attr);

    return tsr2rcipher_get_attr_impl(handle, tsc_attr);
}

hi_s32 hi_drv_tsr2rcipher_set_attr(hi_handle handle, const tsr2rcipher_attr *tsc_attr)
{
    tsc_check_handle(handle);
    TSC_CHECK_NULL_POINTER(tsc_attr);

    return tsr2rcipher_set_attr_impl(handle, tsc_attr);
}

hi_s32 hi_drv_tsr2rcipher_get_keyslot_handle(hi_handle tsc_handle, hi_handle *ks_handle)
{
    tsc_check_handle(tsc_handle);
    TSC_CHECK_NULL_POINTER(ks_handle);

    return tsr2rcipher_get_keyslot_handle_impl(tsc_handle, ks_handle);
}

hi_s32 hi_drv_tsr2rcipher_attach_keyslot(hi_handle tsc_handle, hi_handle ks_handle)
{
    tsc_check_handle(tsc_handle);
    tsc_check_ks(ks_handle);

    return tsr2rcipher_attach_keyslot_impl(tsc_handle, ks_handle);
}

hi_s32 hi_drv_tsr2rcipher_detach_keyslot(hi_handle tsc_handle, hi_handle ks_handle)
{
    tsc_check_handle(tsc_handle);
    tsc_check_ks(ks_handle);

    return tsr2rcipher_detach_keyslot_impl(tsc_handle, ks_handle);
}

hi_s32 hi_drv_tsr2rcipher_set_iv(hi_handle handle, tsr2rcipher_iv_type iv_type, hi_u8 *iv, hi_u32 iv_len)
{
    tsc_check_handle(handle);
    TSC_CHECK_NULL_POINTER(iv);

    if (iv_len < TSR2RCIPHER_MIN_IV_LEN || iv_len > TSR2RCIPHER_MAX_IV_LEN || iv_type >= TSR2RCIPHER_IV_MAX) {
        hi_log_err("invalid para!\n");
        return HI_FAILURE;
    }

    return tsr2rcipher_set_iv_impl(handle, iv_type, iv, iv_len);
}

static hi_s32 __drv_tsr2rcipher_trim_data_args(hi_u64 src_addr, hi_u64 dst_addr, hi_u32 len)
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

hi_s32 hi_drv_tsr2rcipher_encrypt(hi_handle handle, hi_u64 src_buf, hi_u64 dst_buf, hi_u32 data_len)
{
    hi_s32 ret;

    tsc_check_handle(handle);

    ret = __drv_tsr2rcipher_trim_data_args(src_buf, dst_buf, data_len);
    if (ret != HI_SUCCESS) {
        hi_log_err("invalid para!\n");
        return HI_FAILURE;
    }

    return tsr2rcipher_encrypt_impl(handle, src_buf, dst_buf, data_len);
}

hi_s32 hi_drv_tsr2rcipher_decrypt(hi_handle handle, hi_u64 src_buf, hi_u64 dst_buf, hi_u32 data_len)
{
    hi_s32 ret;

    tsc_check_handle(handle);

    ret = __drv_tsr2rcipher_trim_data_args(src_buf, dst_buf, data_len);
    if (ret != HI_SUCCESS) {
        hi_log_err("invalid para!\n");
        return HI_FAILURE;
    }

    return tsr2rcipher_decrypt_impl(handle, src_buf, dst_buf, data_len);
}

