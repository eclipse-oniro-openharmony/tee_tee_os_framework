/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:
 * Author: Hisilicon hisecurity team
 * Create: 2019-07-23
 */

#include "tee_keyslot.h"

#include "hmdrv.h"
#include "hm_msg_type.h"
#include "hi_tee_keyslot.h"
#include "hi_tee_drv_syscall_id.h"
#include "tee_drv_ioctl_keyslot.h"

static hi_s32 __ks_ioctl(hi_u32 cmd, const hi_void *data)
{
    hi_u32 val;
    hi_s32 ret = HI_SUCCESS;

    hi_u32 args[] = {
        (hi_u32)cmd,
        (hi_u32)(uintptr_t)data,
    };
    val = hm_drv_call(CMD_KS_PROCESS, args, ARRAY_SIZE(args));
    if (val != HI_SUCCESS) {
        print_err_hex4(ARRAY_SIZE(args), cmd, (hi_u32)(uintptr_t)data, val);
        ret = HI_FAILURE;
    }
    return ret;
}

hi_s32 hi_tee_keyslot_init(hi_void)
{
    return HI_SUCCESS;
}

hi_s32 hi_tee_keyslot_deinit(hi_void)
{
    return HI_SUCCESS;
}

hi_s32 hi_tee_keyslot_create(hi_tee_keyslot_type keyslot_type, hi_handle *handle)
{
    hi_s32 ret;
    ks_entry entry = {0};

    if (handle == HI_NULL) {
        print_err_code(HI_ERR_KS_PTR_NULL);
        return HI_ERR_KS_PTR_NULL;
    }

    entry.ks_type = keyslot_type;
    ret = __ks_ioctl(CMD_KS_CREATE, &entry);
    if (ret != HI_SUCCESS) {
        print_err_hex3(CMD_KS_CREATE, entry.ks_type, ret);
        return ret;
    }
    *handle = entry.ks_handle;

    return HI_SUCCESS;
}

hi_s32 hi_tee_keyslot_destroy(hi_handle handle)
{
    hi_s32 ret;

    ret = __ks_ioctl(CMD_KS_DESTORY, &handle);
    if (ret != HI_SUCCESS) {
        print_err_hex3(CMD_KS_DESTORY, handle, ret);
        return ret;
    }

    return HI_SUCCESS;
}

hi_s32 hi_tee_keyslot_set_attr(hi_handle handle,  hi_tee_keyslot_attr_type attr_type, const hi_tee_keyslot_attr *attr)
{
    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KS_PTR_NULL);
        return HI_ERR_KS_PTR_NULL;
    }
    if (attr_type >= HI_TEE_KEYSLOT_ATTR_TYPE_MAX) {
        print_err_hex(attr_type);
        return HI_ERR_KS_INVALID_PARAM;
    }
    return HI_SUCCESS;
}

hi_s32 hi_tee_keyslot_get_attr(hi_handle handle,  hi_tee_keyslot_attr_type attr_type, const hi_tee_keyslot_attr *attr)
{
    if (attr == HI_NULL) {
        print_err_code(HI_ERR_KS_PTR_NULL);
        return HI_ERR_KS_PTR_NULL;
    }
    if (attr_type >= HI_TEE_KEYSLOT_ATTR_TYPE_MAX) {
        print_err_hex(attr_type);
        return HI_ERR_KS_INVALID_PARAM;
    }
    return HI_SUCCESS;
}

