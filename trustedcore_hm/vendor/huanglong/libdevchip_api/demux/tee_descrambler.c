/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee demux descrambler impl
 * Author: sdk
 * Create: 2019-07-13
 */

#include "hi_tee_descrambler.h"
#include "tee_demux_utils.h"
#include "hi_tee_module_id.h"
#include "tee_drv_demux_ioctl.h"

hi_s32 hi_tee_dmx_desc_create(hi_u32 dmx_id, const hi_tee_dmx_desc_attr *attr, hi_handle *handle)
{
    hi_s32 ret;
    dmx_create_dsc_fct_info desc_attr = {0};

    dmx_null_pointer_return(attr);
    dmx_null_pointer_return(handle);

    desc_attr.attrs.ca_type = DMX_CA_ADVANCE;
    desc_attr.attrs.ca_entropy = attr->ca_entropy;
    desc_attr.attrs.alg = attr->alg_type;
    desc_attr.attrs.key_secure_mode = attr->key_secure_mode;
    desc_attr.attrs.keyslot_create_en = attr->is_create_keyslot;

    ret = __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DSCFCT_CREATE, (void *)&desc_attr);
    if (ret == HI_SUCCESS) {
        *handle = desc_attr.handle;
    }

    return ret;
}

hi_s32 hi_tee_dmx_desc_destroy(hi_handle handle)
{
    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DSCFCT_DESTROY, (void *)&handle);
}

hi_s32 hi_tee_dmx_desc_get_attr(hi_handle handle, hi_tee_dmx_desc_attr *attr)
{
    hi_s32 ret;
    dmx_get_dsc_fct_attr_info desc_attr = {
        .handle = handle
    };

    dmx_null_pointer_return(attr);

    ret = __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DSCFCT_GETATTRS, (void *)&desc_attr);
    if (ret == HI_SUCCESS) {
        attr->alg_type = desc_attr.attrs.alg;
        attr->ca_entropy = desc_attr.attrs.ca_entropy;
        attr->key_secure_mode = desc_attr.attrs.key_secure_mode;
        attr->is_create_keyslot = desc_attr.attrs.keyslot_create_en;
    }

    return ret;
}

hi_s32 hi_tee_dmx_desc_set_attr(hi_handle handle, const hi_tee_dmx_desc_attr *attr)
{
    dmx_get_dsc_fct_attr_info desc_attr = {0};

    dmx_null_pointer_return(attr);

    desc_attr.handle = handle;
    desc_attr.attrs.ca_entropy = attr->ca_entropy;
    desc_attr.attrs.alg = attr->alg_type;
    desc_attr.attrs.key_secure_mode = attr->key_secure_mode;
    desc_attr.attrs.keyslot_create_en = attr->is_create_keyslot;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DSCFCT_SETATTRS, (void *)&desc_attr);
}

hi_s32 hi_tee_dmx_desc_set_sys_key(hi_handle handle, const hi_u8 *sys_key, hi_u32 sys_key_len)
{
    hi_s32 ret;
    dmx_dsc_fct_sys_key_info key_info = {0};

    dmx_null_pointer_return(sys_key);
    if (sys_key_len != DMX_SYS_KEY_LEN) {
        hi_log_err("system key length[%u] error!\n", sys_key_len);
        return HI_FAILURE;
    }

    key_info.handle = handle;
    key_info.len = sys_key_len;
    ret = memcpy_s(key_info.key, DMX_SYS_KEY_LEN, sys_key, sys_key_len);
    if (ret != HI_SUCCESS) {
        hi_log_err("memcpy_s failed!\n");
        return HI_FAILURE;
    }

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DSCFCT_SET_KEY, (void *)&key_info);
}

hi_s32 hi_tee_dmx_desc_set_even_iv(hi_handle handle, const hi_u8 *iv_key, hi_u32 even_iv_len)
{
    hi_s32 ret;
    dmx_dsc_fct_iv_key_info key_info = {0};

    dmx_null_pointer_return(iv_key);
    if (even_iv_len > DMX_KEY_MAX_LEN) {
        hi_log_err("even iv key length[%u] error!\n", even_iv_len);
        return HI_FAILURE;
    }

    key_info.handle = handle;
    key_info.len = even_iv_len;
    ret = memcpy_s(key_info.key, DMX_KEY_MAX_LEN, iv_key, even_iv_len);
    if (ret != HI_SUCCESS) {
        hi_log_err("memcpy_s failed!\n");
        return HI_FAILURE;
    }

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DSCFCT_SET_EVEN_IV, (void *)&key_info);
}

hi_s32 hi_tee_dmx_desc_set_odd_iv(hi_handle handle, const hi_u8 *iv_key, hi_u32 odd_iv_len)
{
    hi_s32 ret;
    dmx_dsc_fct_iv_key_info key_info = {0};

    dmx_null_pointer_return(iv_key);
    if (odd_iv_len > DMX_KEY_MAX_LEN) {
        hi_log_err("odd iv key length[%u] error!\n", odd_iv_len);
        return HI_FAILURE;
    }

    key_info.handle = handle;
    key_info.len = odd_iv_len;
    ret = memcpy_s(key_info.key, DMX_KEY_MAX_LEN, iv_key, odd_iv_len);
    if (ret != HI_SUCCESS) {
        hi_log_err("memcpy_s failed!\n");
        return HI_FAILURE;
    }

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DSCFCT_SET_ODD_IV, (void *)&key_info);
}

hi_s32 hi_tee_dmx_desc_attach_key_slot(hi_handle handle, hi_handle ks_handle)
{
    dmx_dsc_fct_attach_info info = {0};

    info.handle = handle;
    info.target_handle = ks_handle;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DSCFCT_ATTACH_KEYSLOT, (void *)&info);
}

hi_s32 hi_tee_dmx_desc_detach_key_slot(hi_handle handle)
{
    dmx_dsc_fct_detach_info info = {0};

    info.handle = handle;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DSCFCT_DETACH_KEYSLOT, (void *)&info);
}

hi_s32 hi_tee_dmx_desc_get_key_slot_handle(hi_handle handle, hi_handle *ks_handle)
{
    hi_s32 ret;
    dmx_dsc_fct_get_ks_handle_info info = {0};

    dmx_null_pointer_return(ks_handle);

    info.handle = handle;

    ret = __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DSCFCT_GET_KS_HANDLE, (void *)&info);
    if (ret == HI_SUCCESS) {
        *ks_handle = info.ks_handle;
    }

    return ret;
}

hi_s32 hi_tee_dmx_desc_attach_pid_chan(hi_handle handle, hi_handle pid_channel)
{
    dmx_dsc_fct_attach_info info = {0};

    info.handle = handle;
    info.target_handle = pid_channel;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DSCFCT_ATTACH, (void *)&info);
}

hi_s32 hi_tee_dmx_desc_detach_pid_chan(hi_handle handle, hi_handle pid_channel)
{
    dmx_dsc_fct_detach_info info = {0};

    info.handle = handle;
    info.target_handle = pid_channel;

    return __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DSCFCT_DETACH, (void *)&info);
}

hi_s32 hi_tee_dmx_desc_get_handle(hi_handle pid_chan, hi_handle *desc_handle)
{
    hi_s32 ret;

    dmx_dsc_fct_get_key_handle_info info = {0};

    dmx_null_pointer_return(desc_handle);
    info.pid_ch_handle = pid_chan;

    ret = __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DSCFCT_GET_KEY_HANDLE, (void *)&info);
    if (ret == HI_SUCCESS) {
        *desc_handle = info.dsc_handle;
    }

    return ret;
}

hi_s32 hi_tee_dmx_desc_get_chan_handle(hi_u32 dmx_id, hi_u32 pid, hi_u32 *chan_num, hi_handle chan[])
{
    hi_s32 ret;
    dmx_dsc_fct_get_chan_handle_info info = {0};

    dmx_null_pointer_return(chan_num);
    dmx_null_pointer_return(chan);

    info.dmx_id = dmx_id;
    info.pid = pid;

    ret = __tee_demux_ioctl(DMX_TEE_IOCTL_GLB_DSCFCT_GET_CHAN_HANDLE, (void *)&info);
    if (ret == HI_SUCCESS) {
        *chan_num = info.chan_num;

        ret = memcpy_s(chan, DMX_PID_CHAN_CNT_PER_BAND * sizeof(hi_handle), info.chan,
            info.chan_num * sizeof(hi_handle));
        if (ret != HI_SUCCESS) {
            hi_log_err("memcpy_s failed!, ret=%#x\n", ret);
            return ret;
        }
    }

    return ret;
}

