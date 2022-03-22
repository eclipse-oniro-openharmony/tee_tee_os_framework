/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee drv demux function impl
 * Author: sdk
 * Create: 2019-06-05
 */

#include "hi_type_dev.h"
#include "hi_tee_drv_demux.h"
#include "tee_drv_demux_func.h"

hi_s32 hi_tee_drv_dmx_init(hi_void)
{
    return HI_SUCCESS;
}

hi_s32 hi_tee_drv_dmx_deinit(hi_void)
{
    return HI_SUCCESS;
}

hi_s32 hi_tee_drv_dmx_suspend(hi_void)
{
    return HI_SUCCESS;
}

hi_s32 hi_tee_drv_dmx_resume(hi_void)
{
    return HI_SUCCESS;
}

hi_s32 hi_tee_drv_dmx_dsc_create(const dmx_dsc_attrs *attrs, hi_handle *handle)
{
    dmx_null_pointer_return(attrs);
    dmx_null_pointer_return(handle);

    return dmx_dsc_fct_create(attrs, handle);
}

hi_s32 hi_tee_drv_dmx_dsc_get_attrs(hi_handle handle, dmx_dsc_attrs *attrs)
{
    DMX_CHECK_HANDLE(handle);
    dmx_null_pointer_return(attrs);

    return dmx_dsc_get_attrs(handle, attrs);
}

hi_s32 hi_tee_drv_dmx_dsc_set_attrs(hi_handle handle, const dmx_dsc_attrs *attrs)
{
    DMX_CHECK_HANDLE(handle);
    dmx_null_pointer_return(attrs);

    return dmx_dsc_set_attrs(handle, attrs);
}

hi_s32 hi_tee_drv_dmx_dsc_attach_pid_chan(hi_handle handle, hi_handle pid_chan)
{
    DMX_CHECK_HANDLE(handle);
    DMX_CHECK_HANDLE(pid_chan);

    return dmx_dsc_attach_pid_ch(handle, pid_chan);
}

hi_s32 hi_tee_drv_dmx_dsc_detach_pid_chan(hi_handle handle, hi_handle pid_chan)
{
    DMX_CHECK_HANDLE(handle);
    DMX_CHECK_HANDLE(pid_chan);

    return dmx_dsc_detach_pid_ch(handle, pid_chan);
}

hi_s32 hi_tee_drv_dmx_dsc_attach_keyslot(hi_handle handle, hi_handle ks_handle)
{
    DMX_CHECK_HANDLE(handle);
    CHECK_KEYSLOT_HANDLE(ks_handle);

    return dmx_dsc_attach_keyslot(handle, ks_handle);
}

hi_s32 hi_tee_drv_dmx_dsc_detach_keyslot(hi_handle handle)
{
    DMX_CHECK_HANDLE(handle);
    return dmx_dsc_detach_keyslot(handle);
}

hi_s32 hi_tee_drv_dmx_dsc_get_keyslot_handle(hi_handle handle, hi_handle *ks_handle)
{
    DMX_CHECK_HANDLE(handle);
    dmx_null_pointer_return(ks_handle);

    return dmx_dsc_get_keyslot_handle(handle, ks_handle);
}

hi_s32 hi_tee_drv_dmx_dsc_set_sys_key(hi_handle handle, const hi_u8 *key, hi_u32 len)
{
    DMX_CHECK_HANDLE(handle);
    dmx_null_pointer_return(key);

    dmx_err_condition_return(len != DMX_SYS_KEY_LEN, HI_ERR_DMX_INVALID_PARA);

    return dmx_dsc_set_sys_key(handle, key, len);
}

hi_s32 hi_tee_drv_dmx_dsc_set_even_iv(hi_handle handle, const hi_u8 *iv, hi_u32 len)
{
    DMX_CHECK_HANDLE(handle);
    dmx_null_pointer_return(iv);

    dmx_err_condition_return((len < DMX_KEY_MIN_LEN || len > DMX_KEY_MAX_LEN), HI_ERR_DMX_INVALID_PARA);

    return dmx_dsc_set_iv(handle, DMX_DSC_KEY_EVEN, iv, len);
}

hi_s32 hi_tee_drv_dmx_dsc_set_odd_iv(hi_handle handle, const hi_u8 *iv, hi_u32 len)
{
    DMX_CHECK_HANDLE(handle);
    dmx_null_pointer_return(iv);

    dmx_err_condition_return((len < DMX_KEY_MIN_LEN || len > DMX_KEY_MAX_LEN), HI_ERR_DMX_INVALID_PARA);

    return dmx_dsc_set_iv(handle, DMX_DSC_KEY_ODD, iv, len);
}

hi_s32 hi_tee_drv_dmx_dsc_destroy(hi_handle handle)
{
    DMX_CHECK_HANDLE(handle);

    return dmx_dsc_fct_destroy(handle);
}

hi_s32 hi_tee_drv_dmx_dsc_get_key_handle(hi_handle pid_ch_handle, hi_handle *dsc_handle)
{
    DMX_CHECK_HANDLE(pid_ch_handle);
    dmx_null_pointer_return(dsc_handle);

    return dmx_dsc_get_key_handle(pid_ch_handle, dsc_handle);
}

hi_s32 hi_tee_drv_dmx_dsc_get_chan_handle(hi_u32 dmx_id, hi_u32 pid, hi_u32 *chan_num, hi_handle chan[])
{
    dmx_null_pointer_return(chan_num);
    dmx_null_pointer_return(chan);

    return dmx_dsc_get_chan_handle(dmx_id, pid, chan_num, chan);
}
