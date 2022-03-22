/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee drv demux head file.
 * Author: sdk
 * Create: 2019-09-13
 */

#ifndef __HI_TEE_DRV_DEMUX_H__
#define __HI_TEE_DRV_DEMUX_H__

#include "hi_type_dev.h"
#include "tee_drv_demux_ioctl.h"

#ifdef __cplusplus
extern "C" {
#endif

hi_s32 hi_tee_drv_dmx_init(hi_void);
hi_s32 hi_tee_drv_dmx_deinit(hi_void);
hi_s32 hi_tee_drv_dmx_suspend(hi_void);
hi_s32 hi_tee_drv_dmx_resume(hi_void);

hi_s32 hi_tee_drv_dmx_dsc_create(const dmx_dsc_attrs *attrs, hi_handle *handle);
hi_s32 hi_tee_drv_dmx_dsc_get_attrs(hi_handle handle, dmx_dsc_attrs *attrs);
hi_s32 hi_tee_drv_dmx_dsc_set_attrs(hi_handle handle, const dmx_dsc_attrs *attrs);
hi_s32 hi_tee_drv_dmx_dsc_attach_pid_chan(hi_handle handle, hi_handle pid_chan);
hi_s32 hi_tee_drv_dmx_dsc_detach_pid_chan(hi_handle handle, hi_handle pid_chan);
hi_s32 hi_tee_drv_dmx_dsc_attach_keyslot(hi_handle handle, hi_handle ks_handle);
hi_s32 hi_tee_drv_dmx_dsc_detach_keyslot(hi_handle handle);
hi_s32 hi_tee_drv_dmx_dsc_get_keyslot_handle(hi_handle handle, hi_handle *ks_handle);
hi_s32 hi_tee_drv_dmx_dsc_set_sys_key(hi_handle handle, const hi_u8 *key, hi_u32 len);
hi_s32 hi_tee_drv_dmx_dsc_set_even_iv(hi_handle handle, const hi_u8 *iv, hi_u32 len);
hi_s32 hi_tee_drv_dmx_dsc_set_odd_iv(hi_handle handle, const hi_u8 *iv, hi_u32 len);
hi_s32 hi_tee_drv_dmx_dsc_destroy(hi_handle handle);
hi_s32 hi_tee_drv_dmx_dsc_get_key_handle(hi_handle pid_ch_handle, hi_handle *dsc_handle);
hi_s32 hi_tee_drv_dmx_dsc_get_chan_handle(hi_u32 dmx_id, hi_u32 pid, hi_u32 *chan_num, hi_handle chan[]);

#ifdef __cplusplus
}
#endif

#endif  /* __HI_TEE_DRV_DEMUX_H__ */

