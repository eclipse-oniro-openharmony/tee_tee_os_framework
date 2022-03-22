/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee drv demux utils head file
 * Author: sdk
 * Create: 2019-09-05
 */

#ifndef __TEE_DRV_DEMUX_UTILS_H__
#define __TEE_DRV_DEMUX_UTILS_H__

#include "tee_drv_demux_define.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define TS_SYNC_BYTE                   0x47
#define TTS_SYNC_BYTE_OFFSET           4
#define DMX_KEY_MAX_LEN                16
#define DMX_STR_LEN_32                 32
#define DMX_STR_LEN_16                 16
#define DMX_TS_PKT_SIZE                188
#define DMX_TS_FEC_PKT_SIZE            204
#define DMX_TTS_PKT_SIZE               192

#define DMX_PES_PACKAGE_MAX_LEN       (64 * 1024 - 1 + 6)     /* 64 KB - 1 + pes head:0x6 */

/* general interface */
tee_dmx_mgmt *get_dmx_mgmt(hi_void);
void demux_mutex_init(struct hi_tee_hal_mutex *lock);
void demux_mutex_deinit(struct hi_tee_hal_mutex *lock);
void demux_mutex_lock(struct hi_tee_hal_mutex *lock);
void demux_mutex_unlock(struct hi_tee_hal_mutex *lock);
hi_s32 dmx_alloc_and_map_secbuf(const hi_char *buf_name, hi_u32 buf_len, hi_u32 secbuf_size,
    hi_ulong *secbuf_smmu_addr_ptr, hi_u8 **secbuf_vir_addr_ptr);
hi_s32 dmx_unmap_and_free_secbuf(hi_u32 secbuf_size, hi_ulong secbuf_smmu_addr, hi_u8 *secbuf_vir_addr);
hi_s32 dmx_map_shadow_buffer(hi_ulong phy_addr, hi_u32 buf_len, hi_u8 **vir_addr);
hi_s32 dmx_unmap_shadow_buffer(hi_ulong phy_addr, hi_u32 buf_len, hi_u8 *vir_addr);

/* for tee demux api interface */
hi_s32 tee_drv_dmx_init(hi_void *argp);
hi_s32 tee_drv_dmx_deinit(hi_void *argp);
hi_s32 tee_drv_dmx_create_ramport(hi_void *argp);
hi_s32 tee_drv_dmx_destroy_ramport(hi_void *argp);
hi_s32 tee_drv_dmx_set_ramport_dsc(hi_void *argp);
hi_s32 tee_drv_dmx_create_play_chan(hi_void *argp);
hi_s32 tee_drv_dmx_destroy_play_chan(hi_void *argp);
hi_s32 tee_drv_dmx_attach_play_chan(hi_void *argp);
hi_s32 tee_drv_dmx_detach_play_chan(hi_void *argp);
hi_s32 tee_drv_dmx_create_rec_chan(hi_void *argp);
hi_s32 tee_drv_dmx_destroy_rec_chan(hi_void *argp);
hi_s32 tee_drv_dmx_attach_rec_chan(hi_void *argp);
hi_s32 tee_drv_dmx_detach_rec_chan(hi_void *argp);
hi_s32 tee_drv_dmx_update_play_read_idx(hi_void *argp);
hi_s32 tee_drv_dmx_update_rec_read_idx(hi_void *argp);
hi_s32 tee_drv_dmx_acquire_buf_id(hi_void *argp);
hi_s32 tee_drv_dmx_release_buf_id(hi_void *argp);
hi_s32 tee_drv_dmx_detach_raw_pidch(hi_void *argp);
hi_s32 tee_drv_dmx_config_sebuf(hi_void *argp);
hi_s32 tee_drv_dmx_deconfig_secbuf(hi_void *argp);
hi_s32 tee_drv_dmx_enable_rec_chan(hi_void *argp);
hi_s32 tee_drv_dmx_fixup_hevc_index(hi_void *argp);

/* descrambler interface */
hi_s32 tee_drv_dmx_dsc_create(hi_void *argp);
hi_s32 tee_drv_dmx_dsc_destroy(hi_void *argp);
hi_s32 tee_drv_dmx_dsc_get_attr(hi_void *argp);
hi_s32 tee_drv_dmx_dsc_set_attr(hi_void *argp);
hi_s32 tee_drv_dmx_dsc_set_sys_key(hi_void *argp);
hi_s32 tee_drv_dmx_dsc_set_even_iv_key(hi_void *argp);
hi_s32 tee_drv_dmx_dsc_set_odd_iv_key(hi_void *argp);
hi_s32 tee_drv_dmx_dsc_attach_keyslot(hi_void *argp);
hi_s32 tee_drv_dmx_dsc_detach_keyslot(hi_void *argp);
hi_s32 tee_drv_dmx_dsc_get_keyslot_handle(hi_void *argp);
hi_s32 tee_drv_dmx_dsc_attach_pid_chan(hi_void *argp);
hi_s32 tee_drv_dmx_dsc_detach_pid_chan(hi_void *argp);
hi_s32 tee_drv_dmx_dsc_get_handle(hi_void *argp);
hi_s32 tee_drv_dmx_dsc_get_chan_handle(hi_void *argp);

hi_s32 tee_drv_dmx_sec_pes_flush_shadow_buf(hi_void *argp);
hi_s32 tee_drv_dmx_flt_sec_pes_lock(hi_void *argp);
hi_s32 tee_drv_dmx_config_cc_drop_info(hi_void *argp);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __TEE_DRV_DEMUX_UTILS_H__ */
