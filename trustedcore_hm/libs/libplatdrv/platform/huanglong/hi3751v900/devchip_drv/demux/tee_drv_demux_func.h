/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee drv demux function head file
 * Author: sdk
 * Create: 2019-09-05
 */

#ifndef __TEE_DRV_DEMUX_FUNC_H__
#define __TEE_DRV_DEMUX_FUNC_H__

#include "tee_drv_demux_define.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* for tee ramport */
#define DEFAULT_RAM_DSC_SIZE           8
#define DEFAULT_RAM_DSC_DEPTH          1024
#define RAM_DSC_GUIDE_NUMBER           0xa   /* 4 bits in dsc word1 */

typedef struct {
    hi_u32 mono_parser_len;
    hi_u32 real_parser_len;
} dmx_parser_len_info;

typedef struct {
    hi_u8 *scdata_buf;
    hi_u32 scdata_buf_len;
} dmx_scdata_info;

/* word1 of ramport dscriptor */
typedef union {
    struct {
        unsigned int    iplength                : 20  ; /* [19.. 0] */
        unsigned int    desep                   : 1   ; /* [20] */
        unsigned int    flush                   : 1   ; /* [21] */
        unsigned int    syncdata                : 1   ; /* [22] */ /* sync flag before flush */
        unsigned int    reserved_0              : 1   ; /* [23]  */
        unsigned int    session                 : 4   ; /* [27..24] */
        unsigned int    check_data              : 4   ; /* [31..28] */
    } bits;

    unsigned int    u32;
} U_RAM_DSC_WORD_1;

hi_s32 dmx_drv_mod_init(hi_void);
hi_s32 dmx_drv_mod_exit(hi_void);
hi_s32 dmx_create_ramport_impl(hi_u32 ram_id, hi_u32 buf_size, hi_u32 flush_buf_size, hi_u32 dsc_buf_size,
    dmx_tee_ramport_info *tee_ramport_info);
hi_s32 dmx_destroy_ramport_impl(hi_u32 ram_id, const dmx_tee_ramport_info *tee_ramport_info);
hi_s32 dmx_set_ramport_dsc_impl(hi_u32 ram_id, const dmx_tee_ramport_dsc *tee_ramport_dsc);
hi_s32 dmx_create_play_chan_impl(hi_u32 id, dmx_chan_type chan_type, hi_u32 buf_size, dmx_tee_mem_swap_info *mem_info);
hi_s32 dmx_destroy_play_chan_impl(hi_u32 id, dmx_chan_type chan_type, const dmx_tee_mem_swap_info *mem_info);
hi_s32 dmx_attach_play_chan_impl(hi_u32 chan_id, dmx_chan_type chan_type, hi_u32 raw_pidch_id,
    hi_u32 master_raw_pidch_id);
hi_s32 dmx_detach_play_chan_impl(hi_u32 chan_id, dmx_chan_type chan_type, hi_u32 raw_pidch_id);
hi_s32 dmx_create_rec_chan_impl(hi_u32 id, hi_u32 buf_size, dmx_tee_mem_swap_info *mem_info);
hi_s32 dmx_destroy_rec_chan_impl(hi_u32 id, dmx_tee_mem_swap_info *mem_info);
hi_s32 dmx_attach_rec_chan_impl(const dmx_rec_attach_info *attach_info);
hi_s32 dmx_detach_rec_chan_impl(const dmx_rec_detach_info *detach_info);
hi_s32 dmx_update_play_read_idx_impl(hi_u32 buf_id, dmx_chan_type chan_type, hi_u32 read_idx);
hi_s32 dmx_update_rec_read_idx_impl(hi_u32 buf_id, hi_u32 read_idx);
hi_s32 dmx_acquire_buf_id_impl(hi_u32 *buf_id_ptr);
hi_s32 dmx_release_buf_id_impl(hi_u32 buf_id);
hi_s32 dmx_detach_raw_pidch_impl(hi_u32 raw_pidch);
hi_s32 dmx_utils_fixup_hevc_index(dmx_scd_buf *dmx_scd_buf);
hi_s32 dmx_sec_pes_flush_shadow_buf(dmx_sec_pes_flush_info *flush_info);
hi_s32 dmx_flt_sec_pes_lock(const dmx_tee_flt_info *flt_info);
hi_s32 dmx_config_cc_drop_info(const dmx_tee_cc_drop_info *flt_info);

/* descrambler api declare */
hi_s32 dmx_dsc_fct_create(const dmx_dsc_attrs *attrs, hi_handle *handle);
hi_s32 dmx_dsc_get_attrs(hi_handle handle, dmx_dsc_attrs *attrs);
hi_s32 dmx_dsc_set_attrs(hi_handle handle, const dmx_dsc_attrs *attrs);
hi_s32 dmx_dsc_attach_pid_ch(hi_handle handle, hi_handle pid_ch_handle);
hi_s32 dmx_dsc_detach_pid_ch(hi_handle handle, hi_handle pid_ch_handle);
hi_s32 dmx_dsc_attach_keyslot(hi_handle handle, hi_handle ks_handle);
hi_s32 dmx_dsc_detach_keyslot(hi_handle handle);
hi_s32 dmx_dsc_get_keyslot_handle(hi_handle handle, hi_handle *ks_handle);
hi_s32 dmx_dsc_set_sys_key(hi_handle handle, const hi_u8 *key, hi_u32 len);
hi_s32 dmx_dsc_set_iv(hi_handle handle, dmx_dsc_key_type ivtype, const hi_u8 *iv, hi_u32 len);
hi_s32 dmx_dsc_get_key_handle(hi_handle pid_ch_handle, hi_handle *dsc_handle);
hi_s32 dmx_dsc_get_chan_handle(hi_u32 dmx_id, hi_u32 pid, hi_u32 *chan_num, hi_handle chan[]);
hi_s32 dmx_dsc_fct_destroy(hi_handle handle);
hi_s32 dmx_config_secbuf_impl(hi_u32 chan_id, dmx_chan_type chan_type);
hi_s32 dmx_deconfig_secbuf_impl(hi_u32 chan_id, dmx_chan_type chan_type);
hi_s32 dmx_enable_rec_chan(hi_u32 id);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __TEE_DRV_DEMUX_FUNC_H__ */
