/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee hal demux head file
 * Author: sdk
 * Create: 2019-09-05
 */

#ifndef __TEE_HAL_DEMUX_H__
#define __TEE_HAL_DEMUX_H__

#include "tee_drv_demux_define.h"
#include "tee_drv_demux_ioctl.h"

#ifdef __cplusplus
extern "C" {
#endif

enum dmx_pid_flt_rec {
    DMX_PID_TYPE_REC_SCD   =    0,
    DMX_PID_TYPE_FLT       =    1,
    DMX_PID_FLT_REC_BUTT
};

enum dmx_pid_pes_sec_type {
    DMX_PID_TYPE_SECTION   =    0,
    DMX_PID_TYPE_PES       =    1,
    DMX_PID_PES_SEC_BUTT
};

enum dmx_full_ts_out_type {
    DMX_FULL_TS_OUT_TYPE_DAV             = 0,
    DMX_FULL_TS_OUT_TYPE_DSC_REC_SCD     = 2,
    DMX_FULL_TS_OUT_TYPE_FLT             = 3,
    DMX_FULL_TS_OUT_TYPE_BUTT
};

enum dmx_pid_chn_flag {
    DMX_PID_CHN_TEE_LOCK            = (0x1 << 0),     /* 1: tee lock, 0: none tee lock */
    DMX_PID_CHN_PIDCOPY_FLAG        = (0x1 << 8),     /* bit 8 */
    DMX_PID_CHN_CW_FLAG             = (0x1 << 10),    /* bit 10 */
    DMX_PID_CHN_WHOLE_TS_FLAG       = (0x1 << 12),    /* bit 12 */
    DMX_PID_CHN_PES_SEC_FLAG        = (0x1 << 14),    /* bit 14 */
    DMX_PID_CHN_AVPES_FLAG          = (0x1 << 16),    /* bit 16 */
    DMX_PID_CHN_REC_FLAG            = (0x1 << 18),    /* bit 18 */
    DMX_PID_CHN_TS_SCD_FLAG         = (0x1 << 22),    /* bit 22 */
    DMX_PID_CHN_PES_SCD_FLAG        = (0x1 << 24),    /* bit 24 */
    DMX_PID_CHN_DATA_MASK           = DMX_PID_CHN_WHOLE_TS_FLAG | DMX_PID_CHN_PES_SEC_FLAG |
                                      DMX_PID_CHN_AVPES_FLAG | DMX_PID_CHN_REC_FLAG,
};

hi_void tee_dmx_hal_init_hw(hi_void);
hi_void tee_dmx_hal_deinit_hw(hi_void);
hi_void tee_dmx_hal_get_rec_ts_cnt(const tee_dmx_mgmt *tee_dmx_mgmt_ptr, hi_u32 rec_id, hi_u64 *ts_cnt);

/*
 * DEMUX DAV(Buf) hal level functions begin.
 */
#ifdef DMX_SMMU_SUPPORT
hi_void tee_dmx_hal_en_mmu(tee_dmx_mgmt *mgmt);
hi_void tee_dmx_hal_dis_mmu(const tee_dmx_mgmt *mgmt);
hi_void tee_dmx_hal_buf_clr_mmu_cache(const tee_dmx_mgmt *mgmt, hi_u32 id);
hi_void tee_dmx_hal_pid_copy_clr_mmu_cache(const tee_dmx_mgmt *mgmt, hi_u32 pcid);
hi_void tee_dmx_hal_ram_clr_mmu_cache(const tee_dmx_mgmt *mgmt, hi_u32 id);
#else
static inline hi_void dmx_hal_en_mmu(const tee_dmx_mgmt *mgmt) {}
static inline hi_void dmx_hal_dis_mmu(const tee_dmx_mgmt *mgmt) {}
static inline hi_void dmx_hal_buf_clr_mmu_cache(const tee_dmx_mgmt *mgmt, hi_u32 id) {}
static inline hi_void dmx_hal_pid_copy_clr_mmu_cache(const tee_dmx_mgmt *mgmt, hi_u32 pcid) {}
static inline hi_void dmx_hal_ram_clr_mmu_cache(const tee_dmx_mgmt *mgmt, hi_u32 id) {}
#endif

hi_void tee_dmx_hal_ram_port_set_desc(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u64 dsc_phy_addr, hi_u32 dsc_depth);

hi_void tee_dmx_hal_buf_lock_tee_rd(const tee_dmx_mgmt *mgmt, hi_bool lock);
hi_void tee_dmx_hal_buf_set_sec_attrs(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool lock_en, hi_bool secure);
hi_void tee_dmx_hal_buf_set_start_addr(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u64 start_addr);
hi_void tee_dmx_hal_buf_set_size(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 buf_size);
hi_void tee_dmx_hal_buf_set_read_idx(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 read_idx);
hi_void tee_dmx_hal_buf_config(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u64 buf_start_addr, hi_u32 buf_size);
hi_void tee_dmx_hal_buf_deconfig(const tee_dmx_mgmt *mgmt, hi_u32 id);
hi_void tee_dmx_hal_rec_chn_enable(const tee_dmx_mgmt *mgmt, hi_u32 id);
hi_void tee_dmx_hal_pid_tab_set_cc_drop(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool ccerr_drop,
    hi_bool ccrepeat_drop);

/* pidch begin */
hi_void tee_dmx_hal_pid_tab_flt_en(const tee_dmx_mgmt *mgmt, hi_u32 id);
hi_void tee_dmx_hal_pid_tab_flt_dis(const tee_dmx_mgmt *mgmt, hi_u32 id);
hi_bool tee_dmx_hal_pid_tab_flt_check(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 dmx_id, hi_u32 pid);
hi_void tee_dmx_hal_pid_tab_ctl_en_set(const tee_dmx_mgmt *mgmt, hi_u32 id, enum dmx_pid_chn_flag ch_type);
hi_void tee_dmx_hal_pid_tab_ctl_dis_set(const tee_dmx_mgmt *mgmt, hi_u32 id, enum dmx_pid_chn_flag ch_type);
hi_void tee_dmx_hal_pid_tab_set_sub_play_chan_id(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 sub_play_chan_id);
hi_void tee_dmx_hal_pid_set_whole_tstab(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 buf_id, hi_bool no_afcheck,
    hi_bool tee_lock);
hi_void tee_dmx_hal_pid_set_av_pes_tab(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 buf_id, hi_bool pusi_en,
    hi_bool tee_lock);
hi_void tee_dmx_hal_pid_set_rec_dsc_mode(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool descramed);
hi_void tee_dmx_hal_pid_set_pes_sec_tab(const tee_dmx_mgmt *mgmt, hi_u32 id, enum dmx_pid_pes_sec_type pes_sec_type,
    hi_bool pusi_en, hi_bool pes_len_chk);
hi_void tee_dmx_hal_pes_sec_unlock(const tee_dmx_mgmt *mgmt, hi_u32 id);
hi_void tee_dmx_hal_pid_set_rec_tab(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 rec_id);
hi_void tee_dmx_hal_pid_set_scd_tab(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 ts_scd_id, hi_u32 pes_scd_id);
hi_void tee_dmx_hal_pid_cw_en_set(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool cw_en);
hi_bool tee_dmx_hal_pid_cw_en_check(const tee_dmx_mgmt *mgmt, hi_u32 id);
hi_void tee_dmx_hal_pid_set_cw_id(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 cw_id);
hi_void tee_dmx_hal_pid_get_cw_id(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 *cw_id);
hi_void tee_dmx_hal_pid_set_dsc_type(const tee_dmx_mgmt *mgmt, hi_u32 dsc_id, hi_bool ts_desc_en, hi_bool pes_desc_en);

/* scd begin */
hi_void tee_dmx_hal_scd_en(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool scd_en);
hi_void tee_dmx_hal_scd_set_buf_id(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 buf_id);
hi_void tee_dmx_hal_scd_set_tee_lock(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool lock_en);
hi_void tee_dmx_hal_scd_set_rec_tab(const tee_dmx_mgmt *mgmt, hi_u32 id,
    hi_bool tpit_en, hi_bool pes_en, hi_bool es_long_en);
hi_void tee_dmx_hal_scd_set_flt_en(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool flt_en);
hi_void tee_dmx_hal_scd_set_av_pes_cfg(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 chan_en, hi_u32 mode,
    hi_u32 pesh_id_ena);
hi_void tee_dmx_hal_scd_set_ts_rec_cfg(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool ts_rec_en, hi_u32 buf_id);

/* desc begin */
hi_void tee_dmx_hal_mdscset_encrypt_even_odd(const tee_dmx_mgmt *mgmt, hi_u32 id, dmx_dsc_key_type even_odd);
hi_void tee_dmx_hal_mdscset_entropy_reduction(const tee_dmx_mgmt *mgmt, hi_u32 id,
    dmx_dsc_entropy entropy_reduction);
hi_void tee_dmx_hal_mdscset_en(const tee_dmx_mgmt *mgmt, hi_bool ca_en, hi_bool ts_ctrl_dsc_change_en,
    hi_bool cw_iv_en);
hi_void tee_dmx_hal_mdscdis_cpd_core(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool dis_core);
hi_void tee_dmx_hal_mdscdis_ca_core(const tee_dmx_mgmt *mgmt, hi_bool dis_core);
hi_void tee_dmx_hal_mdscdis_cps_core(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool dis_core);
hi_void tee_dmx_hal_mdsc_key_slot_sec_cfg(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool secure_en);
hi_void tee_dmx_hal_mdsc_key_slot_sec_cfg_lock(const tee_dmx_mgmt *mgmt, hi_bool secure_lock_en);
hi_void tee_dmx_hal_mdsc_multi2_sys_key_cfg(const tee_dmx_mgmt *mgmt, hi_u8 *key, hi_u32 key_len);
hi_void tee_dmx_hal_ram_set_sec_attrs(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool secure);
hi_void tee_dmx_hal_pes_sec_set_tee_lock(const tee_dmx_mgmt *mgmt, const dmx_tee_flt_info *flt_info);
hi_void tee_dmx_hal_flt_pes_sec_config(const tee_dmx_mgmt *mgmt, const dmx_tee_flt_info *flt_info);
hi_void tee_dmx_hal_flt_set_sec_default_attr(const tee_dmx_mgmt *mgmt, hi_u32 pes_sec_id, hi_u32 buf_id);
hi_void tee_dmx_hal_flt_set_pes_default_attr(const tee_dmx_mgmt *mgmt, hi_u32 pes_sec_id, hi_u32 buf_id);
#ifdef __cplusplus
}
#endif
#endif /* __HAL_DEMUX_H__ */


