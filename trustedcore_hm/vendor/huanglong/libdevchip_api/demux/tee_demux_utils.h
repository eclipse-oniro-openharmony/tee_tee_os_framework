/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee demux utils impl head file
 * Author: SDK
 * Create: 2019-10-11
 */

#ifndef __TEE_DEMUX_UTILS_H__
#define __TEE_DEMUX_UTILS_H__

#include "hi_type_dev.h"
#include "hi_log.h"
#include "hi_tee_errcode.h"

#undef LOG_MODULE_ID
#define LOG_MODULE_ID HI_ID_DEMUX

#undef HI_LOG_D_FUNCTRACE
#define HI_LOG_D_FUNCTRACE 1

#undef HI_LOG_D_UNFTRACE
#define HI_LOG_D_UNFTRACE 1

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*
 * keep synchronization with sdk/source/common/include/hi_module.h
 */
#define HI_ID_DEMUX                    0x2c
#define HI_MAX_PID                     0x1FFF
#define DMX_KEY_MIN_LEN                8
#define DMX_KEY_MAX_LEN                16

#define dmx_null_pointer_void(p) do { \
    if ((p) == HI_NULL) {                \
        hi_log_err("null pointer!\n"); \
        return; \
    }\
} while (0)

#define dmx_null_pointer_return(p) do {  \
    if ((p) == HI_NULL) {                \
        hi_log_err("null pointer!\n"); \
        return HI_TEE_ERR_INVALID_PTR; \
    }\
} while (0)

#define dmx_null_pointer_goto(p, out_flag) do { \
    if ((p) == HI_NULL) {                       \
        hi_log_err("null pointer!\n");        \
        ret =  HI_TEE_ERR_INVALID_PTR;             \
        goto out_flag;                          \
    }\
} while (0)

#define dmx_null_pointer_void_break(p) do {   \
    if ((p) == HI_NULL) {                \
        hi_log_err("null pointer!\n"); \
        break;                   \
    }\
} while (0)

#define dmx_null_pointer_break(p) do {   \
    if ((p) == HI_NULL) {                \
        hi_log_err("null pointer!\n"); \
        ret =  HI_TEE_ERR_INVALID_PTR;   \
        break;                   \
    }\
} while (0)

#define dmx_unused(x) ((x) = (x))
#define unlikely(condition) (condition)

#define dmx_err_condition_void(condition) do { \
    if (unlikely(condition)) { \
        hi_log_err("DEMUX ERROR CONDITION: %s\n", #condition); \
        return;  \
    } \
} while (0)

#define dmx_err_condition_void_goto(condition, out_flag) do { \
    if (unlikely(condition)) { \
        hi_log_err("DEMUX ERROR CONDITION: %s\n", #condition); \
        goto out_flag;  \
    } \
} while (0)

#define dmx_err_condition_return(condition, err_code) do { \
    if (unlikely(condition)) { \
        hi_log_err("DEMUX ERROR CONDITION: %s\n", #condition); \
        return err_code;  \
    } \
} while (0)

#define dmx_err_condition_goto(condition, err_code, out_flag) do { \
    if (unlikely(condition)) { \
        hi_log_err("DEMUX ERROR CONDITION: %s\n", #condition); \
        ret = err_code; \
        goto out_flag;  \
    } \
} while (0)

typedef struct {
    hi_u32 magic      : 16;
    hi_u32 head_size  : 16;
    hi_u8  version[32]; /* max size is 32 bytes */
} dmx_ree_tee_version;

/* Defines the capability of the demux module */
typedef struct {
    hi_u32 dmx_num;           /* number of band devices */
    hi_u32 ramport_num;       /* number of ram ports. */
    hi_u32 play_chan_num;     /* number of channels, containing the audio and video channels */
    hi_u32 key_num;           /* number of keys */
    hi_u32 rec_chan_num;      /* number of record channels */
} dmx_capability;

typedef struct {
    hi_handle   handle;
    hi_u32      buf_id;
    hi_u32      buf_size;
    hi_u64      buf_phy_addr;
    hi_u64      shadow_buf_start_addr;
    hi_u32      shadow_buf_size;
} dmx_tee_mem_swap_info;

typedef enum {
    DMX_FLT_CRC_MODE_FORBID                 =    0,
    DMX_FLT_CRC_MODE_FORCE_AND_DISCARD      =    1,
    DMX_FLT_CRC_MODE_FORCE_AND_SEND         =    2,
    DMX_FLT_CRC_MODE_BY_SYNTAX_AND_DISCARD  =    3,
    DMX_FLT_CRC_MODE_BY_SYNTAX_AND_SEND     =    4,
    DMX_FLT_CRC_MODE_MAX
} dmx_flt_crc_mode;

typedef enum {
    DMX_FLT_ATTR_INIT                 =    0,
    DMX_FLT_ATTR_SET                  =    1,
    DMX_FLT_ATTR_ATTACH               =    2,
    DMX_FLT_ATTR_MAX
} flt_attr_status;

typedef struct {
    hi_bool             flt_pes_sec_lock;
    hi_u32              flt_index;
    hi_u32              flt_id;
    hi_u32              pes_sec_id;
    hi_u32              flt_num;
    hi_u32              buf_id;
    dmx_flt_crc_mode    crc_mode;
    flt_attr_status     status;
} dmx_tee_flt_info;

typedef struct {
    hi_u32              pid_ch_id;
    hi_bool             ccerr_drop;
    hi_bool             ccrepeat_drop;
} dmx_tee_cc_drop_info;

typedef struct {
    hi_handle buf_handle;
    hi_u32  buf_size;
    hi_u32  flush_buf_size;
    hi_u32  dsc_buf_size;

    hi_u64  buf_phy_addr;
    hi_u64  flush_buf_phy_addr;
    hi_u64  dsc_buf_phy_addr;
} dmx_tee_ramport_info;

typedef struct {
    hi_u64 buf_phy_addr;
    hi_u32 buf_len;
    hi_bool desep;
    hi_bool flush_flag;
    hi_bool sync_data_flag;
    hi_u32  write_index;
} dmx_tee_ramport_dsc;

typedef struct {
    hi_u32  chan_id;
    hi_bool is_descram;
    hi_bool is_video_index;
    hi_u32  index_scd_id;
    hi_u32  scd_buf_id;
    hi_u32  raw_pidch_id;
    hi_u32  master_raw_pidch_id;
} dmx_rec_attach_info;

typedef struct {
    hi_u32  chan_id;
    hi_bool is_rec_only;
    hi_bool is_descram;
    hi_bool is_video_index;
    hi_u32  index_scd_id;
    hi_u32  raw_pidch_id;
} dmx_rec_detach_info;

typedef enum {
    DMX_CHAN_TYPE_SEC = 0x1,
    DMX_CHAN_TYPE_PES = 0x2,
    DMX_CHAN_TYPE_AUD = 0x4,
    DMX_CHAN_TYPE_VID = 0x8,
    DMX_CHAN_TYPE_TS  = 0x10,
    DMX_CHAN_TYPE_REC = 0x20,
    DMX_CHAN_TYPE_SCD = 0x40,
    DMX_CHAN_TYPE_MAX = 0x7F
} dmx_chan_type;

/* refer to hi_unf_video.h, Defines the type of the video frame. */ /* CNcomment: 定义视频帧的类型枚举 */
typedef enum {
    DMX_FRM_TYPE_UNKNOWN,   /* Unknown */  /* CNcomment: 未知的帧类型 */
    DMX_FRM_TYPE_I,         /* I frame */  /* CNcomment: I帧 */
    DMX_FRM_TYPE_P,         /* P frame */  /* CNcomment: P帧 */
    DMX_FRM_TYPE_B,         /* B frame */  /* CNcomment: B帧 */
    DMX_FRM_TYPE_IDR,       /* IDR frame */ /* CNcomment: IDR帧 */
    DMX_FRM_TYPE_BLA,       /* BLA frame */ /* CNcomment: BLA帧 */
    DMX_FRM_TYPE_CRA,       /* CRA frame */ /* CNcomment: CRA帧 */
    DMX_FRM_TYPE_MAX
} dmx_vid_frm_type;

/* index data */
typedef struct {
    dmx_vid_frm_type   frame_type;
    hi_s64             pts_us;
    hi_u64             global_offset;
    hi_u32             frame_size;
    hi_u32             data_time_ms;

    /* hevc private */
    hi_s16              cur_poc;
    hi_u16              ref_poc_cnt;
    hi_s16              ref_poc[16]; /* according to hevc protocol, max reference poc is 16. */
} dmx_tee_rec_index;

/* pvr index's SCD descriptor */
typedef struct {
    hi_u8   index_type;   /* type of index(pts,sc,pause,ts) */
    hi_u8   start_code;   /* type of start code, 1byte after 000001 */

    hi_s64  pts_us;
    hi_u64  global_offset;        /* start code offset in global buffer */
    hi_u8   data_after_sc[8];      /* 1~8 byte next to SC */
    hi_u32  extra_scdata_size;     /* extra data size */
    hi_u32  extra_real_scdata_size; /* real extra data size */
    hi_u64  extra_scdata_phy_addr;  /* extra data phy addr */
    hi_u8   *extra_scdata;        /* save extra more data */
} findex_api_scd;

typedef struct {
    hi_u32 rec_pid;
    hi_u32 idx_pid;
    hi_u32 parse_offset;
    findex_api_scd findex_scd;
    hi_u32 findex_scd_size;
    dmx_tee_rec_index dmx_rec_index;
    hi_u32 rec_index_size;
} dmx_tee_scd_buf;

hi_s32 tee_dmx_init(hi_void);
hi_s32 tee_dmx_deinit(hi_void);

hi_s32 __tee_demux_ioctl(unsigned long cmd, const hi_void *pri_args);

hi_s32 tee_dmx_create_ramport(hi_u32 ram_id, hi_u32 buf_size, hi_u32 flush_buf_size, hi_u32 dsc_buf_size,
    dmx_tee_ramport_info *tee_ramport_info);
hi_s32 tee_dmx_destroy_ramport(hi_u32 ram_id, const dmx_tee_ramport_info *tee_ramport_info);
hi_s32 tee_dmx_set_ramport_dsc(hi_u32 ram_id, const dmx_tee_ramport_dsc *tee_ramport_dsc);
hi_s32 tee_dmx_create_play_chan(hi_u32 id, dmx_chan_type chan_type, hi_u32 buf_size, dmx_tee_mem_swap_info *mem_info);
hi_s32 tee_dmx_destroy_play_chan(hi_u32 id, dmx_chan_type chan_type, const dmx_tee_mem_swap_info *mem_info);
hi_s32 tee_dmx_attach_play_chan(hi_u32 chan_id, dmx_chan_type chan_type, hi_u32 raw_pidch_id,
    hi_u32 master_raw_pidch_id);
hi_s32 tee_dmx_detach_play_chan(hi_u32 chan_id, dmx_chan_type chan_type, hi_u32 raw_pidch_id);
hi_s32 tee_dmx_create_rec_chan(hi_u32 id, hi_u32 buf_size, dmx_tee_mem_swap_info *mem_info);
hi_s32 tee_dmx_destroy_rec_chan(hi_u32 id, const dmx_tee_mem_swap_info *mem_info);
hi_s32 tee_dmx_attach_rec_chan(const dmx_rec_attach_info *rec_attach_ptr);
hi_s32 tee_dmx_detach_rec_chan(const dmx_rec_detach_info *rec_detach_ptr);
hi_s32 tee_dmx_update_play_read_idx(hi_u32 buf_id, dmx_chan_type chan_type, hi_u32 read_idx);
hi_s32 tee_dmx_update_rec_read_idx(hi_u32 buf_id, hi_u32 read_idx);
hi_s32 tee_dmx_acquire_buf_id(hi_u32 *buf_id_ptr);
hi_s32 tee_dmx_release_buf_id(hi_u32 buf_id);
hi_s32 tee_dmx_detach_raw_pidch(hi_u32 raw_pidch);
hi_s32 tee_dmx_config_secbuf(hi_u32 chan_id, dmx_chan_type chan_type);
hi_s32 tee_dmx_deconfig_secbuf(hi_u32 chan_id, dmx_chan_type chan_type);
hi_s32 tee_dmx_enable_rec_chn(hi_u32 id);
hi_s32 tee_dmx_fixup_hevc_index(dmx_tee_scd_buf *scd_buf_info);
hi_s32 tee_dmx_sec_pes_flush_shadow_buf(hi_u32 chan_id, dmx_chan_type chan_type, hi_u32 offset, hi_bool *rool_flag,
    hi_u32 *data_len);
hi_s32 tee_dmx_flt_sec_pes_lock(const dmx_tee_flt_info *flt_info);
hi_s32 tee_dmx_config_cc_drop(const dmx_tee_cc_drop_info *cc_drop_info);
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __TEE_DEMUX_UTILS_H__ */
