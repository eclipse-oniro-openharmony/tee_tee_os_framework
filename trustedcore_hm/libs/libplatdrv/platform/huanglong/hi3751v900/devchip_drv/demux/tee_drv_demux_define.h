/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Tee defined header file.
 * Author: SDK
 * Create: 2019-10-11
 */

#ifndef __TEE_DRV_DEMUX_DEFINE_H__
#define __TEE_DRV_DEMUX_DEFINE_H__


#include "hi_type_dev.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_common.h"

#include "hi_bitmap.h"
#include "tee_demux_utils.h"
#include "tee_drv_demux_config.h"
#include "tee_drv_demux_ioctl.h"

extern void *hi_tee_drv_hal_asm_memmove(hi_void *dest, const hi_void *src, unsigned int n);
#define TEE_DEMUX_MEMCPY hi_tee_drv_hal_asm_memmove

#define DMX_INVALID_DEMUX_ID            0xffffffffU
#define DMX_INVALID_REC_ID              0xffffffffU
#define DMX_INVALID_PORT_ID             0xffffffffU
#define DMX_INVALID_CHAN_ID             0xffffU
#define DMX_INVALID_KEY_ID              0xffffU

#define DMX_INVALID_PID                 0x1fffU
#define DMX_PES_HEADER_LENGTH           0x9

typedef struct {
    hi_u8   *buf_start_vir_addr;
    hi_u32  buf_size;
    hi_u64  buf_start_addr;
    hi_u64  shadow_buf_start_addr;
    hi_u8   *shadow_buf_start_vir_addr;
    hi_u32  shadow_buf_size;
    hi_bool flush_shadow_buf;
    hi_u32  buf_id;
} dmx_playbuf_info;

typedef struct {
    hi_u8  *buf_start_vir_addr;
    hi_u64 buf_start_addr;
    hi_u32 buf_size;
    hi_u32 buf_id;
} dmx_recbuf_info;

typedef struct {
    hi_u8  *buf_vir_addr;
    hi_u8  *dsc_buf_vir_addr;
    hi_u8  *flush_buf_vir_addr;

    hi_u32 buf_size;
    hi_u32 flush_buf_size;
    hi_u32 dsc_buf_size;

    hi_u64 buf_phy_addr;
    hi_u64 flush_buf_phy_addr;
    hi_u64 dsc_buf_phy_addr;
} dmx_tsbuf_info;

typedef enum {
    DMX_BUF_TYPE_TSBUF = 0,      /* secure ts buffer */
    DMX_BUF_TYPE_RECBUF,         /* secure rec buffer */
    DMX_BUF_TYPE_PLAYBUF,        /* secure play buffer */

    DMX_BUF_TYPE_MAX
} dmx_buf_type;

typedef struct {
    struct hi_tee_hal_mutex    lock_ts;
    TEE_UUID           user_uuid;
    hi_u32             dmx_id;
    hi_u32             key_id;
    dmx_playbuf_info   ts_secbuf;
} dmx_play_ts;

typedef struct {
    struct hi_tee_hal_mutex    lock_pes_sec;
    TEE_UUID           user_uuid;
    hi_u32             dmx_id;
    hi_u32             key_id;
    dmx_chan_type      dmx_play_type;
    dmx_playbuf_info   pes_sec_secbuf;
} dmx_play_pes_sec;

typedef struct {
    struct hi_tee_hal_mutex    lock_avpes;
    TEE_UUID           user_uuid;
    hi_u32             dmx_id;
    hi_u32             key_id;
    hi_void           *averify;
    dmx_chan_type      dmx_play_type;
    dmx_playbuf_info   avpes_secbuf;
} dmx_play_avpes;

typedef struct {
    struct hi_tee_hal_mutex    lock_key;
    TEE_UUID       user_uuid;
    hi_u32         dmx_id;
    hi_u32         key_id;
    hi_u32         ca_type;
    hi_u32         ca_entropy;
    hi_u32         alg;
    hi_u32         key_len;
    hi_bool        keyslot_create_en;
    hi_handle      ks_handle;
    hi_bool        keyslot_attached;
    dmx_dsc_key_mode key_secure_mode;
    hi_u32  iv[DMX_KEY_MAX_LEN / sizeof(hi_u32)];
} dmx_key_info;

typedef struct {
    struct hi_tee_hal_mutex  lock_rec;  /* not use now */
    TEE_UUID              user_uuid;
    hi_u32                dmx_id;
    hi_s32                pic_parser;
    dmx_recbuf_info       rec_secbuf;
    tee_dmx_rec_index    last_frame_info;
} dmx_rec_info;

typedef struct {
    struct hi_tee_hal_mutex  lock_dmx;  /* not use now */
    hi_u32                   ramport_id;
} dmx_dmx_info;

typedef struct {
    struct hi_tee_hal_mutex  lock_ramport;
    hi_u32                ramport_id;
    dmx_tsbuf_info        tsbuf_secbuf;
    TEE_UUID              user_uuid;
} dmx_ramport_info;

/* structure definition */
typedef struct {
    hi_u32 cmd;
    hi_s32(*fun_entry)(hi_void *arg);
} dmx_ioctl_entry;

typedef struct {
    hi_u32                      io_base;
    hi_u32                      io_mdsc_base;
    hi_u64                      cb_ttbr;

    hi_u32                      dmx_pid_copy_cnt;
    hi_u32                      dmx_raw_pidch_cnt;
    hi_u32                      dmx_scd_cnt;

    dmx_dmx_info                dmx_info[DMX_CNT];
    hi_u32                      dmx_cnt;
    struct hi_tee_hal_mutex     lock_all_dmx;
    DECLARE_BITMAP(dmx_bitmap, DMX_CNT);

    dmx_ramport_info            ramport_info[DMX_RAMPORT_CNT];
    hi_u32                      ramport_cnt;
    struct hi_tee_hal_mutex     lock_all_ramport;
    DECLARE_BITMAP(ramport_bitmap, DMX_RAMPORT_CNT);

    dmx_play_ts                 play_ts[DMX_PLAY_TS_CNT];
    hi_u32                      play_ts_cnt;
    struct hi_tee_hal_mutex     lock_all_play_ts;
    DECLARE_BITMAP(play_ts_bitmap, DMX_PLAY_TS_CNT);

    dmx_play_pes_sec            play_pes_sec[DMX_PLAY_SEC_PES_CNT];
    hi_u32                      play_pes_sec_cnt;
    struct hi_tee_hal_mutex     lock_all_play_pes_sec;
    DECLARE_BITMAP(play_pes_sec_bitmap, DMX_PLAY_TS_CNT);

    dmx_play_avpes              play_avpes[DMX_AVR_CNT];
    dmx_rec_info                rec_info[DMX_AVR_CNT];
    hi_u32                      avr_cnt;
    struct hi_tee_hal_mutex     lock_all_avr;
    DECLARE_BITMAP(avr_bitmap, DMX_AVR_CNT);

    dmx_key_info                key_info[DMX_KEY_CNT];
    hi_u32                      key_cnt;
    struct hi_tee_hal_mutex     lock_all_key;
    DECLARE_BITMAP(key_bitmap, DMX_KEY_CNT);

    struct hi_tee_hal_mutex     lock_all_buf;
    hi_u32                      buf_cnt;
    DECLARE_BITMAP(buf_bitmap, DMX_BUF_CNT);

    dmx_ioctl_entry             *dmx_ioctl_entry;

    struct hi_tee_hal_mutex     total_lock;
}tee_dmx_mgmt;

#endif      /* __TEE_DRV_DEMUX_DEFINE_H__ */
