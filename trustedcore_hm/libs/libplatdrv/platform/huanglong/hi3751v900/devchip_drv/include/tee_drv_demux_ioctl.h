/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description:
 * Author: SDK
 * Create: 2019-10-11
 */

#ifndef __TEE_DRV_DEMUX_IOCTL_H__
#define __TEE_DRV_DEMUX_IOCTL_H__

#include "hi_type_dev.h"
#include "hi_tee_module_id.h"
#include "hi_tee_drv_syscall_id.h"
#include "sre_access_control.h"
#include "hmdrv_stub.h"
#include "errno.h"

#include "tee_demux_utils.h"
#include "tee_drv_klad_struct.h"

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

#define _IOC_NRBITS     8
#define _IOC_TYPEBITS   8

/*
 * Let any architecture override either of the following before
 * including this file.
 */
#ifndef _IOC_SIZEBITS
# define _IOC_SIZEBITS  14
#endif

#ifndef _IOC_DIRBITS
# define _IOC_DIRBITS   2
#endif

#define _IOC_NRMASK     ((1 << _IOC_NRBITS) - 1)
#define _IOC_TYPEMASK   ((1 << _IOC_TYPEBITS) - 1)
#define _IOC_SIZEMASK   ((1 << _IOC_SIZEBITS) - 1)
#define _IOC_DIRMASK    ((1 << _IOC_DIRBITS) - 1)

#define _IOC_NRSHIFT    0
#define _IOC_TYPESHIFT  (_IOC_NRSHIFT + _IOC_NRBITS)
#define _IOC_SIZESHIFT  (_IOC_TYPESHIFT + _IOC_TYPEBITS)
#define _IOC_DIRSHIFT   (_IOC_SIZESHIFT + _IOC_SIZEBITS)

/*
 * Direction bits, which any architecture can choose to override
 * before including this file.
 */
#ifndef _IOC_NONE
# define _IOC_NONE      0U
#endif

#ifndef _IOC_WRITE
# define _IOC_WRITE     1U
#endif

#ifndef _IOC_READ
# define _IOC_READ      2U
#endif

#define _IOC(dir,type,nr,size) \
        (((dir)  << _IOC_DIRSHIFT) | \
         ((type) << _IOC_TYPESHIFT) | \
         ((nr)   << _IOC_NRSHIFT) | \
         ((size) << _IOC_SIZESHIFT))

#define _IOC_TYPECHECK(t) (sizeof(t))

/* used to create numbers */
#define _IO(type, nr)             _IOC(_IOC_NONE, (type), (nr), 0)
#define _IOR(type, nr, size)      _IOC(_IOC_READ, (type), (nr), (_IOC_TYPECHECK(size)))
#define _IOW(type, nr, size)      _IOC(_IOC_WRITE, (type), (nr), (_IOC_TYPECHECK(size)))
#define _IOWR(type, nr, size)     _IOC(_IOC_READ | _IOC_WRITE, (type), (nr), (_IOC_TYPECHECK(size)))
#define _IOR_BAD(type, nr, size)  _IOC(_IOC_READ, (type), (nr), sizeof(size))
#define _IOW_BAD(type, nr, size)  _IOC(_IOC_WRITE, (type), (nr), sizeof(size))
#define _IOWR_BAD(type, nr, size) _IOC(_IOC_READ | _IOC_WRITE, (type), (nr), sizeof(size))

/* used to decode ioctl numbers.. */
#define _IOC_DIR(nr)            (((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
#define _IOC_TYPE(nr)           (((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
#define _IOC_NR(nr)             (((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _IOC_SIZE(nr)           (((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK)

/* and for the drivers/sound files... */
#define IOC_IN  (_IOC_WRITE << _IOC_DIRSHIFT)
#define IOC_OUT (_IOC_READ << _IOC_DIRSHIFT)
#define IOC_INOUT  ((_IOC_WRITE | _IOC_READ) << _IOC_DIRSHIFT)
#define IOCSIZE_MASK  (_IOC_SIZEMASK << _IOC_SIZESHIFT)
#define IOCSIZE_SHIFT  (_IOC_SIZESHIFT)

/* dmx cmd mask */
#define DMX_CMD_MASK               0xF0
#define DMX_GLB_CMD                0x00

/* HANDLE macro */
#define DMX_HANDLE_MAGIC        (0xB)
#define dmx_id_2_handle(id)     ((HI_ID_DEMUX << 24) | (DMX_HANDLE_MAGIC << 20) | (id & 0xFFFFF))
#define dmx_handle_2_id(handle) ((handle) & 0xFFFFF)

#define DMX_CHECK_HANDLE(handle) do { \
    if ((((handle) >> 24) & 0xFF) != HI_ID_DEMUX || (((handle) >> 20) & 0xF) != DMX_HANDLE_MAGIC) { \
        hi_log_err("invalid demux handle!\n"); \
        return HI_ERR_DMX_INVALID_PARA; \
    } \
} while (0)

#define KS_HANDLE_2_ID(handle)  ((handle) & 0x0000FFFF)
#define CHECK_KEYSLOT_HANDLE(handle) do {             \
    if (((handle >> 24) & 0xFF) != HI_ID_KEYSLOT) {  \
        return HI_ERR_DMX_INVALID_PARA;               \
    }                                                 \
} while (0)

#define check_keyslot_handle_goto(handle, out_flag) do {  \
    if (((handle >> 24) & 0xFF) != HI_ID_KEYSLOT) {  \
        ret = HI_ERR_DMX_INVALID_PARA;                \
        goto out_flag;                                \
    }                                                 \
} while (0)

typedef struct {
    hi_u32 ram_id;         /* [in] */
    hi_u32 buf_size;       /* [in] */
    hi_u32 flush_buf_size; /* [in] */
    hi_u32 dsc_buf_size;   /* [in] */
    dmx_tee_ramport_info tee_ramport_info; /* [inout] */
} dmx_ramport_buf_info;

typedef struct {
    hi_u32 ram_id;         /* [in] */
    dmx_tee_ramport_dsc tee_ramport_dsc; /* [inout] */
} dmx_ramport_dsc_info;

typedef struct {
    hi_u32 id;        /* [in] */
    hi_u32 buf_size;  /* [in] */
    dmx_chan_type chan_type; /* [in] */
    dmx_tee_mem_swap_info tee_mem_info; /* [inout] */
} dmx_chan_info;

typedef struct {
    hi_u32 chan_id;
    dmx_chan_type chan_type;
    hi_u32 raw_pidch_id;
    hi_u32 master_raw_pidch_id;
} dmx_play_attach_info;

typedef struct {
    hi_u32 chan_id;
    dmx_chan_type chan_type;
    hi_u32 raw_pidch_id;
} dmx_play_detach_info;

typedef struct {
    hi_u32 buf_id;
    dmx_chan_type chan_type;
    hi_u32 read_idx;
} dmx_play_idx_info;

typedef dmx_play_idx_info dmx_rec_idx_info;

typedef struct {
    hi_u32 chan_id;
    dmx_chan_type chan_type;
} dmx_config_secbuf_info;

/* refer to hi_unf_video.h, Defines the type of the video frame. */ /* CNcomment: 定义视频帧的类型枚举 */
typedef enum {
    TEE_FRAME_TYPE_UNKNOWN,   /* Unknown */  /* CNcomment: 未知的帧类型 */
    TEE_FRAME_TYPE_I,         /* I frame */  /* CNcomment: I帧 */
    TEE_FRAME_TYPE_P,         /* P frame */  /* CNcomment: P帧 */
    TEE_FRAME_TYPE_B,         /* B frame */  /* CNcomment: B帧 */
    TEE_FRAME_TYPE_IDR,       /* IDR frame */ /* CNcomment: IDR帧 */
    TEE_FRAME_TYPE_BLA,       /* BLA frame */ /* CNcomment: BLA帧 */
    TEE_FRAME_TYPE_CRA,       /* CRA frame */ /* CNcomment: CRA帧 */
    TEE_FRAME_TYPE_MAX
} tee_video_frame_type;

/* index data */
typedef struct {
    tee_video_frame_type      frame_type;
    hi_s64                    pts_us;
    hi_u64                    global_offset;
    hi_u32                    frame_size;
    hi_u32                    data_time_ms;

    /* hevc private */
    hi_s16                    cur_poc;
    hi_u16                    ref_poc_cnt;
    hi_s16                    ref_poc[16]; /* according to hevc protocol, max reference poc is 16. */
} tee_dmx_rec_index;

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
} findex_scd;

typedef struct {
    hi_u32 rec_id;
    hi_u32 idx_pid;
    hi_u32 parse_offset;
    findex_scd findex_scd;
    hi_u32 scd_buf_size;
    tee_dmx_rec_index dmx_rec_index;
    hi_u32 index_buf_size;
} dmx_scd_buf;

typedef struct {
    hi_bool rool_flag;
    hi_u32 chan_id;
    dmx_chan_type chan_type;
    hi_u32 offset;
    hi_u32 data_len;
} dmx_sec_pes_flush_info;

/****************** dsc_fct  begin************************/
#define DMX_SYS_KEY_LEN                 32
#define DMX_PID_CHAN_CNT_PER_BAND       32

typedef enum {
    DMX_CA_NORMAL = 0,    /* <common CA */
    DMX_CA_ADVANCE,       /* <advanced CA */

    DMX_CA_MAX
} dmx_dsc_ca_type;

typedef enum {
    DMX_DSC_KEY_EVEN = 0,
    DMX_DSC_KEY_ODD,
    DMX_DSC_KEY_SYS,
} dmx_dsc_key_type;

/* CA entropy reduction mode */
typedef enum {
    DMX_CA_ENTROPY_CLOSE = 0,  /* <64bit */
    DMX_CA_ENTROPY_OPEN,       /* <48bit */

    DMX_CA_ENTROPY_MAX
} dmx_dsc_entropy;

typedef enum {
    DMX_KEY_MODE_TEE_SECURE = 0,  /* create in TEE, secure key */
    DMX_KEY_MODE_TEE_NONSECURE,   /* create in TEE, nonsecure key */
    DMX_KEY_MODE_REE_NONSECURE,   /* create in REE, nonsecure key */

    DMX_KEY_MODE_MAX
} dmx_dsc_key_mode;

typedef struct {
    dmx_dsc_ca_type     ca_type;              /* whether the descrambler adopts advanced CA. */
    hi_crypto_engine_alg alg;                  /* Descrambling protocol type of the descrambler. */
    dmx_dsc_entropy     ca_entropy;           /* CA entropy reduction mode,for CSA2.0 */
    dmx_dsc_key_mode    key_secure_mode;      /* Secure indication. */
    hi_bool              keyslot_create_en;    /* Whether the keysloy will be created, when create descrambler. */
} dmx_dsc_attrs;

typedef struct {
    dmx_dsc_attrs          attrs;      /* [in] */
    hi_handle              handle;     /* [out] */
} dmx_create_dsc_fct_info;

typedef struct {
    hi_handle              handle;     /* [in] */
    dmx_dsc_attrs          attrs;      /* [out] */
} dmx_get_dsc_fct_attr_info;

typedef struct {
    hi_handle               handle;     /* [in] */
    dmx_dsc_attrs           attrs;      /* [in] */
} dmx_set_dsc_fct_attr_info;

typedef struct {
    hi_handle               handle;            /* [in] */
    hi_handle               target_handle;     /* [in] */
} dmx_dsc_fct_attach_info, dmx_dsc_fct_detach_info;

typedef struct {
    hi_handle               handle;        /* [in] */
    hi_handle               ks_handle;     /* [out] */
} dmx_dsc_fct_get_ks_handle_info;

typedef struct {
    hi_handle               handle;                 /* [in] */
    hi_u32                  len;                    /* [in] */
    hi_u8                   key[DMX_SYS_KEY_LEN];   /* [in] */
} dmx_dsc_fct_sys_key_info;

typedef struct {
    hi_handle               handle;                 /* [in] */
    hi_u32                  len;                    /* [in] */
    hi_u8                   key[DMX_KEY_MAX_LEN];   /* [in] */
} dmx_dsc_fct_iv_key_info;

typedef struct {
    hi_handle               pid_ch_handle;          /* [in] */
    hi_handle               dsc_handle;             /* [out] */
} dmx_dsc_fct_get_key_handle_info;

typedef struct {
    hi_u32                  dmx_id;          /* [in] */
    hi_u32                  pid;             /* [in] */
    hi_u32                  chan_num;        /* [out] */
    hi_handle               chan[DMX_PID_CHAN_CNT_PER_BAND]; /* [out] */
} dmx_dsc_fct_get_chan_handle_info;

/* ioctl definitions */
#define DMX_TEE_IOCTL_GLB_INIT                  _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x0), hi_handle)
#define DMX_TEE_IOCTL_GLB_DEINIT                _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x1), hi_handle)

#define DMX_TEE_IOCTL_GLB_CREATE_RAMPORT        _IOWR(HI_ID_DEMUX, (DMX_GLB_CMD + 0x2), dmx_ramport_buf_info)
#define DMX_TEE_IOCTL_GLB_DESTROY_RAMPORT       _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x3), dmx_ramport_buf_info)
#define DMX_TEE_IOCTL_GLB_SET_RAMPORT_DSC       _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x4), dmx_ramport_dsc_info)

#define DMX_TEE_IOCTL_GLB_CREATE_PLAY_CHAN      _IOWR(HI_ID_DEMUX, (DMX_GLB_CMD + 0x5), dmx_chan_info)
#define DMX_TEE_IOCTL_GLB_DESTROY_PLAY_CHAN     _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x6), dmx_chan_info)

#define DMX_TEE_IOCTL_GLB_ATTACH_PLAY_CHAN      _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x7), dmx_play_attach_info)
#define DMX_TEE_IOCTL_GLB_DETACH_PLAY_CHAN      _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x8), dmx_play_detach_info)

#define DMX_TEE_IOCTL_GLB_CREATE_REC_CHAN       _IOWR(HI_ID_DEMUX, (DMX_GLB_CMD + 0x9), dmx_chan_info)
#define DMX_TEE_IOCTL_GLB_DESTROY_REC_CHAN      _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0xA), dmx_chan_info)

#define DMX_TEE_IOCTL_GLB_ATTACH_REC_CHAN       _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0xB), dmx_rec_attach_info)
#define DMX_TEE_IOCTL_GLB_DETACH_REC_CHAN       _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0xC), dmx_rec_detach_info)

#define DMX_TEE_IOCTL_GLB_UPDATE_PLAY_READ_IDX  _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0xD), dmx_play_idx_info)
#define DMX_TEE_IOCTL_GLB_UPDATE_REC_READ_IDX   _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0xE), dmx_rec_idx_info)
#define DMX_TEE_IOCTL_GLB_ACQUIRE_SECBUF_ID     _IOWR(HI_ID_DEMUX, (DMX_GLB_CMD + 0xF), hi_u32)
#define DMX_TEE_IOCTL_GLB_RELEASE_SECBUF_ID     _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x10), hi_u32)
#define DMX_TEE_IOCTL_GLB_DETACH_RAW_PIDCH      _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x11), hi_u32)

#define DMX_TEE_IOCTL_GLB_CONFIG_SECBUF         _IOW(HI_ID_DEMUX, (DMX_GLB_CMD + 0x12), dmx_config_secbuf_info)
#define DMX_TEE_IOCTL_GLB_DECONFIG_SECBUF       _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x13), dmx_config_secbuf_info)
#define DMX_TEE_IOCTL_GLB_ENABLE_REC_CHAN       _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x14), hi_u32)
#define DMX_TEE_IOCTL_GLB_FIXUP_HEVC_INDEX      _IOWR(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x15), dmx_scd_buf)
#define DMX_TEE_IOCTL_GLB_FLUSH_PES_SEC_DATA    _IOWR(HI_ID_DEMUX, (DMX_GLB_CMD + 0x16), dmx_sec_pes_flush_info)
#define DMX_TEE_IOCTL_GLB_FLT_PES_SEC_LOCK      _IOW(HI_ID_DEMUX, (DMX_GLB_CMD + 0x17), dmx_tee_flt_info)
#define DMX_TEE_IOCTL_GLB_CONFIG_CC_DROP_INFO   _IOW(HI_ID_DEMUX, (DMX_GLB_CMD + 0x18), dmx_tee_cc_drop_info)

#define DMX_TEE_IOCTL_GLB_DSCFCT_CREATE             _IOWR(HI_ID_DEMUX, (DMX_GLB_CMD + 0x19), dmx_create_dsc_fct_info)
#define DMX_TEE_IOCTL_GLB_DSCFCT_GETATTRS           _IOWR(HI_ID_DEMUX, (DMX_GLB_CMD + 0x1A), dmx_get_dsc_fct_attr_info)
#define DMX_TEE_IOCTL_GLB_DSCFCT_SETATTRS           _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x1B), dmx_set_dsc_fct_attr_info)
#define DMX_TEE_IOCTL_GLB_DSCFCT_ATTACH             _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x1C), dmx_dsc_fct_attach_info)
#define DMX_TEE_IOCTL_GLB_DSCFCT_DETACH             _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x1D), dmx_dsc_fct_detach_info)
#define DMX_TEE_IOCTL_GLB_DSCFCT_ATTACH_KEYSLOT     _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x1E), dmx_dsc_fct_attach_info)
#define DMX_TEE_IOCTL_GLB_DSCFCT_DETACH_KEYSLOT     _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x1F), dmx_dsc_fct_detach_info)
#define DMX_TEE_IOCTL_GLB_DSCFCT_GET_KS_HANDLE      _IOWR(HI_ID_DEMUX, (DMX_GLB_CMD + 0x20), \
    dmx_dsc_fct_get_ks_handle_info)
#define DMX_TEE_IOCTL_GLB_DSCFCT_SET_KEY            _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x21), dmx_dsc_fct_sys_key_info)
#define DMX_TEE_IOCTL_GLB_DSCFCT_SET_EVEN_IV        _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x22), dmx_dsc_fct_iv_key_info)
#define DMX_TEE_IOCTL_GLB_DSCFCT_SET_ODD_IV         _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x23), dmx_dsc_fct_iv_key_info)
#define DMX_TEE_IOCTL_GLB_DSCFCT_DESTROY            _IOW(HI_ID_DEMUX,  (DMX_GLB_CMD + 0x24), hi_handle)
#define DMX_TEE_IOCTL_GLB_DSCFCT_GET_KEY_HANDLE     _IOWR(HI_ID_DEMUX, (DMX_GLB_CMD + 0x25), \
    dmx_dsc_fct_get_key_handle_info)
#define DMX_TEE_IOCTL_GLB_DSCFCT_GET_CHAN_HANDLE    _IOWR(HI_ID_DEMUX, (DMX_GLB_CMD + 0x26), \
    dmx_dsc_fct_get_chan_handle_info)

#define DMX_TEE_IOCTL_CMD_COUNT                 0x27

#define DMX_TEE_IOCTL_ARG_MAX_SIZE              0x100

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* end of #ifndef __TEE_DRV_DEMUX_IOCTL_H__*/
