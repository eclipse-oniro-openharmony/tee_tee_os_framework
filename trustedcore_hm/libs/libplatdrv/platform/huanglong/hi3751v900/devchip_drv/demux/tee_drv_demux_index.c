/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2004-2020. All rights reserved.
 * Description: make video stream index info for trick play. support multi video standards
 */

#include <stddef.h>
#include "tee_drv_demux_utils.h"
#include "tee_drv_demux_define.h"
#include "tee_drv_demux_index.h"

#define  FIDX_MAX_CTX_NUM          16 /* maximum channel can be processed are the same as record channel */
#define  SC_SUPPORT_DATA_SIZE      16          /*! SC support data size, 16 bytes */
#define  BUF_NAME_LEN              32

/* #ifdef HEVC_ENABLE */
#define FIDX_HEVC_NAL_SLICE_TRAIL_N                      0      /* 0 */
#define FIDX_HEVC_NAL_SLICE_TRAIL_R                      1      /* 1 */
#define FIDX_HEVC_NAL_SLICE_TSA_N                         2       /* 2 */
#define FIDX_HEVC_NAL_SLICE_TLA_R                         3       /* 3 */
#define FIDX_HEVC_NAL_SLICE_STSA_N                       4       /* 4 */
#define FIDX_HEVC_NAL_SLICE_STSA_R                       5       /* 5 */
#define FIDX_HEVC_NAL_SLICE_RADL_N                       6       /* 6 */
#define FIDX_HEVC_NAL_SLICE_RADL_R                       7       /* 7 */
#define FIDX_HEVC_NAL_SLICE_RASL_N                        8       /* 8 */
#define FIDX_HEVC_NAL_SLICE_RASL_R                        9       /* 9 */

#define FIDX_HEVC_NAL_SLICE_BLA_W_LP                   16    /* 16 */
#define FIDX_HEVC_NAL_SLICE_BLA_W_RADL              17    /* 17 */
#define FIDX_HEVC_NAL_SLICE_BLA_N_LP                    18    /* 18 */
#define FIDX_HEVC_NAL_SLICE_IDR_W_RADL               19    /* 19 */
#define FIDX_HEVC_NAL_SLICE_IDR_N_LP                     20    /* 20 */
#define FIDX_HEVC_NAL_SLICE_CRA                              21    /* 21 */
#define FIDX_HEVC_NAL_RESERVED_IRAP_VCL22        22    /* 22 */
#define FIDX_HEVC_NAL_RESERVED_IRAP_VCL23        23    /* 23 */

#define FIDX_HEVC_NAL_VPS               32
#define FIDX_HEVC_NAL_SPS               33
#define FIDX_HEVC_NAL_PPS               34
#define FIDX_HEVC_NAL_PRE_SEI        39
#define FIDX_HEVC_NAL_SUF_SEI        40

#define FIDX_HEVC_I_SLICE                   2
#define FIDX_HEVC_P_SLICE                 1
#define FIDX_HEVC_B_SLICE                 0

/* ! start code type */
typedef enum {
    SC_TYPE_UNKNOWN = 0,
    SC_TYPE_SPS,
    SC_TYPE_PPS,
    SC_TYPE_PIC,
    SC_TYPE_SLICE,
    SC_TYPE_NONSLICE,
    SC_TYPE_VPS,
    SC_TYPE_MAX
} sc_type;

/* ! start code description */
typedef struct {
    sc_type     sc_type;
    hi_s32      sc_id;           /* ! for H.264, assign PPS or SPS ID; for non-H.264, assign the byte after 00 00 01 */
    hi_s32      sup_sc_id;       /* ! for H.264 only, record the SPS ID for the current used PPS */
    hi_s64      global_offset;   /* ! the offset of the start code, in the global(whole) stream data space */
    hi_s32      offset_inpacket; /* ! the offset of the start code, in the stream data packet */
    hi_s32      packet_count;    /* ! the stream data packet number where the start code was found */
    hi_s32      profile_id;

    /* VPS */
    /* SPS */
    hi_s32      max_cu_depth;
    hi_s32      max_cu_width;
    hi_s32      max_cu_height;
    hi_s32      pic_width_in_luma_samples;
    hi_s32      pic_height_in_luma_samples;
    /* PPS */
    hi_s32      seq_parameter_set_id;
    hi_s32      dependent_slice_segments_enabled_flag;
    hi_s32      num_extra_slice_header_bits;
} sc_info;

/*! state of the instance */
typedef enum {
    CTX_STATE_DISABLE = 0,
    CTX_STATE_ENABLE,
    CTX_STATE_BUTT
} ctx_state;

/* ! context */
typedef struct {
    ctx_state       ctx_state;
    vid_standard    video_standard;  /*! video standard type */
    strm_type       strm_type;       /*! stream type, ES or PES */
    hi_s64          pts;          /* ! current PTS, usually equals to the pts of the latest stream packet */
    sc_info         sps[32];       /* size 32 */
                                   /*
                                    * ! start code of the sequence level parameters.
                                    * H264  - sps
                                    * MPEG2 - sequence header
                                    * AVS   - sequence header
                                    * MPEG4 - VOL or higher
                                    */
    /*! one SPS can be used by one I frame only, an I frame without SPS will be treated as P or B frame */
    hi_u8           sps_fresh[32]; /* size 32 */
    sc_info         pps[256];      /* size 256 */
                                   /*
                                    * ! picture level parameter
                                    * H264  - pps
                                    * MPEG2 - picture header
                                    * AVS   - picture header
                                    * MPEG4 - VOP header
                                    */
    /* previous 2 bytes, for start code detection, to prevent the 00 or 00 00 lost */
    hi_u8           prev2bytes[2]; /* ! store the latest 2 byte */

    /* this SC store the latest tetected start code */
    hi_s32          this_scvalid;  /*! indicate the support data of this start code is ready for use */
    sc_info         this_sc;        /*
                                    * ! when a start code was found, the support data is probably not enough.
                                    * If so, this start
                                    */
    hi_u8           this_scdata[SC_SUPPORT_DATA_SIZE]; /* ! has to be stored temporarily to wait more data */
    hi_s32          this_scdata_len;  /* ! actual support data size, usually equals to SC_SUPPORT_DATA_SIZE */

    sc_info         sei_follow_slice;  /*
                                        * ! record the SEI start code followed the last slice of the previous picture.
                                        * Generally this SEI is the start of a new picture
                                        */

    /* frame, a set of frame info probably can be generated after 'this SC' was processed */
    frame_pos       new_frame_pos;     /*! frame info to be output, temporarily stored here */
    hi_s32          wait_frame_size; /* !indicate if most info of new_frame_pos has been ready, except the frame size */
    hi_s32          sps_id;          /*! H264: SPS ID */
    hi_s32          pps_id;          /*! H264: PPS ID */
    hi_u32         *param;

    /* HEVC_ENABLE */
    hi_u32          next_pts;
    sc_info         vps[16]; /* size 16 */
    hi_s32          vps_sps_pps_err;
    hi_s32          is_ref_idc;

    hi_s64           new_frm_offset;
    hi_s64           last_vps_offset;
    hi_s64           last_sps_offset;
    hi_s64           last_pps_offset;
    hi_s64           last_sei_offset;
    hi_s64           first_nal_offset;

    hevc_ctx        *hevc_ctx;
    hi_u8           *hevc_scdata;     /* hevc special buffer, refer to this_sc_data. */
    dmx_recbuf_info hevc_ctx_buf;   /* for hevc hevc_ctx struct. */
} fidx_ctx;

typedef struct {
    hi_u32 *buff_z;
    hi_u32 *buff_h;
    hi_u32 *buff_v;
    hi_u32 *buff_d;
    hi_s32 buffer_size;
    hi_s32 i_width;
    hi_s32 i_height;
    hi_s32 i_depth;
} sig_last_scan_info;

/* static shared data */
static hi_s32 g_hevc_rec_dev_fd = -1;
static fidx_ctx *g_fidx_iis = HI_NULL;

/* callback, used to output infomation */
static hi_void(*g_out_put_frame_position)(hi_u32 *param, const frame_pos *sc_ino);

/* function declaration */
static hi_s32 process_this_sc(hi_s32 inst_idx);

static hi_s32 process_sc_hevc(hi_s32 inst_idx);

/* !assertion */
#define fidx_assert_ret(cond, else_print) do {                        \
    if(!(cond)) {                                                     \
        hi_log_info(else_print);                                    \
        return FIDX_ERR;                                              \
    }                                                                 \
} while (0)

/* ! analyze a prepared  start code */
#define ananyse_sc() do {                                            \
    process_this_sc((hi_s32)inst_idx);                               \
    ctx->this_scvalid = 0;                                          \
    ctx->this_scdata_len = 0;                                       \
} while (0)

/* !output prepared frame position infomation */
#define out_put_frame() do{                                                                     \
    if(g_out_put_frame_position != HI_NULL) {                                                   \
        (hi_void)g_out_put_frame_position(ctx->param, &ctx->new_frame_pos);                     \
    }                                                                                           \
    if (memset_s(&ctx->new_frame_pos, sizeof(frame_pos), 0x0, sizeof(frame_pos))) {             \
        hi_log_err("memset_s failed.\n");                                           \
    }                                                                                           \
    ctx->new_frame_pos.frame_type = FIDX_FRAME_TYPE_UNKNOWN;                                    \
} while (0)

/*! decide if the SC is valid */
#define is_sc_wrong()   \
    (ctx->this_scdata_len < 0x3 ||   \
    (ctx->this_scdata[0] == 0x00 && ctx->this_scdata[1] == 0x00 && ctx->this_scdata[0x2] == 0x01))

/* brief global init, clear context, and register call back */
static dmx_recbuf_info g_hevc_index_fidxii_sec_buf = {0};
static hi_bool g_mmz_alloced = HI_FALSE;

static hi_s32 alloc_all_fidxii_sec_buf(hi_void)
{
    hi_s32 ret;
    hi_u8 *buf_vir_addr = HI_NULL;
    hi_ulong buf_phy_addr;
    hi_char buf_name[BUF_NAME_LEN] = "DMX_HEVCFidxIIS"; /* array size is 32 */

    if (g_mmz_alloced) {
        return HI_SUCCESS;
    }

    /* alloc and map  FidxIISBuf */
    ret = dmx_alloc_and_map_secbuf(buf_name, BUF_NAME_LEN, FIDX_MAX_CTX_NUM * sizeof(fidx_ctx),
        &buf_phy_addr, &buf_vir_addr);
    if (ret != HI_SUCCESS) {
        hi_log_info("alloc DMX_HEVCFidxIIS failed\n");
        return ret;
    }

    if (memset_s(&g_hevc_index_fidxii_sec_buf, sizeof(dmx_recbuf_info), 0x00, sizeof(dmx_recbuf_info))) {
        hi_log_info("memset_s failed.\n");
    }
    g_hevc_index_fidxii_sec_buf.buf_start_vir_addr = buf_vir_addr;
    g_hevc_index_fidxii_sec_buf.buf_start_addr     = buf_phy_addr;
    g_hevc_index_fidxii_sec_buf.buf_size           = FIDX_MAX_CTX_NUM * sizeof(fidx_ctx);
    g_hevc_index_fidxii_sec_buf.buf_id = 0;

    g_mmz_alloced = HI_TRUE;

    return ret;
}

static hi_s32 free_all_sec_fidxii_sec_buf(hi_void)
{
    hi_s32 ret = HI_SUCCESS;

    if (!g_mmz_alloced) {
        return HI_SUCCESS;
    }

    if (g_hevc_index_fidxii_sec_buf.buf_size != 0) {
        ret = dmx_unmap_and_free_secbuf(g_hevc_index_fidxii_sec_buf.buf_size,
            g_hevc_index_fidxii_sec_buf.buf_start_addr, g_hevc_index_fidxii_sec_buf.buf_start_vir_addr);
        if (ret != HI_SUCCESS) {
            hi_log_info("Unmap FidxIIS secure buffer failed.");
            goto out;
        }
    }

    g_mmz_alloced = HI_FALSE;
    if (memset_s(&g_hevc_index_fidxii_sec_buf, sizeof(dmx_recbuf_info), 0x0, sizeof(dmx_recbuf_info))) {
        hi_log_err("memset_s failed.\n");
        return HI_FAILURE;
    }
out:
    return ret;
}

static hi_s32 alloc_hevc_ctl_sec_buf(dmx_recbuf_info *sec_buf, hi_s32 rec_chan_id)
{
    hi_s32 ret;
    hi_char buf_name[BUF_NAME_LEN]; /* array size is 32 */
    hi_u8 *buf_vir_addr = HI_NULL;
    hi_ulong buf_phy_addr;

    /* Alloc and map  HevcCtxBuf */
    if (snprintf_s(buf_name, sizeof(buf_name), sizeof(buf_name) - 1, "DMX_HevcCtx[%d]", rec_chan_id) < 0) {
        hi_log_info("snprintf_s failed!\n");
        return HI_FAILURE;
    }
    ret = dmx_alloc_and_map_secbuf(buf_name, BUF_NAME_LEN, sizeof(hevc_ctx), &buf_phy_addr, &buf_vir_addr);
    if (ret != HI_SUCCESS) {
        hi_log_info("malloc DMX_HevcCtx failed\n");
        return ret;
    }

    sec_buf->buf_start_vir_addr = buf_vir_addr;
    sec_buf->buf_start_addr     = buf_phy_addr;
    sec_buf->buf_size           = sizeof(hevc_ctx);

    return ret;
}

static hi_s32 free_hevc_ctl_sec_buf(dmx_recbuf_info *sec_buf)
{
    hi_s32 ret = HI_FAILURE;

    /* Unmap and Free HevcCtx  */
    if (sec_buf->buf_size != 0) {
        ret = dmx_unmap_and_free_secbuf(sec_buf->buf_size, sec_buf->buf_start_addr, sec_buf->buf_start_vir_addr);
        if (ret != HI_SUCCESS) {
            hi_log_info("Unmap and FREE HevcCtx secure buffer failed.");
            goto out;
        }
    }

    if (memset_s(sec_buf, sizeof(dmx_recbuf_info), 0x0, sizeof(dmx_recbuf_info))) {
        hi_log_info("memset_s failed.\n");
    }
out:
    return ret;
}

hi_s32 fidx_init(hi_void(*out_put_frame_position)(hi_u32 *param, const frame_pos *sc_ino))
{
    hi_s32 i;
    hi_s32 ret;

    if (g_hevc_rec_dev_fd > 0) {
        g_hevc_rec_dev_fd++;
        return HI_SUCCESS;
    }

    g_out_put_frame_position = out_put_frame_position;

    ret = alloc_all_fidxii_sec_buf();
    if (ret == HI_SUCCESS) {
        g_fidx_iis = (fidx_ctx *)g_hevc_index_fidxii_sec_buf.buf_start_vir_addr;
        for (i = 0; i < FIDX_MAX_CTX_NUM; i++) {
            g_fidx_iis[i].ctx_state = CTX_STATE_DISABLE;
        }
    } else {
        hi_log_info("alloc_all_fidxii_sec_buf failed.");
        goto out;
    }

    g_hevc_rec_dev_fd = 1;
out:
    return ret;
}

hi_s32 fidx_de_init(hi_void)
{
    hi_s32 ret = HI_SUCCESS;

    if (g_hevc_rec_dev_fd > 0) {
        g_hevc_rec_dev_fd--;
    }

    if (g_hevc_rec_dev_fd != 0) {
        return HI_SUCCESS;
    }

    if (g_fidx_iis != HI_NULL) {
        ret = free_all_sec_fidxii_sec_buf();
        if (ret != HI_SUCCESS) {
            hi_log_info("free_all_sec_fidxii_sec_buf failed.");
            goto out;
        }
        g_out_put_frame_position = HI_NULL;
        g_fidx_iis = HI_NULL;
    }

    g_hevc_rec_dev_fd = -1;
out:
    return ret;
}

hi_void dmx_rec_update_frame_info(hi_u32 *param, const frame_pos *index_info)
{
    tee_dmx_rec_index *frame_info = (tee_dmx_rec_index *)param;
    hi_u32 idx;

    switch (index_info->frame_type) {
        case FIDX_FRAME_TYPE_I:
            frame_info->frame_type = TEE_FRAME_TYPE_I;
            break;

        case FIDX_FRAME_TYPE_P:
            frame_info->frame_type = TEE_FRAME_TYPE_P;
            break;

        case FIDX_FRAME_TYPE_B:
            frame_info->frame_type = TEE_FRAME_TYPE_B;
            break;

        case FIDX_FRAME_TYPE_IDR:
            frame_info->frame_type = TEE_FRAME_TYPE_IDR;
            break;

        case FIDX_FRAME_TYPE_BLA:
            frame_info->frame_type = TEE_FRAME_TYPE_BLA;
            break;

        case FIDX_FRAME_TYPE_CRA:
            frame_info->frame_type = TEE_FRAME_TYPE_CRA;
            break;

        default :
            return;
    }

    frame_info->pts_us          = index_info->pts;
    frame_info->global_offset   = (hi_u64)index_info->global_offset;
    frame_info->frame_size      = (hi_u32)index_info->frame_size;

    frame_info->cur_poc = (hi_s16)index_info->cur_poc;
    frame_info->ref_poc_cnt = (hi_u16)index_info->ref_num;
    for (idx = 0; idx < frame_info->ref_poc_cnt; idx++) {
        frame_info->ref_poc[idx] = (hi_s16)index_info->ref_poc[idx];
    }
}

/************************************************************************
    @brief  open an instance
    @param[in]  vid_standard: video standard
    @return
        if success, return instance ID, 0~(FIDX_MAX_CTX_NUM-1)
        if fail, return -1
 ************************************************************************/
hi_s32 fidx_open_instance(vid_standard vid_standard, strm_type strm_type, hi_u32 *param)
{
    hi_s32 ret = -1;
    hi_s32 i;

    fidx_assert_ret(vid_standard < VIDSTD_MAX, "'vid_standard' out of range");
    fidx_assert_ret(strm_type < STRM_TYPE_MAX, "'strm_type' out of range");

    /* ! find an idle instance */
    for (i = 0; i < FIDX_MAX_CTX_NUM; i++) {
        if (g_fidx_iis[i].ctx_state == CTX_STATE_ENABLE) {
            continue;
        }
        if (memset_s(&g_fidx_iis[i], sizeof(fidx_ctx), 0x0, sizeof(fidx_ctx))) {
            hi_log_info("memset_s failed.\n");
        }
        g_fidx_iis[i].ctx_state = CTX_STATE_ENABLE;
        g_fidx_iis[i].video_standard = vid_standard;
        g_fidx_iis[i].strm_type = strm_type;
        g_fidx_iis[i].prev2bytes[0] = 0xff;
        g_fidx_iis[i].prev2bytes[1] = 0xff;
        g_fidx_iis[i].param = param;
        g_fidx_iis[i].vps_sps_pps_err = 0;
        g_fidx_iis[i].new_frm_offset = -1;
        g_fidx_iis[i].first_nal_offset = -1;
        g_fidx_iis[i].last_vps_offset = -1;
        g_fidx_iis[i].last_sps_offset = -1;
        g_fidx_iis[i].last_pps_offset = -1;
        g_fidx_iis[i].last_sei_offset = -1;
        g_fidx_iis[i].hevc_ctx = HI_NULL;

        if (vid_standard == VIDSTD_HEVC) {
            ret = alloc_hevc_ctl_sec_buf(&g_fidx_iis[i].hevc_ctx_buf, i);
            if (ret != HI_SUCCESS) {
                hi_log_info("alloc_hevc_ctl_sec_buf failed.");
                ret = -1;
                break;
            }

            g_fidx_iis[i].hevc_ctx = (hevc_ctx *)((hi_u8 *)g_fidx_iis[i].hevc_ctx_buf.buf_start_vir_addr);
            if (!g_fidx_iis[i].hevc_ctx) {
                hi_log_info("malloc hevc ctx failed.");
                break;
            }

            hevc_init(g_fidx_iis[i].hevc_ctx);
        }

        ret = i;
        break;
    }

    return ret;
}

/* close instalce */
hi_s32 fidx_close_instance(hi_s32 inst_idx)
{
    hi_s32 ret = HI_FAILURE;

    fidx_assert_ret(inst_idx < FIDX_MAX_CTX_NUM, "inst_idx out of range");

    if (g_fidx_iis[inst_idx].ctx_state != CTX_STATE_ENABLE) {
        return FIDX_ERR;
    } else {
        if (g_fidx_iis[inst_idx].hevc_ctx) {
            ret = free_hevc_ctl_sec_buf(&g_fidx_iis[inst_idx].hevc_ctx_buf);
            if (ret != HI_SUCCESS) {
                hi_log_info("free_hevc_ctl_sec_buf failed.");
                goto out;
            }
            g_fidx_iis[inst_idx].hevc_ctx = HI_NULL;
        }

        if (memset_s(&g_fidx_iis[inst_idx], sizeof(fidx_ctx), 0x0, sizeof(fidx_ctx))) {
            hi_log_info("memset_s failed.\n");
        }
        g_fidx_iis[inst_idx].ctx_state = CTX_STATE_DISABLE;

        return FIDX_OK;
    }

out:
    return ret;
}

static hi_s32 is_pes_sc(hi_u8 code, vid_standard vid_standard)
{
    hi_s32 ret = 0;

    if (vid_standard != VIDSTD_AUDIO_PES) {
        if (code >= 0xe0 && code <= 0xef) {
            ret = 1;
        }
    } else {
        if (code >= 0xc0 && code <= 0xdf) {
            ret = 1;
        }
    }

    return ret;
}

/* entry of the start code process, if success return FIDX_OK, otherwise return FIDX_ERR */
hi_s32 process_this_sc(hi_s32 inst_idx)
{
    fidx_ctx *ctx = &g_fidx_iis[inst_idx];
    hi_s32 ret = FIDX_ERR;

    switch (ctx->video_standard) {
        case VIDSTD_HEVC: {
            ret = process_sc_hevc(inst_idx);
            break;
        }
        default: {
            ret = FIDX_ERR;
            break;
        }
    }

    return ret;
}

#define DPRINT  hi_log_dbg

#define pos()   DPRINT("%s %d\n", __func__, __LINE__);

#define max(a, b)         (((a) < (b)) ?  (b) : (a))
#define min(a, b)         (((a) > (b)) ?  (b) : (a))
#define abs(x)            (((x) < 0) ? -(x) : (x))
#define sing(a)           (((a) < 0) ? (-1) : (1))
#define me_dian(a, b, c)   ((a) + (b) + (c) - min((a), min((b), (c))) - max((a), max((b), (c))))

#define clip1(high, x)             (max(min((x), high), 0))
#define clip3(low, high, x)        (max(min((x), high), low))
#define clip255(x)                 (max(min((x), 255), 0))

#ifndef FIDX_BIG_ENDIAN
#define endian32(x) (((x) << 24) | (((x) & 0x0000ff00) << 0x8) | (((x) & 0x00ff0000) >> 0x8) | \
    (((x) >> 24) & 0x000000ff))
#else
#define  endian32(x)      (x)
#endif

static hi_u8 g_calc_zero_num[256] = { /* array size is 256 */
    8, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static hi_u32 zeros_ms(hi_u32 data)
{
    hi_u32 i;
    hi_u32 zero_num = 0;
    hi_u32 tmp_zero_num;
    hi_u32 tmp_data = 0;

    for (i = 0x4; i > 0; i--) {
        tmp_data = (data & 0xff000000) >> 24; /* left shift 24 bits */
        if (tmp_data >= 256) { /* max data is 256 */
            return HI_FAILURE;
        }
        tmp_zero_num = (hi_u32)g_calc_zero_num[tmp_data];
        zero_num += tmp_zero_num;
        if (tmp_zero_num != 0x8) {
            break;
        }
        data = data << 0x8;
    }

    return zero_num;
}

static hi_void bs_init(bs *bs, const hi_u8 *input, hi_s32 length)
{
    hi_u32 data;
    const unsigned long align_word = 0x3;

    bs->head    = (hi_u8 *)(uintptr_t)(((unsigned long)(uintptr_t)input) & (~align_word));
    bs->tail    = bs->head + 0x8;
    bs->bs_len  = length;

    data = *(hi_u32 *)bs->head;
    bs->buf_a = endian32(data);
    data = *(hi_u32 *)(bs->head + 0x4);
    bs->buf_b = endian32(data);

    bs->buf_pos = (((unsigned long)(uintptr_t)input) & 0x3) << 0x3;
    bs->total_pos = 0;

    return;
}

static hi_s32 bs_show(const bs *bs, hi_s32 bits)
{
    hi_s32 ab_buf_pos = bits + bs->buf_pos;
    hi_u32 data, data1;

    if (ab_buf_pos > 32) { /* ab_buf_pos more than 32 */
        data  = bs->buf_a << (hi_u32)bs->buf_pos;   /* (ab_buf_pos - 32) */
        data1 = bs->buf_b >> (hi_u32)(32 - bs->buf_pos); /* 32 - ab_buf_pos */
        data |= data1;
        data >>= (hi_u32)(32 - bits); /* 32 - bits */
    } else {
        data  = (bs->buf_a << (hi_u32)bs->buf_pos) >> (hi_u32)(32 - bits); /* 32 - bits */
    }

    return (data);
}

static hi_s32 bs_skip(bs *bs, hi_s32 bits)
{
    hi_s32 ab_buf_pos = bits + bs->buf_pos;
    hi_u32 data1;

    bs->total_pos += bits;

    if (ab_buf_pos >= 32) { /* ab_buf_pos more than 32 */
        bs->buf_pos =  ab_buf_pos - 32; /* ab_buf_pos - 32 */

        bs->buf_a = bs->buf_b;
        data1 = *(hi_u32*)bs->tail;
        bs->buf_b = endian32(data1);

        bs->tail += 0x4;
    } else {
        bs->buf_pos   += bits;
    }

    return (bits);
}

static inline hi_s32 bs_get(bs *bs, hi_s32 bits)
{
    hi_u32 data;

    data = bs_show(bs, bits);
    bs_skip(bs, bits);

    return (data);
}

static inline hi_s32 bs_resid_bits(const bs *bs)
{
    return (0x8 * bs->bs_len - bs->total_pos);
}

static hi_s32 g_quant_ts_default4x4[16] = { /* array size is 16 */
    16, 16, 16, 16,
    16, 16, 16, 16,
    16, 16, 16, 16,
    16, 16, 16, 16
};

static hi_s32 g_quant_intra_default8x8[64] = { /* array size is 64 */
    16, 16, 16, 16, 17, 18, 21, 24,
    16, 16, 16, 16, 17, 19, 22, 25,
    16, 16, 17, 18, 20, 22, 25, 29,
    16, 16, 18, 21, 24, 27, 31, 36,
    17, 17, 20, 24, 30, 35, 41, 47,
    18, 19, 22, 27, 35, 44, 54, 65,
    21, 22, 25, 31, 41, 54, 70, 88,
    24, 25, 29, 36, 47, 65, 88, 115
};

static hi_s32 g_quant_inter_default8x8[64] = { /* array size is 64 */
    16, 16, 16, 16, 17, 18, 20, 24,
    16, 16, 16, 17, 18, 20, 24, 25,
    16, 16, 17, 18, 20, 24, 25, 28,
    16, 17, 18, 20, 24, 25, 28, 33,
    17, 18, 20, 24, 25, 28, 33, 41,
    18, 20, 24, 25, 28, 33, 41, 54,
    20, 24, 25, 28, 33, 41, 54, 71,
    24, 25, 28, 33, 41, 54, 71, 91
};

static hi_void hevc_proc_width_less_than_16(hevc_ctx *hevc_ctx, sig_last_scan_info *scan)
{
    hi_u32 ui_next_scan_pos = 0;
    hi_s32 ui_scan_line, i_prim_dim, i_scnd_dim;
    hi_u32 ui_num_scan_pos = scan->i_width * scan->i_width;
    hi_u32 *buff_temp = scan->buff_d;

    if (scan->i_width == 0x8) {
        buff_temp = hevc_ctx->sig_last_scan_cg32x32;
    }
    for (ui_scan_line = 0; ui_next_scan_pos < ui_num_scan_pos; ui_scan_line++) {
        i_prim_dim = ui_scan_line;
        i_scnd_dim = 0;
        while (i_prim_dim >= scan->i_width) {
            i_scnd_dim++;
            i_prim_dim--;
        }
        while ((i_prim_dim >= 0) && (i_scnd_dim < scan->i_width)) {
            buff_temp[ui_next_scan_pos] = i_prim_dim * scan->i_width + i_scnd_dim ;
            ui_next_scan_pos++;
            i_scnd_dim++;
            i_prim_dim--;
        }
    }

    return;
}

static hi_void hevc_proc_width_more_than_4(hevc_ctx *hevc_ctx, sig_last_scan_info *scan)
{
    hi_u32 ui_next_scan_pos = 0;
    hi_s32 ui_scan_line, i_prim_dim, i_scnd_dim;
    hi_u32 ui_num_blk_side = ((hi_u32)scan->i_width) >> 0x2;
    hi_u32 ui_num_blks, ui_blk, init_blk_pos;
    hi_u32 offset_y, offset_x, offset_d, offset_scan;
    hi_s32 log2blk = hevc_ctx->auc_convert_to_bit[ui_num_blk_side] + 1;

    ui_num_blks = ui_num_blk_side * ui_num_blk_side;

    for (ui_blk = 0; ui_blk < ui_num_blks; ui_blk++) {
        ui_next_scan_pos = 0;
        init_blk_pos = hevc_ctx->aui_sig_last_scan[SCAN_DIAG][log2blk][ui_blk];
        if (scan->i_width == 32) { /* width equal 32 */
            init_blk_pos = hevc_ctx->sig_last_scan_cg32x32[ui_blk];
        }
        offset_y = init_blk_pos / ui_num_blk_side;
        offset_x = init_blk_pos - offset_y * ui_num_blk_side;
        offset_d = 0x4 * (offset_x + offset_y * scan->i_width);
        offset_scan = 16 * ui_blk; /* ui_blk multiply by 16 */
        for (ui_scan_line = 0; ui_next_scan_pos < 16; ui_scan_line++) { /* 16 loops */
            i_prim_dim = ui_scan_line ;
            i_scnd_dim = 0;
            while (i_prim_dim >= 0x4) {
                i_scnd_dim++;
                i_prim_dim--;
            }
            while (i_prim_dim >= 0 && i_scnd_dim < 0x4 &&
                ((hi_s32)(ui_next_scan_pos + offset_scan) < scan->buffer_size)) {
                scan->buff_d[ui_next_scan_pos + offset_scan] = i_prim_dim * scan->i_width + i_scnd_dim + offset_d;
                ui_next_scan_pos++;
                i_scnd_dim++;
                i_prim_dim--;
            }
        }
    }
    return;
}

static hi_void update_buff_h(sig_last_scan_info *scan, hi_s32 *ui_cnt, hi_s32 offset)
{
    hi_s32 x, y;

    for (y = 0; y < 0x4; y++) {
        for (x = 0; x < 0x4; x++) {
            scan->buff_h[*ui_cnt] = y * scan->i_width + x + offset;
            (*ui_cnt)++;
        }
    }

    return;
}

static hi_void update_buff_v(sig_last_scan_info *scan, hi_s32 *ui_cnt, hi_s32 offset)
{
    hi_s32 x, y;

    for (x = 0; x < 0x4; x++) {
        for (y = 0; y < 0x4; y++) {
            scan->buff_v[*ui_cnt] = y * scan->i_width + x + offset;
            (*ui_cnt)++;
        }
    }

    return;
}

static hi_void hevc_proc_width_more_than_2(sig_last_scan_info *scan)
{
    hi_s32 ui_cnt = 0;
    hi_s32 num_blk_side = (hi_s32)(((hi_u32)scan->i_width) >> 0x2);
    hi_s32 offset;
    hi_s32 blk_y, blk_x;

    for (blk_y = 0; blk_y < num_blk_side; blk_y++) {
        for (blk_x = 0; blk_x < num_blk_side; blk_x++) {
            offset = blk_y * 0x4 * scan->i_width + blk_x * 0x4;
            update_buff_h(scan, &ui_cnt, offset);
        }
    }

    ui_cnt = 0;
    for (blk_x = 0; blk_x < num_blk_side; blk_x++) {
        for (blk_y = 0; blk_y < num_blk_side; blk_y++) {
            offset = blk_y * 0x4 * scan->i_width + blk_x * 0x4;
            update_buff_v(scan, &ui_cnt, offset);
        }
    }
    return;
}

static hi_void hevc_proc_width_less_than_2(sig_last_scan_info *scan)
{
    hi_s32 ui_cnt = 0;
    hi_s32 i_y, i_x;

    for (i_y = 0; i_y < scan->i_height; i_y++) {
        for (i_x = 0; i_x < scan->i_width; i_x++) {
            scan->buff_h[ui_cnt] = i_y * scan->i_width + i_x;
            ui_cnt++;
        }
    }

    ui_cnt = 0;
    for (i_x = 0; i_x < scan->i_width; i_x++) {
        for (i_y = 0; i_y < scan->i_height; i_y++) {
            scan->buff_v[ui_cnt] = i_y * scan->i_width + i_x;
            ui_cnt++;
        }
    }
    return;
}

static hi_void hevc_init_sig_last_scan(hevc_ctx *hevc_ctx, sig_last_scan_info *scan)
{
    if (scan->i_width < 16) { /* i_width less than 16 */
        hevc_proc_width_less_than_16(hevc_ctx, scan);
    }

    if (scan->i_width > 0x4) {  /* width more than 4 */
        hevc_proc_width_more_than_4(hevc_ctx, scan);
    }

    if (scan->i_width > 0x2) {  /* width more than 2 */
        hevc_proc_width_more_than_2(scan);
    } else {    /* width less than 2 */
        hevc_proc_width_less_than_2(scan);
    }

    return;
}

static hi_void hevc_init_scaling_order_table(hevc_ctx *hevc_ctx)
{
    hi_u32 i, c;
    sig_last_scan_info scan;

    for (i = 0; i < sizeof(hevc_ctx->auc_convert_to_bit); i++) {
        hevc_ctx->auc_convert_to_bit[i] = -1;
    }

    c = 0;

    for (i = 0x2; i < HEVC_MAX_CU_DEPTH; i++) {
        hevc_ctx->auc_convert_to_bit[(1 << i)] = c;
        c++;
    }

    c = 0x2;
    for (i = 0; i < HEVC_MAX_CU_DEPTH; i++) {
        scan.buff_z = hevc_ctx->aui_sig_last_scan[0][i];
        scan.buff_h = hevc_ctx->aui_sig_last_scan[1][i];
        scan.buff_v = hevc_ctx->aui_sig_last_scan[0x2][i];
        scan.buff_d = hevc_ctx->aui_sig_last_scan[0x3][i];
        scan.buffer_size = HEVC_MAX_CU_SIZE * HEVC_MAX_CU_SIZE;
        scan.i_width = c;
        scan.i_height = c;
        scan.i_depth = i;
        hevc_init_sig_last_scan(hevc_ctx, &scan);
        c <<= 1;
    }

    return;
}

static hi_s8 hevc_is_idr_unit(hi_u32 nal_unit_type)
{
    return (nal_unit_type == NAL_UNIT_CODED_SLICE_IDR_W_RADL ||
            nal_unit_type == NAL_UNIT_CODED_SLICE_IDR_N_LP) ? 1 : 0;
}

static hi_s8 hevc_is_bla_unit(hi_u32 nal_unit_type)
{
    return (nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_N_LP || nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_W_RADL ||
            nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_W_LP) ? 1 : 0;
}

static hi_s8 hevc_is_cra_unit(hi_u32 nal_unit_type)
{
    return (nal_unit_type == NAL_UNIT_CODED_SLICE_CRA) ? 1 : 0;
}

static hi_s32 hevc_is_flush_unit(hi_u32 nal_unit_type)
{
    return (nal_unit_type == NAL_UNIT_CODED_SLICE_IDR_W_RADL || nal_unit_type == NAL_UNIT_CODED_SLICE_IDR_N_LP ||
            nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_N_LP ||
            nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_W_RADL ||
            nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_W_LP) ? 1 : 0;
}

static hi_void hevc_init_frame_store(hevc_ctx *hevc_ctx)
{
    hi_u32 i;

    for (i = 0; i < HEVC_MAX_FRAME_STORE; i++) {
        hevc_ctx->frame_store[i].non_existing = 0;      /* a real pic; */
        hevc_ctx->frame_store[i].frame_store_state = FS_NOT_USED;  /* empty; */
        hevc_ctx->frame_store[i].is_reference = 0;                /* not pic used for ref; */
        hevc_ctx->frame_store[i].poc = 0;
        hevc_ctx->frame_store[i].frame.frame_store = (struct hevc_frame_store *)&hevc_ctx->frame_store[i];
    }

    return;
}

static hi_void hevc_init_scaling_list(hevc_ctx *hevc_ctx)
{
    hevc_ctx->scaling_list_size[0] = 16; /* scaling_list_size 0 is 16 */
    hevc_ctx->scaling_list_size[1] = 64; /* scaling_list_size 1 is 64 */
    hevc_ctx->scaling_list_size[0x2] = 256; /* scaling_list_size 2 is 256 */
    hevc_ctx->scaling_list_size[0x3] = 1025; /* scaling_list_size 3 is 1025 */

    hevc_ctx->scaling_list_size_x[0] = 0x4;
    hevc_ctx->scaling_list_size_x[1] = 0x8;
    hevc_ctx->scaling_list_size_x[0x2] = 16; /* scaling_list_size_x 2 is 16 */
    hevc_ctx->scaling_list_size_x[0x3] = 32; /* scaling_list_size_x 3 is 32 */

    hevc_ctx->scaling_list_num[0] = 0x6;
    hevc_ctx->scaling_list_num[1] = 0x6;
    hevc_ctx->scaling_list_num[0x2] = 0x6;
    hevc_ctx->scaling_list_num[0x3] = 0x2;

    return;
}

static hi_void hevc_init_dec_para(hevc_ctx *hevc_ctx)
{
    hi_u32 i;

    pos();

    hevc_ctx->last_display_poc = -HEVC_MAX_INT;

    hevc_init_frame_store(hevc_ctx);

    for (i = 0; i < HEVC_MAX_DPB_NUM; i++) {
        hevc_ctx->dpb.fs[i] = hevc_ctx->dpb.fs_negative_ref[i] = \
            hevc_ctx->dpb.fs_positive_ref[i] = hevc_ctx->dpb.fs_ltref[i] = HI_NULL;
    }
    hevc_ctx->dpb.used_size = 0;
    hevc_ctx->dpb.max_long_term_pic_idx = 0;
    hevc_ctx->dpb.ltref_frames_in_buffer = 0;
    hevc_ctx->dpb.negative_ref_frames_in_buffer = 0;
    hevc_ctx->dpb.positive_ref_frames_in_buffer = 0;
    hevc_ctx->dpb.size = HEVC_MAX_DPB_NUM;

    for (i = 0; i < HEVC_MAX_LIST_SIZE; i++) {
        hevc_ctx->list_x[0][i] = hevc_ctx->list_x[1][i] = HI_NULL;
    }

    if (memset_s(&hevc_ctx->curr_slice, sizeof(hevc_slice_segment_header), 0x0, sizeof(hevc_slice_segment_header))) {
        hi_log_err("memset_s failed.\n");
    }
    hevc_ctx->curr_slice.slice_type = HEVC_ERR_SLICE;
    hevc_ctx->curr_slice.new_pic_type = IS_NEW_PIC;
    hevc_ctx->curr_pic.pic_type = HEVC_ERR_FRAME;
    hevc_ctx->total_slice_num = 0;

    hevc_ctx->new_sequence = HEVC_TRUE;
    hevc_ctx->no_out_put_of_prior_pics_flag = HEVC_FALSE;
    hevc_ctx->no_rasl_out_put_flag = HEVC_TRUE;

    hevc_ctx->allow_start_dec = 0;
    hevc_ctx->poc_random_access = HEVC_MAX_INT;
    hevc_ctx->prev_rap_is_bla = HEVC_FALSE;

    hevc_init_scaling_list(hevc_ctx);

    if (memset_s(&hevc_ctx->bs, sizeof(bs), 0x0, sizeof(bs))) {
        hi_log_err("memset_s failed.\n");
    }
    hevc_ctx->bs_p = &hevc_ctx->bs;
    hevc_ctx->curr_nal = &hevc_ctx->nal_array;

    return;
}

static hi_u32 hevc_ue_v(bs *bs, char *name)
{
    hi_u32 tmp_bits;
    hi_u32 info;
    hi_u32 leading_zeros;

    HI_UNUSED(name);
    tmp_bits = bs_show(bs, 32); /* 32 bits */
    leading_zeros = zeros_ms(tmp_bits);
    if (leading_zeros < 32) { /* leading_zeros less than 32 */
        bs_skip(bs, leading_zeros);
        info = bs_show(bs, (leading_zeros + 1)) - 1;
        bs_skip(bs, (leading_zeros + 1));
    } else {
        info = 0xffffeeee;
        return info;
    }

    return info;
}

static hi_u32 hevc_u_v(bs *bs, int v, char *name)
{
    hi_u32 code;

    HI_UNUSED(name);
    code = bs_get(bs, (hi_s32)v);

    return code;
}

static hi_s32 hevc_dec_ptl(const hevc_ctx *hevc_ctx, hevc_profile_tier_level *ptl, hi_s32 profile_present_flag,
                           hi_s32 max_num_sub_layers_minus1)
{
    hi_s32 i;

    if ((hevc_ctx == HI_NULL) || (ptl == HI_NULL)) {
        hi_log_err("Invalid parameter!\n");
        return HEVC_DEC_ERR;
    }

    if (profile_present_flag) {
        hevc_u_v(hevc_ctx->bs_p, 0x8, "general_profile_space[]");
        hevc_u_v(hevc_ctx->bs_p, 32, "xxx"); /* 32 bit */
        hevc_u_v(hevc_ctx->bs_p, 20, "general_reserved_zero_44bits[0..15]"); /* 20 bit */
        hevc_u_v(hevc_ctx->bs_p, 28, "general_reserved_zero_44bits[16..31]"); /* 28 bit */
    }

    ptl->general_level_idc = hevc_u_v(hevc_ctx->bs_p, 0x8, "general_level_idc");

    for (i = 0; i < max_num_sub_layers_minus1 && i < 0x6; i++) {
        if (profile_present_flag) {
            ptl->sub_layer_profile_present_flag[i] = hevc_u_v(hevc_ctx->bs_p, 1, "sub_layer_profile_present_flag");
        }
        ptl->sub_layer_level_present_flag[i]   = hevc_u_v(hevc_ctx->bs_p, 1, "sub_layer_level_present_flag");
    }

    if (max_num_sub_layers_minus1 > 0) {
        for (i = max_num_sub_layers_minus1; i < 0x8; i++) {
            hevc_u_v(hevc_ctx->bs_p, 0x2, "reserved_zero_2bits");
        }
    }

    for (i = 0; i < max_num_sub_layers_minus1 && i < 0x6; i++) {
        if (profile_present_flag && ptl->sub_layer_profile_present_flag[i]) {
            hevc_u_v(hevc_ctx->bs_p, 0x8, "sub_layer_profile_space");
            hevc_u_v(hevc_ctx->bs_p, 32, "sub_layer_profile_compatibility_flag"); /* 32 bits */
            hevc_u_v(hevc_ctx->bs_p, 20, "general_progressive_source_flag"); /* 20 bits */
            hevc_u_v(hevc_ctx->bs_p, 28, "general_reserved_zero_44bits[16..31]"); /* 28 bits */
        }

        if (ptl->sub_layer_level_present_flag[i]) {
            hevc_u_v(hevc_ctx->bs_p, 0x8, "sub_layer_level_idc");
        }
    }

    return HEVC_DEC_NORMAL;
}

static hi_void hevc_process_sub_layers(hevc_ctx *hevc_ctx, hevc_video_param_set *vps,
    hi_s32 vps_max_sub_layers_minus1)
{
    hi_s32 i;

    for (i = 0; i <= vps_max_sub_layers_minus1; i++) {
        vps->vps_max_dec_pic_buffering[i] = hevc_ue_v(hevc_ctx->bs_p,  "vps_max_dec_pic_buffering_minus1[i]") + 1;
        vps->vps_num_reorder_pics[i] = hevc_ue_v(hevc_ctx->bs_p, "vps_num_reorder_pics[i]");
        vps->vps_max_latency_increase[i] = hevc_ue_v(hevc_ctx->bs_p,  "vps_max_latency_increase_plus1[i]");

        if (!vps->vps_sub_layer_ordering_info_present_flag) {
            for (i++; i <= vps_max_sub_layers_minus1; i++) {
                vps->vps_max_dec_pic_buffering[i] =  vps->vps_max_dec_pic_buffering[0] ;
                vps->vps_num_reorder_pics[i] = vps->vps_num_reorder_pics[0];
                vps->vps_max_latency_increase[i] =  vps->vps_max_latency_increase[0];
            }
            break;
        }
    }

    return;
}

static hi_void hevc_process_layer_id_inc_flag(hevc_ctx *hevc_ctx, hevc_video_param_set *vps)
{
    char buf[100]; /* array size is 100 */
    hi_s32 i, j;

    for (i = 1; i <= vps->vps_num_layer_sets_minus1; i++) {
        /* Operation point set */
        for (j = 0; j <= vps->vps_max_layer_id; j++) {
            if (snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "layer_id_included_flag[%d][%d]", i, j) < 0) {
                hi_log_err("snprintf_s failed!\n");
                return;
            }
            vps->layer_id_included_flag[i][j] = hevc_u_v(hevc_ctx->bs_p, 1, buf);
        }
    }
    return;
}

static hi_void hevc_process_timing_info_present_flag(hevc_ctx *hevc_ctx, hevc_video_param_set *vps)
{
    vps->vps_timing_info_present_flag = hevc_u_v(hevc_ctx->bs_p, 1, "vps_timing_info_present_flag");
    if (vps->vps_timing_info_present_flag) {
        vps->vps_num_units_in_tick = hevc_u_v(hevc_ctx->bs_p, 32, "vps_num_units_in_tick"); /* 32 bits */
        vps->vps_time_scale = hevc_u_v(hevc_ctx->bs_p, 32, "vps_time_scale"); /* 32 bits */
        vps->vps_poc_proportional_to_timing_flag = hevc_u_v(hevc_ctx->bs_p, 1, "vps_poc_proportional_to_timing_flag");
        if (vps->vps_poc_proportional_to_timing_flag) {
            vps->vps_num_ticks_poc_diff_one_minus1 = hevc_ue_v(hevc_ctx->bs_p, "vps_num_ticks_poc_diff_one_minus1");
        }
        vps->vps_num_hrd_parameters = hevc_ue_v(hevc_ctx->bs_p, "vps_num_hrd_parameters");

        if (vps->vps_num_hrd_parameters > 0) {
            vps->cprms_present_flag[0] = HEVC_TRUE;
        }
    }
    return;
}


static hi_s32 hevc_process_vps(hevc_ctx *hevc_ctx, hevc_video_param_set *vps)
{
    hi_s32 ret;
    hi_s32 vps_max_sub_layers_minus1;

    vps->vps_reserved_three_2bits = hevc_u_v(hevc_ctx->bs_p, 0x2, "vps_reserved_three_2bits");
    if (vps->vps_reserved_three_2bits != 0x3) {
        hi_log_info("vps_reserved_three_2bits not equal 0x3");
    }

    vps->vps_max_layers_minus1 = hevc_u_v(hevc_ctx->bs_p, 0x6, "vps_max_layers_minus1");
    if (vps->vps_max_layers_minus1 < 0 || vps->vps_max_layers_minus1 > 63) { /* range is 0, 63 */
        hi_log_info("vps_max_layers_minus1 out of range(0,63).");
        return HEVC_DEC_ERR;
    }

    vps_max_sub_layers_minus1 = hevc_u_v(hevc_ctx->bs_p, 0x3, "vps_max_sub_layers_minus1");
    if (vps_max_sub_layers_minus1 < 0 || vps_max_sub_layers_minus1 > 0x6) {
        hi_log_info("vps_max_sub_layers_minus1 out of range(0,6).");
        return HEVC_DEC_ERR;
    }

    vps->vps_max_sub_layers_minus1 = vps_max_sub_layers_minus1 + 1;
    vps->vps_temporal_id_nesting_flag = hevc_u_v(hevc_ctx->bs_p, 1, "vps_temporal_id_nesting_flag");

    vps->vps_reserved_0xffff_16bits = hevc_u_v(hevc_ctx->bs_p, 16, "vps_reserved_ffff_16bits"); /* 16 bits */

    if (vps->vps_reserved_0xffff_16bits != 0xffff) {
        hi_log_info("vps_reserved_0xffff_16bits not equal 0xffff.");
        return HEVC_DEC_ERR;
    }

    ret = hevc_dec_ptl(hevc_ctx, &(vps->profile_tier_level), 1, vps_max_sub_layers_minus1);
    if (HEVC_DEC_NORMAL != ret) {
        hi_log_info("VPS hevc_dec_ptl error.");
        return HEVC_DEC_ERR;
    }

    vps->vps_sub_layer_ordering_info_present_flag =
        hevc_u_v(hevc_ctx->bs_p, 1, "vps_sub_layer_ordering_info_present_flag");

    hevc_process_sub_layers(hevc_ctx, vps, vps_max_sub_layers_minus1);

    vps->vps_max_layer_id = hevc_u_v(hevc_ctx->bs_p, 0x6, "vps_max_layer_id");
    if (vps->vps_max_layer_id >= HEVC_MAX_VPS_NUH_RESERVED_ZERO_LAYER_ID_PLUS1) {
        hi_log_info("vps_max_layer_id is out of range(0)");
        hi_log_info("vps_max_layer_id:%d\n", vps->vps_max_layer_id);
        return HEVC_DEC_ERR;
    }

    vps->vps_num_layer_sets_minus1 = hevc_ue_v(hevc_ctx->bs_p,  "vps_num_layer_sets_minus1");
    if (vps->vps_num_layer_sets_minus1 < 0 || vps->vps_num_layer_sets_minus1 > HEVC_MAX_VPS_OP_SETS_PLUS1 - 1) {
        hi_log_info("vps_num_layer_sets_minus1 is out of range(0,1023)");
        hi_log_info("vps_num_layer_sets_minus1:%d\n", vps->vps_num_layer_sets_minus1);
        return HEVC_DEC_ERR;
    }

    hevc_process_layer_id_inc_flag(hevc_ctx, vps);

    hevc_process_timing_info_present_flag(hevc_ctx, vps);

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_dec_vps(hevc_ctx *hevc_ctx)
{
    hi_u32 vps_video_parameter_set_id;
    hevc_video_param_set *vps_tmp = HI_NULL;

    pos();

    vps_tmp = &hevc_ctx->tmp_param.vps_tmp;
    if (memset_s(vps_tmp, sizeof(hevc_video_param_set), 0x0, sizeof(hevc_video_param_set))) {
        hi_log_err("memset_s failed.\n");
    }
    vps_video_parameter_set_id = hevc_u_v(hevc_ctx->bs_p, 0x4, "vps_video_parameter_set_id");
    if (vps_video_parameter_set_id > 15) { /* vps_video_parameter_set_id more than 15 */
        hi_log_err("vps->vps_video_parameter_set_id out of range(0,15).");
        return HEVC_DEC_ERR;
    }

    if (hevc_ctx->vps[vps_video_parameter_set_id].valid) {
        vps_tmp->video_parameter_set_id = vps_video_parameter_set_id;

        if (hevc_process_vps(hevc_ctx, vps_tmp) != HEVC_DEC_NORMAL) {
            hi_log_err("VPS decode error0");
            hi_log_err("vps_video_parameter_set_id：%u\n", vps_video_parameter_set_id);
            return HEVC_DEC_ERR;
        }

        vps_tmp->is_refresh = 1;
        vps_tmp->valid = 1;
        if (memmove_s(&(hevc_ctx->vps[vps_video_parameter_set_id]), sizeof(hevc_video_param_set),
            vps_tmp, sizeof(hevc_video_param_set)) != EOK) {
            hi_log_err("call memmove_s failed\n");
            return HEVC_DEC_ERR;
        }
    } else {
        hevc_ctx->vps[vps_video_parameter_set_id].video_parameter_set_id = vps_video_parameter_set_id;

        if (hevc_process_vps(hevc_ctx, &(hevc_ctx->vps[vps_video_parameter_set_id])) != HEVC_DEC_NORMAL) {
            hi_log_err("VPS decode error1");
            hi_log_err("vps_video_parameter_set_id：%u\n", vps_video_parameter_set_id);
            hevc_ctx->vps[vps_video_parameter_set_id].is_refresh = 1;
            hevc_ctx->vps[vps_video_parameter_set_id].valid = 0;
            return HEVC_DEC_ERR;
        }
        hevc_ctx->vps[vps_video_parameter_set_id].is_refresh = 1;
        hevc_ctx->vps[vps_video_parameter_set_id].valid = 1;
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_se_v(bs *bs, char *name)
{
    hi_u32 tmp_bits;
    hi_s32 info;
    hi_u32 leading_zeros;
    hi_u32 info_last_bit;

    HI_UNUSED(name);
    tmp_bits = bs_show(bs, 32); /* 32 bits */
    leading_zeros = zeros_ms(tmp_bits);
    if (leading_zeros < 32) { /* 32 bits */
        bs_skip(bs, leading_zeros);
        info = bs_show(bs, (leading_zeros + 1)) - 1;
        info_last_bit = (hi_u32)info & 1;
        info = (hi_u32)info >> 1;
        info = ((info_last_bit & 1) ? (info + 1) : -1 * info);
        bs_skip(bs, (leading_zeros + 1));
    } else {
        info = 0x7fffffff;
        return info;
    }

    return info;
}

static hi_s32 *hevc_get_scaling_list_default_address(hi_u32 size_id, hi_u32 matrix_id)
{
    hi_s32 *src = HI_NULL;

    switch (size_id) {
        case SCALING_LIST_4X4:
            src = g_quant_ts_default4x4;
            break;
        case SCALING_LIST_8X8:
            src = (matrix_id < 0x3) ? g_quant_intra_default8x8 : g_quant_inter_default8x8;
            break;
        case SCALING_LIST_16X16:
            src = (matrix_id < 0x3) ? g_quant_intra_default8x8 : g_quant_inter_default8x8;
            break;
        case SCALING_LIST_32X32:
            src = (matrix_id < 1) ? g_quant_intra_default8x8 : g_quant_inter_default8x8;
            break;
        default:
            hi_log_err("hevc_get_scaling_list_default_address HI_NULL.");
            src = HI_NULL;
            break;
    }
    return src;
}

static hi_s32 hevc_dec_scaling_list_data_copy_mode(hevc_ctx *hevc_ctx, hevc_scaling_list *scaling_list,
    hi_u32 size_id, hi_u32 matrix_id)
{
    hi_u32 code, reflist_id;
    hi_s32 coef_num = min(HEVC_MAX_MATRIX_COEF_NUM, (hi_s32)hevc_ctx->scaling_list_size[size_id]);
    hi_s32 *matrix_address = HI_NULL;
    hi_s32 *dst_scaling_list = scaling_list->scaling_list_coef[size_id][matrix_id];

    code = hevc_ue_v(hevc_ctx->bs_p, "scaling_list_pred_matrix_id_delta");
    if (code > matrix_id || matrix_id >= HEVC_SCALING_LIST_NUM) {
        hi_log_err("scaling_list_pred_matrix_id_delta out of range(0,matrix_id).\n");
        return HEVC_DEC_ERR;
    }

    scaling_list->scaling_list_pred_matrix_id_delta[size_id][matrix_id] = code;
    scaling_list->ref_matrix_id[size_id][matrix_id] = (hi_u32)((hi_s32)matrix_id - code);
    if (size_id > SCALING_LIST_8X8) {
        reflist_id = scaling_list->ref_matrix_id[size_id][matrix_id];
        /* value is 16 */
        code = (matrix_id == reflist_id) ? 16 : scaling_list->scaling_list_dc[size_id][reflist_id];
        scaling_list->scaling_list_dc[size_id][matrix_id] = code;
    }
    reflist_id = scaling_list->ref_matrix_id[size_id][matrix_id];
    matrix_address = (matrix_id == reflist_id) ? hevc_get_scaling_list_default_address(size_id, reflist_id) :
        scaling_list->scaling_list_coef[size_id][reflist_id];
    if (matrix_address == NULL) {
        hi_log_err("hevc_dec_scaling_list_data matrix_address null.\n");
        return HEVC_DEC_ERR;
    }
    if (memmove_s(dst_scaling_list, sizeof(hi_s32) * coef_num, matrix_address, sizeof(hi_s32) * coef_num) != EOK) {
        hi_log_err("call memmove_s failed\n");
        return HEVC_DEC_ERR;
    }
    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_dec_scaling_list_data_dpcm_mode(hevc_ctx *hevc_ctx, hevc_scaling_list *scaling_list,
    hi_u32 size_id, hi_u32 matrix_id)
{
    hi_s32 i;
    hi_s32 coef_num = min(HEVC_MAX_MATRIX_COEF_NUM, (hi_s32)hevc_ctx->scaling_list_size[size_id]);
    hi_s32 next_coef;
    hi_s32 *dst_scaling_list = scaling_list->scaling_list_coef[size_id][matrix_id];
    hi_u32 *scan = (size_id == 0) ? hevc_ctx->aui_sig_last_scan[SCAN_DIAG][1] : hevc_ctx->sig_last_scan_cg32x32;

    next_coef = HEVC_SCALING_LIST_START_VALUE;
    if (size_id > SCALING_LIST_8X8) {
        scaling_list->scaling_list_dc_coef_minus8 = hevc_se_v(hevc_ctx->bs_p, "scaling_list_dc_coef_minus8");
        if (scaling_list->scaling_list_dc_coef_minus8 < -7 || /* range is -7 to 247) */
            scaling_list->scaling_list_dc_coef_minus8 > 247) { /* range is -7 to 247) */
            hi_log_err("scaling_list_dc_coef_minus8 out of range(-7,247).\n");
            return HEVC_DEC_ERR;
        }
        scaling_list->scaling_list_dc[size_id][matrix_id] = scaling_list->scaling_list_dc_coef_minus8 + 0x8;
        next_coef = scaling_list->scaling_list_dc[size_id][matrix_id];
    }
    for (i = 0; i < coef_num; i++) {
        scaling_list->scaling_list_delta_coef = hevc_se_v(hevc_ctx->bs_p, "scaling_list_delta_coef");
        if (scaling_list->scaling_list_delta_coef < -128 || /* range is -128 to 127) */
            scaling_list->scaling_list_delta_coef > 127) { /* range is -128 to 127) */
            hi_log_err("scaling_list_dc_coef_minus8 out of range(-128,127).\n");
            return HEVC_DEC_ERR;
        }
        next_coef = (next_coef + scaling_list->scaling_list_delta_coef + 256) % 256; /* 256 bytes aligned */
        dst_scaling_list[scan[i]] = next_coef;
    }
    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_dec_scaling_list_data(hevc_ctx *hevc_ctx, hevc_scaling_list *scaling_list)
{
    hi_s32 ret;
    hi_u8 scaling_list_pred_mode_flag;
    hi_u32 size_id, matrix_id;

    if (memmove_s(scaling_list->scaling_list_coef[SCALING_LIST_32X32][0x3], HEVC_MAX_MATRIX_COEF_NUM * sizeof(hi_s32),
        scaling_list->scaling_list_coef[SCALING_LIST_32X32][1], HEVC_MAX_MATRIX_COEF_NUM * sizeof(hi_s32)) != EOK) {
        hi_log_err("call memmove_s failed\n");
        return HEVC_DEC_ERR;
    }

    for (size_id = 0; size_id < SCALING_LIST_SIZE_NUM; size_id++) {
        for (matrix_id = 0; matrix_id < hevc_ctx->scaling_list_num[size_id] &&
            matrix_id < HEVC_SCALING_LIST_NUM; matrix_id++) {
            scaling_list_pred_mode_flag = hevc_u_v(hevc_ctx->bs_p, 1, "scaling_list_pred_mode_flag");
            scaling_list->scaling_list_pred_mode_flag[size_id][matrix_id] = scaling_list_pred_mode_flag;

            if (!scaling_list_pred_mode_flag) { /* Copy Mode */
                ret = hevc_dec_scaling_list_data_copy_mode(hevc_ctx, scaling_list, size_id, matrix_id);
            } else { /* DPCM Mode */
                ret = hevc_dec_scaling_list_data_dpcm_mode(hevc_ctx, scaling_list, size_id, matrix_id);
            }
            if (ret != HI_SUCCESS) {
                hi_log_err("proccess scaling list pred mode flag failed. ret = 0x%x\n", ret);
            }
        }
    }
    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_dec_short_term_proc_ref_idc(hevc_ctx *hevc_ctx, hevc_short_term_rpset *short_term_rpset,
    hevc_short_term_rpset *temp_rpset)
{
    hi_u32 ref_idc, i;
    hi_u32 k = 0;
    hi_u32 k1 = 0;
    hi_u32 k2 = 0;
    hi_s32 delta_rps, delta_poc;

    if (temp_rpset->num_of_pics > HEVC_MAX_NUM_REF_PICS) {
        hi_log_err("p_temp_rpset->num_of_pics out of range(0,15).\n");
        hi_log_err("num_of_pic:%u\n", temp_rpset->num_of_pics);
        return HEVC_DEC_ERR;
    }

    delta_rps = (1 - (short_term_rpset->delta_rps_sign << 1)) * short_term_rpset->abs_delta_rps;
    for (i = 0; i <= temp_rpset->num_of_pics; i++) {
        /* first bit is "1" if idc is 1 */
        ref_idc = hevc_u_v(hevc_ctx->bs_p, 1, "used_by_curr_pic_flag");
        if (ref_idc == 0) {
            /* second bit is "1" if idc is 2, "0" otherwise. */
            ref_idc = hevc_u_v(hevc_ctx->bs_p, 1, "use_delta_flag") << 1;
        }
        if ((ref_idc == 1) || (ref_idc == 0x2)) {
            delta_poc = delta_rps + ((i < temp_rpset->num_of_pics) ? temp_rpset->delta_poc[i] : 0);
            short_term_rpset->delta_poc[k] = delta_poc;
            short_term_rpset->used_flag[k] = (1 == ref_idc);
            k1 += (delta_poc < 0) ? 1 : 0;
            k2 += (delta_poc < 0) ? 0 : 1;
            k++;
        }

        short_term_rpset->ref_idc[i] = ref_idc;
    }
    short_term_rpset->num_ref_idc = temp_rpset->num_of_pics + 1;
    short_term_rpset->num_of_pics = k;
    short_term_rpset->num_negative_pics = k1;
    short_term_rpset->num_positive_pics = k2;

    if ((short_term_rpset->num_of_pics > HEVC_MAX_NUM_REF_PICS) ||
        (short_term_rpset->num_negative_pics > HEVC_MAX_NUM_REF_PICS) ||
        (short_term_rpset->num_positive_pics > HEVC_MAX_NUM_REF_PICS)) {
        hi_log_err("num_of_pics out of range(0,15).\n");
        return HEVC_DEC_ERR;
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_dec_short_term_proc_true_prediction(hevc_ctx *hevc_ctx, hevc_seq_param_set *sps,
    hevc_short_term_rpset *short_term_rpset, hi_u32 idx)
{
    hi_u32 r_idx, code, i, num_neg_pics;
    hi_s32 j;
    hi_s32 delta_poc, temp;
    hi_u8 used;

    code = (idx == sps->num_short_term_ref_pic_sets) ? hevc_ue_v(hevc_ctx->bs_p, "delta_idx_minus1") : 0;
    short_term_rpset->delta_idx = (idx == sps->num_short_term_ref_pic_sets) ? (code + 1) : 0;

    if (short_term_rpset->delta_idx > idx) {
        hi_log_err("delta_idx(%u) > idx(%u).\n", short_term_rpset->delta_idx, idx);
        return HEVC_DEC_ERR;
    }

    r_idx = idx - 1 - code;
    if (r_idx > (idx - 1)) {
        hi_log_err("r_idx > (idx-1) or < 0).\n");
        return HEVC_DEC_ERR;
    }

    short_term_rpset->delta_rps_sign = hevc_u_v(hevc_ctx->bs_p, 1, "delta_rps_sign");
    short_term_rpset->abs_delta_rps = hevc_ue_v(hevc_ctx->bs_p, "abs_delta_rps_minus1") + 1;

    if (hevc_dec_short_term_proc_ref_idc(hevc_ctx, short_term_rpset, &(sps->short_term_ref_pic_set[r_idx])) !=
        HEVC_DEC_NORMAL) {
        return HEVC_DEC_ERR;
    }

    /* sort_delta_poc: sort in increasing order (smallest first) */
    for (i = 1; i < short_term_rpset->num_of_pics; i++) {
        delta_poc = short_term_rpset->delta_poc[i];
        used = short_term_rpset->used_flag[i];
        for (j = i - 1; j >= 0; j--) {
            temp = short_term_rpset->delta_poc[j];
            if (delta_poc < temp) {
                short_term_rpset->delta_poc[j + 1] = temp;
                short_term_rpset->used_flag[j + 1] = short_term_rpset->used_flag[j];
                short_term_rpset->delta_poc[j] = delta_poc;
                short_term_rpset->used_flag[j] = used;
            }
        }
    }

    /* flip the negative values to largest first */
    num_neg_pics = short_term_rpset->num_negative_pics;
    for (i = 0, j = (hi_s32)(num_neg_pics - 1); i < (num_neg_pics >> 1); i++, j--) {
        delta_poc = short_term_rpset->delta_poc[i];
        used = short_term_rpset->used_flag[i];
        short_term_rpset->delta_poc[i] = short_term_rpset->delta_poc[j];
        short_term_rpset->used_flag[i] = short_term_rpset->used_flag[j];
        short_term_rpset->delta_poc[j] = delta_poc;
        short_term_rpset->used_flag[j] = used;
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_dec_short_term_proc_false_prediction(hevc_ctx *hevc_ctx, hevc_short_term_rpset *short_term_rpset)
{
    hi_u32 prev = 0;
    hi_s32 delta_poc;
    hi_u32 i;
    hi_u32 delta_poc_s0_minus1, used_by_curr_pic_s0_flag, delta_poc_s1_minus1, used_by_curr_pic_s1_flag;

    short_term_rpset->num_negative_pics = hevc_ue_v(hevc_ctx->bs_p, "num_negative_pics");
    if (short_term_rpset->num_negative_pics > HEVC_MAX_NUM_REF_PICS) {
        hi_log_err("p_temp_rpset->num_negative_pics(%u) out of range(0,15).\n", short_term_rpset->num_negative_pics);
        return HEVC_DEC_ERR;
    }

    short_term_rpset->num_positive_pics = hevc_ue_v(hevc_ctx->bs_p, "num_positive_pics");
    if (short_term_rpset->num_positive_pics > HEVC_MAX_NUM_REF_PICS) {
        hi_log_err("p_temp_rpset->num_positive_pics(%u) out of range(0,15).\n", short_term_rpset->num_positive_pics);
        return HEVC_DEC_ERR;
    }

    short_term_rpset->num_of_pics = short_term_rpset->num_negative_pics + short_term_rpset->num_positive_pics;
    if (short_term_rpset->num_of_pics > HEVC_MAX_NUM_REF_PICS) {
        hi_log_err("p_short_term_rpset->num_of_pics(%u) out of range[0~16].\n", short_term_rpset->num_of_pics);
        return HEVC_DEC_ERR;
    }

    for (i = 0; i < short_term_rpset->num_negative_pics; i++) {
        delta_poc_s0_minus1 = hevc_ue_v(hevc_ctx->bs_p, "delta_poc_s0_minus1");
        if (delta_poc_s0_minus1 > 32767) { /* delta_poc_s0_minus1 less than 32767 */
            hi_log_err("delta_poc_s0_minus1(%u) out of range.\n", delta_poc_s0_minus1);
            return HEVC_DEC_ERR;
        }
        delta_poc = prev - delta_poc_s0_minus1 - 1;
        prev = delta_poc;
        short_term_rpset->delta_poc[i] = delta_poc;
        used_by_curr_pic_s0_flag = hevc_u_v(hevc_ctx->bs_p, 1, "used_by_curr_pic_s0_flag");
        short_term_rpset->used_flag[i] = used_by_curr_pic_s0_flag;
    }

    prev = 0;
    for (i = short_term_rpset->num_negative_pics; i < short_term_rpset->num_of_pics; i++) {
        delta_poc_s1_minus1 = hevc_ue_v(hevc_ctx->bs_p, "delta_poc_s1_minus1");
        delta_poc = prev + delta_poc_s1_minus1 + 1;
        prev = delta_poc;
        short_term_rpset->delta_poc[i] = delta_poc;
        used_by_curr_pic_s1_flag = hevc_u_v(hevc_ctx->bs_p, 1, "used_by_curr_pic_s1_flag");
        short_term_rpset->used_flag[i] = used_by_curr_pic_s1_flag;
    }
    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_dec_short_term_ref_pic_set(hevc_ctx *hevc_ctx, hevc_seq_param_set *sps,
    hevc_short_term_rpset *short_term_rpset, hi_u32 idx)
{
    short_term_rpset->inter_ref_pic_set_prediction_flag = ((hi_s32)idx <= 0) ? HEVC_FALSE :
        hevc_u_v(hevc_ctx->bs_p, 1, "inter_ref_pic_set_prediction_flag");

    if (short_term_rpset->inter_ref_pic_set_prediction_flag) {
        if (hevc_dec_short_term_proc_true_prediction(hevc_ctx, sps, short_term_rpset, idx) != HEVC_DEC_NORMAL) {
            hi_log_err("proc true prediction failed!\n");
            return HEVC_DEC_ERR;
        }
    } else {
        if (hevc_dec_short_term_proc_false_prediction(hevc_ctx, short_term_rpset) != HEVC_DEC_NORMAL) {
            hi_log_err("proc false prediction failed!\n");
            return HEVC_DEC_ERR;
        }
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_process_sps(hevc_ctx *hevc_ctx, hevc_seq_param_set *sps)
{
    hi_u32 i;
    hi_s32 ret;
    hi_u32 log2_max_pic_order_cnt_lsb_minus4;

    const hi_s32 g_croup_unitx[4] = {1, 2, 2, 1}; /* array size is 4 */
    const hi_s32 g_croup_unity[4] = {1, 2, 1, 1}; /* array size is 4 */

    sps->chroma_format_idc = hevc_ue_v(hevc_ctx->bs_p, "chroma_format_idc");

    /* chroma_format_idc equal to 1 (4:2:0) */
    if (sps->chroma_format_idc != 1) {
        if (sps->chroma_format_idc > 0x3) {
            hi_log_err("sps->chroma_format_idc out of range(0,3).");
            return HEVC_DEC_ERR;
        }
        if (sps->chroma_format_idc == 0x3) {
            sps->separate_colour_plane_flag = hevc_u_v(hevc_ctx->bs_p, 1, "separate_colour_plane_flag");
            if (sps->separate_colour_plane_flag != 0) {
                hi_log_err("sps->separate_colour_plane_flag not equal 0.");
            }
        }
        hi_log_err("sps->chroma_format_idc(%u) not equal 1.", sps->chroma_format_idc);
        return HEVC_DEC_ERR;
    }

    sps->pic_width_in_luma_samples = hevc_ue_v(hevc_ctx->bs_p, "pic_width_in_luma_samples");
    if (sps->pic_width_in_luma_samples > 8192) { /* range is 0 to 8192 */
        hi_log_err("pic_width_in_luma_samples out of range(0,8192).");
        return HEVC_DEC_ERR;
    }

    sps->pic_height_in_luma_samples = hevc_ue_v(hevc_ctx->bs_p, "pic_height_in_luma_samples");
    if (sps->pic_height_in_luma_samples > 4352) { /* range is 0 to 4352 */
        hi_log_err("pic_height_in_luma_samples out of range(0,4352).");
        return HEVC_DEC_ERR;
    }

    sps->conformance_window_flag = hevc_u_v(hevc_ctx->bs_p, 1, "conformance_window_flag");

    if (sps->conformance_window_flag) {
        sps->conf_win_left_offset   = hevc_ue_v(hevc_ctx->bs_p, "conf_win_left_offset");
        sps->conf_win_left_offset   = sps->conf_win_left_offset * g_croup_unitx[sps->chroma_format_idc];
        sps->conf_win_right_offset  = hevc_ue_v(hevc_ctx->bs_p, "conf_win_right_offset");
        sps->conf_win_right_offset  = sps->conf_win_right_offset * g_croup_unitx[sps->chroma_format_idc];
        if (sps->pic_width_in_luma_samples < (sps->conf_win_left_offset + sps->conf_win_right_offset)) {
            hi_log_err("conf_win_left_offset+conf_win_right_offset out of range.");
            return HEVC_DEC_ERR;
        }

        sps->conf_win_top_offset    = hevc_ue_v(hevc_ctx->bs_p, "conf_win_top_offset");
        sps->conf_win_top_offset    = sps->conf_win_top_offset * g_croup_unity[sps->chroma_format_idc];
        sps->conf_win_bottom_offset = hevc_ue_v(hevc_ctx->bs_p, "conf_win_bottom_offset");
        sps->conf_win_bottom_offset = sps->conf_win_bottom_offset * g_croup_unity[sps->chroma_format_idc];
        if (sps->pic_height_in_luma_samples < (sps->conf_win_top_offset + sps->conf_win_bottom_offset)) {
            hi_log_err("conf_win_top_offset+conf_win_bottom_offset out of range.");
            return HEVC_DEC_ERR;
        }
    }

    sps->bit_depth_luma = hevc_ue_v(hevc_ctx->bs_p, "bit_depth_luma_minus8") + 0x8;
    if (sps->bit_depth_luma != 0x8) {
        if (sps->bit_depth_luma < 0x8 || sps->bit_depth_luma > 10) { /* range 8 to 10 */
            hi_log_err("bit_depth_luma(%u) out of range(8,14).", sps->bit_depth_luma);
            return HEVC_DEC_ERR;
        }
    }

    sps->bit_depth_chroma = hevc_ue_v(hevc_ctx->bs_p, "bit_depth_chroma_minus8") + 0x8;
    if (sps->bit_depth_chroma != 0x8) {
        if (sps->bit_depth_chroma < 0x8 || sps->bit_depth_chroma > 14) { /* range is 8 to 14 */
            hi_log_err("bit_depth_chroma(%u) out of range[8,14]", sps->bit_depth_chroma);
            return HEVC_DEC_ERR;
        }
    }

    hevc_ctx->bit_depthy = sps->bit_depth_luma;
    hevc_ctx->bit_depthc = sps->bit_depth_chroma;

    sps->qp_bd_offset_y = (sps->bit_depth_luma - 0x8)   * 0x6;
    sps->qp_bd_offset_c = (sps->bit_depth_chroma - 0x8) * 0x6;

    log2_max_pic_order_cnt_lsb_minus4 = hevc_ue_v(hevc_ctx->bs_p, "log2_max_pic_order_cnt_lsb_minus4");
    if (log2_max_pic_order_cnt_lsb_minus4 > 12) { /* range is 0 to 12 */
        hi_log_err("log2_max_pic_order_cnt_lsb_minus4 out of range[0,12].");
        return HEVC_DEC_ERR;
    }

    sps->max_pic_order_cnt_lsb = log2_max_pic_order_cnt_lsb_minus4 + 0x4;
    sps->bits_for_poc = sps->max_pic_order_cnt_lsb;

    sps->sps_sub_layer_ordering_info_present_flag = hevc_u_v(hevc_ctx->bs_p,
                                                             1, "sps_sub_layer_ordering_info_present_flag");

    for (i = 0; i <= sps->sps_max_sub_layers_minus1; i++) {
        sps->max_dec_pic_buffering[i] = hevc_ue_v(hevc_ctx->bs_p, "sps_max_dec_pic_buffering_minus1") + 1;
        sps->num_reorder_pics[i]      = hevc_ue_v(hevc_ctx->bs_p, "sps_num_reorder_pics");
        sps->max_latency_increase[i]  = hevc_ue_v(hevc_ctx->bs_p, "sps_max_latency_increase_plus1");
        if (!sps->sps_sub_layer_ordering_info_present_flag) {
            for (i++; i <= sps->sps_max_sub_layers_minus1; i++) {
                sps->max_dec_pic_buffering[i] = sps->max_dec_pic_buffering[0];
                sps->num_reorder_pics[i]      = sps->num_reorder_pics[0];
                sps->max_latency_increase[i]  = sps->max_latency_increase[0];
            }
            break;
        }
    }

    sps->log2_min_luma_coding_block_size_minus3   = hevc_ue_v(hevc_ctx->bs_p, "log2_min_coding_block_size_minus3");
    if (sps->log2_min_luma_coding_block_size_minus3 > 0x3) {
        hi_log_err("log2_min_luma_coding_block_size_minus3 out of range(0,3).");
        return HEVC_DEC_ERR;
    }

    sps->log2_diff_max_min_luma_coding_block_size = hevc_ue_v(hevc_ctx->bs_p, "log2_diff_max_min_coding_block_size");

    if (sps->log2_diff_max_min_luma_coding_block_size > 0x3) {
        hi_log_err("log2_diff_max_min_luma_coding_block_size out of range(0,3).");
        return HEVC_DEC_ERR;
    }

    sps->log2_min_cb_size_y = sps->log2_min_luma_coding_block_size_minus3 + 0x3;
    sps->log2_ctb_size_y    = sps->log2_min_cb_size_y + sps->log2_diff_max_min_luma_coding_block_size;
    if (sps->log2_ctb_size_y < 0x4 || sps->log2_ctb_size_y > 0x6) {
        hi_log_err("log2_ctb_size_y out of range(4,6).");
        return HEVC_DEC_ERR;
    }

    sps->min_cb_size_y     = 1 << sps->log2_min_cb_size_y;
    sps->ctb_size_y        = 1 << sps->log2_ctb_size_y;
    sps->max_cu_width      = 1 << sps->log2_ctb_size_y;
    sps->max_cu_height     = 1 << sps->log2_ctb_size_y;
    sps->ctb_num_width     = (sps->pic_width_in_luma_samples % sps->max_cu_width) ?
        (sps->pic_width_in_luma_samples / sps->max_cu_width + 1) :
        (sps->pic_width_in_luma_samples / sps->max_cu_width);
    sps->ctb_num_height = (sps->pic_height_in_luma_samples % sps->max_cu_height) ?
        (sps->pic_height_in_luma_samples / sps->max_cu_height + 1) :
        (sps->pic_height_in_luma_samples / sps->max_cu_height);

    sps->log2_min_transform_block_size_minus2 = hevc_ue_v(hevc_ctx->bs_p, "log2_min_transform_block_size_minus2");
    if (sps->log2_min_transform_block_size_minus2 > 0x3) {
        hi_log_err("log2_min_transform_block_size_minus2 out of range(0,3).");
        return HEVC_DEC_ERR;
    }

    sps->log2_diff_max_min_transform_block_size = hevc_ue_v(hevc_ctx->bs_p, "log2_diff_max_min_transform_block_size");
    if (sps->log2_diff_max_min_transform_block_size > 0x3) {
        hi_log_err("log2_diff_max_min_transform_block_size out of range(0,3).");
        return HEVC_DEC_ERR;
    }
    sps->quadtree_tu_log2_min_size = sps->log2_min_transform_block_size_minus2 + 0x2;
    if (sps->quadtree_tu_log2_min_size >= sps->log2_min_cb_size_y) {
        hi_log_err("quadtree_tu_log2_min_size not less than log2_min_cb_sizeY.");
        return HEVC_DEC_ERR;
    }

    sps->quadtree_tu_log2_max_size = sps->quadtree_tu_log2_min_size + sps->log2_diff_max_min_transform_block_size;
    if (sps->quadtree_tu_log2_max_size > 0x5 || sps->quadtree_tu_log2_max_size > sps->log2_ctb_size_y) {
        hi_log_err("quadtree_tu_log2_max_size greater than Min( CtbLog2SizeY, 5 ).");
        return HEVC_DEC_ERR;
    }

    sps->max_transform_hierarchy_depth_inter = hevc_ue_v(hevc_ctx->bs_p, "max_transform_hierarchy_depth_inter");
    if (sps->max_transform_hierarchy_depth_inter > sps->log2_ctb_size_y - sps->quadtree_tu_log2_min_size) {
        hi_log_err("max_transform_hierarchy_depth_inter out of range(0,CtbLog2SizeY-Log2MinTrafoSize).");
        return HEVC_DEC_ERR;
    }

    sps->max_transform_hierarchy_depth_intra = hevc_ue_v(hevc_ctx->bs_p, "max_transform_hierarchy_depth_intra");
    if (sps->max_transform_hierarchy_depth_intra > sps->log2_ctb_size_y - sps->quadtree_tu_log2_min_size) {
        hi_log_err("max_transform_hierarchy_depth_intra out of range(0,CtbLog2SizeY-Log2MinTrafoSize).");
        return HEVC_DEC_ERR;
    }

    sps->quadtree_tu_max_depth_inter = sps->max_transform_hierarchy_depth_inter + 1;
    sps->quadtree_tu_max_depth_intra = sps->max_transform_hierarchy_depth_intra + 1;

    hevc_ctx->ui_add_cu_depth = 0;
    while (((hi_u32)(sps->max_cu_width >> sps->log2_diff_max_min_luma_coding_block_size))
            > (hi_u32)(1 << (sps->quadtree_tu_log2_min_size + hevc_ctx->ui_add_cu_depth))) {
        hevc_ctx->ui_add_cu_depth++;
    }
    sps->max_cu_depth = sps->log2_diff_max_min_luma_coding_block_size + hevc_ctx->ui_add_cu_depth;

    sps->scaling_list_enabled_flag = hevc_u_v(hevc_ctx->bs_p, 1, "scaling_list_enabled_flag");
    if (sps->scaling_list_enabled_flag) {
        sps->sps_scaling_list_data_present_flag = hevc_u_v(hevc_ctx->bs_p, 1, "sps_scaling_list_data_present_flag");
        if (sps->sps_scaling_list_data_present_flag) {
            ret = hevc_dec_scaling_list_data(hevc_ctx, &(sps->scaling_list));
            if (HEVC_DEC_NORMAL != ret) {
                hi_log_err("SPS hevc_dec_scaling_list_data error.");
                return HEVC_DEC_ERR;
            }
        }
    }

    sps->amp_enabled_flag = hevc_u_v(hevc_ctx->bs_p, 1, "amp_enabled_flag");
    sps->sample_adaptive_offset_enabled_flag = hevc_u_v(hevc_ctx->bs_p, 1, "sample_adaptive_offset_enabled_flag");

    sps->pcm_enabled_flag = hevc_u_v(hevc_ctx->bs_p, 1, "pcm_enabled_flag");
    if (sps->pcm_enabled_flag) {
        sps->pcm_bit_depth_luma = hevc_u_v(hevc_ctx->bs_p, 0x4, "pcm_sample_bit_depth_luma_minus1") + 1;
        sps->pcm_bit_depth_chroma = hevc_u_v(hevc_ctx->bs_p, 0x4, "pcm_sample_bit_depth_chroma_minus1") + 1;

        sps->log2_min_pcm_coding_block_size_minus3 = hevc_ue_v(hevc_ctx->bs_p,
                                                               "log2_min_pcm_luma_coding_block_size_minus3");

        if (sps->log2_min_pcm_coding_block_size_minus3 > 0x2) {
            hi_log_err("log2_min_pcm_coding_block_size_minus3(%u) out of range[0,2].",
                sps->log2_min_pcm_coding_block_size_minus3);
        }

        sps->log2_diff_max_min_pcm_coding_block_size = hevc_ue_v(hevc_ctx->bs_p,
                                                                 "log2_diff_max_min_pcm_luma_coding_block_size");
        if (sps->log2_diff_max_min_pcm_coding_block_size > 0x2) {
            hi_log_err("log2_diff_max_min_pcm_coding_block_size(%u) out of range[0,2].",
                sps->log2_diff_max_min_pcm_coding_block_size);
        }
        sps->pcm_log2_min_size = sps->log2_min_pcm_coding_block_size_minus3 + 0x3;
        sps->pcm_log2_max_size = sps->pcm_log2_min_size + sps->log2_diff_max_min_pcm_coding_block_size;
        if (sps->pcm_log2_max_size > 0x5 || sps->pcm_log2_max_size > sps->log2_ctb_size_y) {
            hi_log_err("pcm_log2_max_size greater than Min( CtbLog2SizeY, 5 ).");
        }

        sps->pcm_loop_filter_disable_flag = hevc_u_v(hevc_ctx->bs_p, 1, "pcm_loop_filter_disable_flag");
    }

    sps->num_short_term_ref_pic_sets  = hevc_ue_v(hevc_ctx->bs_p, "num_short_term_ref_pic_sets");
    if (sps->num_short_term_ref_pic_sets > 64) { /* range is 0 to 64 */
        hi_log_err("num_short_term_ref_pic_sets out of range[0,64].");
        return HEVC_DEC_ERR;
    }

    for (i = 0; i < sps->num_short_term_ref_pic_sets; i++) {
        /* get short term reference picture sets */
        ret = hevc_dec_short_term_ref_pic_set(hevc_ctx, sps, &(sps->short_term_ref_pic_set[i]), i);
        if (ret != HEVC_DEC_NORMAL) {
            hi_log_err("SPS hevc_dec_short_term_ref_pic_set error.");
            return HEVC_DEC_ERR;
        }
    }

    sps->long_term_ref_pics_present_flag = hevc_u_v(hevc_ctx->bs_p, 1, "long_term_ref_pics_present_flag");
    if (sps->long_term_ref_pics_present_flag) {
        sps->num_long_term_ref_pic_sps = hevc_ue_v(hevc_ctx->bs_p, "num_long_term_ref_pic_sps");
        if (sps->num_long_term_ref_pic_sps > HEVC_MAX_LSB_NUM - 1) {
            hi_log_err("num_long_term_ref_pic_sps out of range[0,32].");
            return HEVC_DEC_ERR;
        }

        for (i = 0; i < sps->num_long_term_ref_pic_sps; i++) {
            sps->lt_ref_pic_poc_lsb_sps[i] = hevc_u_v(hevc_ctx->bs_p,
                                                      sps->max_pic_order_cnt_lsb, "lt_ref_pic_poc_lsb_sps");
            sps->used_by_curr_pic_lt_sps_flag[i] = hevc_u_v(hevc_ctx->bs_p, 1, "used_by_curr_pic_lt_sps_flag");
        }
    }
    sps->sps_temporal_mvp_enable_flag = hevc_u_v(hevc_ctx->bs_p, 1, "sps_temporal_mvp_enable_flag");
    sps->sps_strong_intra_smoothing_enable_flag = hevc_u_v(hevc_ctx->bs_p, 1, "sps_strong_intra_smoothing_enable_flag");

    sps->is_refresh = 1;

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_dec_sps(hevc_ctx *hevc_ctx)
{
    hi_s32 ret;
    hi_u32 video_parameter_set_id;
    hi_u32 sps_max_sub_layers_minus1;
    hi_u8 sps_temporal_id_nesting_flag;
    hi_u32 sps_seq_parameter_set_id;
    hevc_profile_tier_level profile_tier_level;
    hevc_seq_param_set *sps_tmp = HI_NULL;

    pos();

    sps_tmp = &hevc_ctx->tmp_param.sps_tmp;
    if (memset_s(sps_tmp, sizeof(hevc_seq_param_set), 0x0, sizeof(hevc_seq_param_set))) {
        hi_log_err("memset_s failed.\n");
        return HI_FAILURE;
    }

    video_parameter_set_id = hevc_u_v(hevc_ctx->bs_p, 0x4, "sps_video_parameter_set_id");
    if ((hi_s32)video_parameter_set_id >= (hevc_ctx->max_vps_num)) {
        hi_log_err("sps_video_parameter_set_id(%u) out of range", hevc_ctx->max_vps_num);
        return HEVC_DEC_ERR;
    }

    sps_max_sub_layers_minus1 = hevc_u_v(hevc_ctx->bs_p, 0x3, "sps_max_sub_layers_minus1");
    if (sps_max_sub_layers_minus1 > HEVC_MAX_TEMPLAYER) {
        hi_log_err("sps_max_sub_layers_minus1 out of range(0,6).");
        return HEVC_DEC_ERR;
    }
    sps_temporal_id_nesting_flag = hevc_u_v(hevc_ctx->bs_p, 1, "sps_temporal_id_nesting_flag");

    ret = hevc_dec_ptl(hevc_ctx, &(profile_tier_level), 1, sps_max_sub_layers_minus1);
    if (ret != HEVC_DEC_NORMAL) {
        hi_log_err("SPS hevc_dec_ptl error.");
        return HEVC_DEC_ERR;
    }

    sps_seq_parameter_set_id = hevc_ue_v(hevc_ctx->bs_p, "sps_seq_parameter_set_id");
    if ((hi_s32)sps_seq_parameter_set_id >= hevc_ctx->max_sps_num) { /* range is 0 to 16 */
        hi_log_err("sps_seq_parameter_set_id(%d) out of range", hevc_ctx->max_sps_num);
        return HEVC_DEC_ERR;
    }

    if (hevc_ctx->sps[sps_seq_parameter_set_id].valid) {
        sps_tmp->video_parameter_set_id  = video_parameter_set_id;
        sps_tmp->sps_max_sub_layers_minus1  = sps_max_sub_layers_minus1;
        sps_tmp->sps_temporal_id_nesting_flag  = sps_temporal_id_nesting_flag;
        sps_tmp->profile_tier_level = profile_tier_level;
        sps_tmp->seq_parameter_set_id  = sps_seq_parameter_set_id;

        if (hevc_process_sps(hevc_ctx, sps_tmp) != HEVC_DEC_NORMAL) {
            /* 此时p_hevc_ctx->sps[sps_seq_parameter_set_id]为前一个可用 */
            hevc_ctx->sei_sps = hevc_ctx->sps[sps_seq_parameter_set_id];
            DPRINT("SPS[%d] decode error0.\n", sps_seq_parameter_set_id);
            return HEVC_DEC_ERR;
        }

        sps_tmp->is_refresh = 1;
        sps_tmp->valid = 1;
        if (memmove_s(&(hevc_ctx->sps[sps_seq_parameter_set_id]), sizeof(hevc_ctx->sps[sps_seq_parameter_set_id]),
            sps_tmp, sizeof(hevc_seq_param_set)) != EOK) {
            hi_log_err("call memmove_s is failed\n");
            return HEVC_DEC_ERR;
        }
        hevc_ctx->sei_sps = hevc_ctx->sps[sps_seq_parameter_set_id];
    } else {
        hevc_ctx->sps[sps_seq_parameter_set_id].video_parameter_set_id = video_parameter_set_id;
        hevc_ctx->sps[sps_seq_parameter_set_id].sps_max_sub_layers_minus1 = sps_max_sub_layers_minus1;
        hevc_ctx->sps[sps_seq_parameter_set_id].sps_temporal_id_nesting_flag = sps_temporal_id_nesting_flag;
        hevc_ctx->sps[sps_seq_parameter_set_id].profile_tier_level = profile_tier_level;
        hevc_ctx->sps[sps_seq_parameter_set_id].seq_parameter_set_id  = sps_seq_parameter_set_id;

        if (hevc_process_sps(hevc_ctx, &(hevc_ctx->sps[sps_seq_parameter_set_id])) != HEVC_DEC_NORMAL) {
            hi_log_err("SPS[%u] decode error.", sps_seq_parameter_set_id);
            hevc_ctx->sps[sps_seq_parameter_set_id].is_refresh = 1;
            hevc_ctx->sps[sps_seq_parameter_set_id].valid = 0;
            return HEVC_DEC_ERR;
        }
        hevc_ctx->sps[sps_seq_parameter_set_id].is_refresh = 1;
        hevc_ctx->sps[sps_seq_parameter_set_id].valid = 1;
        hevc_ctx->sei_sps = hevc_ctx->sps[sps_seq_parameter_set_id];
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_process_pps_proc_uniform_spacing_flag_false(hevc_ctx *hevc_ctx, hevc_pic_param_set *pps,
    hevc_seq_param_set *sps)
{
    hi_s32 i;

    for (i = 0; i < (pps->num_tile_columns - 1); i++) {
        pps->column_width[i] = hevc_ue_v(hevc_ctx->bs_p, "column_width_minus1") + 1;
        /* Width constraint */
        if (pps->column_width[i] < 0 || pps->column_width[i] > (hi_s32)sps->ctb_num_width) {
            hi_log_err("column_width out of range");
            return HEVC_DEC_ERR;
        }
    }
    for (i = 0; i < (pps->num_tile_rows - 1); i++) {
        pps->row_height[i] = hevc_ue_v(hevc_ctx->bs_p, "row_height_minus1") + 1;
        /* Height constraint */
        if (pps->row_height[i] < 0 || pps->row_height[i] > (hi_s32)sps->ctb_num_height) {
            hi_log_err("row_height out of range");
            return HEVC_DEC_ERR;
        }
    }

    pps->column_bd[pps->num_tile_columns - 1] = sps->ctb_num_width;
    for (i = 0; i < pps->num_tile_columns - 1; i++) {
        pps->column_bd[i] = pps->column_width[i];
        pps->column_bd[pps->num_tile_columns - 1] -= pps->column_bd[i];
    }

    if (pps->column_bd[pps->num_tile_columns - 1] <= 0) {
        hi_log_err("column_bd <= 0, invalid!");
        return HEVC_DEC_ERR;
    }

    pps->row_bd[pps->num_tile_rows - 1] = sps->ctb_num_height;
    for (i = 0; i < pps->num_tile_rows - 1; i++) {
        pps->row_bd[i] = pps->row_height[i];
        pps->row_bd[pps->num_tile_rows - 1] -= pps->row_bd[i];
    }

    if (pps->row_bd[pps->num_tile_rows - 1] <= 0) {
        hi_log_err("row_bd <= 0, invalid!");
        return HEVC_DEC_ERR;
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_process_pps_proc_tiles_enabled_flag(hevc_ctx *hevc_ctx, hevc_pic_param_set *pps,
    hevc_seq_param_set *sps)
{
    hi_s32 i;

    if (!pps->tiles_enabled_flag) {
        pps->column_bd[0] = sps->ctb_num_width;
        pps->row_bd[0] = sps->ctb_num_height;
        return HEVC_DEC_NORMAL;
    }
    pps->num_tile_columns = hevc_ue_v(hevc_ctx->bs_p, "num_tile_columns_minus1") + 1;
    if (pps->num_tile_columns <= 0 || pps->num_tile_columns > HEVC_MAX_TILE_COLUMNS) {
        hi_log_err("num_tile_columns(%u) out of range", pps->num_tile_columns);
        return HEVC_DEC_ERR;
    }

    pps->num_tile_rows = hevc_ue_v(hevc_ctx->bs_p, "num_tile_rows_minus1") + 1;
    if (pps->num_tile_rows <= 0 || pps->num_tile_rows > HEVC_MAX_TILE_ROWS) {
        hi_log_err("num_tile_rows out of range");
        return HEVC_DEC_ERR;
    }

    pps->uniform_spacing_flag = hevc_u_v(hevc_ctx->bs_p, 1, "uniform_spacing_flag");

    if (!pps->uniform_spacing_flag) {
        if (hevc_process_pps_proc_uniform_spacing_flag_false(hevc_ctx, pps, sps) != HEVC_DEC_NORMAL) {
            return HEVC_DEC_ERR;
        }
    } else {
        for (i = 0; i < pps->num_tile_columns; i++) {
            pps->column_bd[i] = (i + 1) * sps->ctb_num_width / pps->num_tile_columns -
                (i * sps->ctb_num_width) / pps->num_tile_columns;
        }
        for (i = 0; i < pps->num_tile_rows; i++) {
            pps->row_bd[i] = (i + 1) * sps->ctb_num_height / pps->num_tile_rows -
                (i * sps->ctb_num_height) / pps->num_tile_rows;
        }
    }

    if (pps->num_tile_columns != 1 || pps->num_tile_rows != 1) {
        pps->loop_filter_across_tiles_enabled_flag = hevc_u_v(hevc_ctx->bs_p, 1,
            "loop_filter_across_tiles_enabled_flag");
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_process_pps_proc_tile_columns_and_rows(hevc_pic_param_set *pps, hevc_seq_param_set *sps)
{
    hi_s32 i;

    for (i = 0; i < pps->num_tile_columns; i++) {
        if (pps->column_bd[i] * sps->max_cu_width <= 64 && sps->pic_width_in_luma_samples > 64) { /* range is 0 to 64 */
            hi_log_err("PPS tile width(%u) is too small.(Logic Unsupport)", pps->column_bd[i] * sps->max_cu_width);
            return HEVC_DEC_ERR;
        }
    }
    for (i = 0; i < pps->num_tile_rows; i++) {
        if (pps->row_bd[i] * sps->max_cu_width < 64) { /* range is more than 64 */
            hi_log_err("PPS tile height(%u) is too small.(Logic Unsupport)", pps->row_bd[i] * sps->max_cu_width);
            return HEVC_DEC_ERR;
        }
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_process_pps_check_sps_id_valid(hevc_ctx *hevc_ctx, hi_s32 sps_id)
{
    if (sps_id < 0 || sps_id >= (hevc_ctx->max_sps_num)) {
        hi_log_err("pic_parameter_set_id(%u) out of range[0,15]", sps_id);
        return HEVC_DEC_ERR;
    } else if (hevc_ctx->sps[sps_id].valid == 0) {
        hi_log_err("SPS(%d) haven't decode", sps_id);
        return HEVC_DEC_ERR;
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_process_pps(hevc_ctx *hevc_ctx, hevc_pic_param_set *pps)
{
    hevc_seq_param_set *sps = HI_NULL;
    hi_s32 init_qp_value;
    hi_s32 ret;

    pps->loop_filter_across_tiles_enabled_flag = 1;
    pps->num_tile_columns = 1;
    pps->num_tile_rows = 1;
    pps->seq_parameter_set_id = hevc_ue_v(hevc_ctx->bs_p, "pps_seq_parameter_set_id");

    if (hevc_process_pps_check_sps_id_valid(hevc_ctx, pps->seq_parameter_set_id) != HEVC_DEC_NORMAL) {
        return HEVC_DEC_ERR;
    }

    sps = &hevc_ctx->sps[pps->seq_parameter_set_id];

    pps->dependent_slice_segments_enabled_flag  = hevc_u_v(hevc_ctx->bs_p, 1, "dependent_slice_segments_enabled_flag");
    pps->output_flag_present_flag               = hevc_u_v(hevc_ctx->bs_p, 1, "output_flag_present_flag");
    pps->num_extra_slice_header_bits            = hevc_u_v(hevc_ctx->bs_p, 0x3, "num_extra_slice_header_bits");
    pps->sign_data_hiding_flag                  = hevc_u_v(hevc_ctx->bs_p, 1, "sign_data_hiding_flag");
    pps->cabac_init_present_flag                = hevc_u_v(hevc_ctx->bs_p, 1, "cabac_init_present_flag");

    pps->num_ref_idx_l0_default_active = 1 + hevc_ue_v(hevc_ctx->bs_p, "num_ref_idx_l0_default_active_minus1");
    if (pps->num_ref_idx_l0_default_active < 0 || pps->num_ref_idx_l0_default_active > 15) { /* range is 0 to 15 */
        hi_log_err("num_ref_idx_l0_default_active out of range[0,15].");
        return HEVC_DEC_ERR;
    }

    pps->num_ref_idx_l1_default_active = 1 + hevc_ue_v(hevc_ctx->bs_p, "num_ref_idx_l1_default_active_minus1");
    if (pps->num_ref_idx_l1_default_active < 0 || pps->num_ref_idx_l1_default_active > 15) { /* range is 0 to 15 */
        hi_log_err("num_ref_idx_l1_default_active out of range[0,15].");
        return HEVC_DEC_ERR;
    }

    init_qp_value = hevc_se_v(hevc_ctx->bs_p, "init_qp_minus26");
    if (init_qp_value == 0x7fffffff) {
        hi_log_err("hevc_se_v failed");
        return HEVC_DEC_ERR;
    }
    pps->pic_init_qp = 26 + init_qp_value; /* 26 bit */
    if (pps->pic_init_qp < (hi_s32)(-(sps->qp_bd_offset_y)) || pps->pic_init_qp > 51) { /* range is 0 to 51 */
        hi_log_err("pic_init_qp(%u) out of range", pps->pic_init_qp);
        return HEVC_DEC_ERR;
    }

    pps->constrained_intra_pred_flag   = hevc_u_v(hevc_ctx->bs_p, 1, "constrained_intra_pred_flag");
    pps->transform_skip_enabled_flag   = hevc_u_v(hevc_ctx->bs_p, 1, "transform_skip_enabled_flag");
    pps->cu_qp_delta_enabled_flag      = hevc_u_v(hevc_ctx->bs_p, 1, "cu_qp_delta_enabled_flag");

    pps->diff_cu_qp_delta_depth = (!pps->cu_qp_delta_enabled_flag) ? 0 :
        hevc_ue_v(hevc_ctx->bs_p, "diff_cu_qp_delta_depth");

    if (pps->diff_cu_qp_delta_depth < 0 || pps->diff_cu_qp_delta_depth > 0x3) {
        hi_log_err("diff_cu_qp_delta_depth out of range[0,3].");
        return HEVC_DEC_ERR;
    }
    pps->max_cu_qp_delta_depth         = pps->diff_cu_qp_delta_depth;
    pps->pic_cb_qp_offset              = hevc_se_v(hevc_ctx->bs_p, "pps_cb_qp_offset");
    if (pps->pic_cb_qp_offset < -12 || pps->pic_cb_qp_offset > 12) { /* range is -12 to 12 */
        hi_log_err("pic_cb_qp_offset out of range[-12,12].");
        return HEVC_DEC_ERR;
    }

    pps->pic_cr_qp_offset = hevc_se_v(hevc_ctx->bs_p, "pps_cr_qp_offset");
    if (pps->pic_cr_qp_offset < -12 || pps->pic_cr_qp_offset > 12) { /* range is -12 to 12 */
        hi_log_err("pic_cr_qp_offset out of range[-12,12].");
        return HEVC_DEC_ERR;
    }

    pps->pic_slice_chroma_qp_offsets_present_flag = hevc_u_v(hevc_ctx->bs_p,
                                                             1, "pps_slice_chroma_qp_offsets_present_flag");
    pps->weighted_pred_flag                       = hevc_u_v(hevc_ctx->bs_p, 1, "weighted_pred_flag");
    pps->weighted_bipred_flag                     = hevc_u_v(hevc_ctx->bs_p, 1, "weighted_bipred_flag");
    pps->transquant_bypass_enable_flag            = hevc_u_v(hevc_ctx->bs_p, 1, "transquant_bypass_enable_flag");
    pps->tiles_enabled_flag                       = hevc_u_v(hevc_ctx->bs_p, 1, "tiles_enabled_flag");
    pps->entropy_coding_sync_enabled_flag         = hevc_u_v(hevc_ctx->bs_p, 1, "entropy_coding_sync_enabled_flag");

    if (hevc_process_pps_proc_tiles_enabled_flag(hevc_ctx, pps, sps) != HEVC_DEC_NORMAL) {
        hi_log_err("PPS proc tiles_enabled_flag failed!");
        return HEVC_DEC_ERR;
    }

    if (hevc_process_pps_proc_tile_columns_and_rows(pps, sps) != HEVC_DEC_NORMAL) {
        hi_log_err("PPS proc tile_columns and rows failed!");
        return HEVC_DEC_ERR;
    }

    pps->loop_filter_across_slices_enabled_flag = hevc_u_v(hevc_ctx->bs_p,
                                                           1, "loop_filter_across_slices_enabled_flag");
    pps->deblocking_filter_control_present_flag = hevc_u_v(hevc_ctx->bs_p,
                                                           1, "deblocking_filter_control_present_flag");
    if (pps->deblocking_filter_control_present_flag) {
        pps->deblocking_filter_override_enabled_flag = hevc_u_v(hevc_ctx->bs_p,
                                                                1, "deblocking_filter_override_enabled_flag");
        pps->pic_disable_deblocking_filter_flag = hevc_u_v(hevc_ctx->bs_p, 1, "pps_disable_deblocking_filter_flag");
        if (!pps->pic_disable_deblocking_filter_flag) {
            pps->pps_beta_offset_div2 = hevc_se_v(hevc_ctx->bs_p, "pps_beta_offset_div2");
            if (pps->pps_beta_offset_div2 < -6 || pps->pps_beta_offset_div2 > 6) { /* range is -6 to 6 */
                hi_log_err("pps_beta_offset_div2(%u) out of range(-6,6)\n", pps->pps_beta_offset_div2);
                pps->pps_beta_offset_div2 = 0; /* Assignment strong solution */
            }
            pps->pps_tc_offset_div2 = hevc_se_v(hevc_ctx->bs_p, "pps_tc_offset_div2");
            if (pps->pps_tc_offset_div2 < -6 || pps->pps_tc_offset_div2 > 6) { /* range is -6 to 6 */
                hi_log_err("pps_tc_offset_div2(%u) out of range(-6,6)\n", pps->pps_tc_offset_div2);
                pps->pps_tc_offset_div2 = 0; /* Assignment strong solution */
            }
        }
    }

    pps->pic_scaling_list_data_present_flag = hevc_u_v(hevc_ctx->bs_p, 1, "pps_scaling_list_data_present_flag");
    if (pps->pic_scaling_list_data_present_flag) {
        ret = hevc_dec_scaling_list_data(hevc_ctx, &(pps->scaling_list));
        if (HEVC_DEC_NORMAL != ret) {
            hi_log_err("PPS hevc_dec_scaling_list_data error.");
            return HEVC_DEC_ERR;
        }
    }
    pps->lists_modification_present_flag = hevc_u_v(hevc_ctx->bs_p, 1, "lists_modification_present_flag");
    pps->log2_parallel_merge_level = hevc_ue_v(hevc_ctx->bs_p, "log2_parallel_merge_level_minus2") + 0x2;
    if (pps->log2_parallel_merge_level < 0x2 || pps->log2_parallel_merge_level > (hi_s32)sps->log2_ctb_size_y) {
        hi_log_err("log2_parallel_merge_level(%u) out of range(2,log2_ctb_size_y)\n", pps->log2_parallel_merge_level);
        return HEVC_DEC_ERR;
    }
    pps->slice_segment_header_extension_present_flag = hevc_u_v(hevc_ctx->bs_p,
                                                                1, "slice_segment_header_extension_present_flag");
    pps->pps_extension_flag = hevc_u_v(hevc_ctx->bs_p, 1, "pps_extension_flag");

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_dec_pps(hevc_ctx *hevc_ctx)
{
    hi_u32 pic_parameter_set_id;
    hevc_pic_param_set *pps_tmp = HI_NULL;

    pos();

    pps_tmp = &hevc_ctx->tmp_param.pps_tmp;
    if (memset_s(pps_tmp, sizeof(hevc_pic_param_set), 0x0, sizeof(hevc_pic_param_set))) {
        hi_log_err("memset_s failed.\n");
    }
    pic_parameter_set_id = hevc_ue_v(hevc_ctx->bs_p, "pps_pic_parameter_set_id");
    if (((hi_s32)pic_parameter_set_id >= (hevc_ctx->max_pps_num)) ||
        (pic_parameter_set_id >= sizeof(hevc_ctx->pps) / sizeof(hevc_ctx->pps[0]))) {
        hi_log_err("pic_parameter_set_id(%u) out of range(0,63)", pic_parameter_set_id);
        return HEVC_DEC_ERR;
    }
    if (hevc_ctx->pps[pic_parameter_set_id].valid) {
        pps_tmp->pic_parameter_set_id = pic_parameter_set_id;
        if (HEVC_DEC_NORMAL != hevc_process_pps(hevc_ctx, pps_tmp)) {
            hi_log_err("decode error, pic_parameter_set_id:%u\n", pic_parameter_set_id);
            return HEVC_DEC_ERR;
        }
        pps_tmp->is_refresh = 1;
        pps_tmp->valid = 1;
        if (memmove_s(&(hevc_ctx->pps[pic_parameter_set_id]), sizeof(hevc_pic_param_set),
            pps_tmp, sizeof(hevc_pic_param_set)) != EOK) {
            hi_log_err("call memmove_s is failed\n");
            return HEVC_DEC_ERR;
        }
    } else {
        hevc_ctx->pps[pic_parameter_set_id].pic_parameter_set_id = pic_parameter_set_id;
        if (hevc_process_pps(hevc_ctx, &(hevc_ctx->pps[pic_parameter_set_id])) != HEVC_DEC_NORMAL) {
            hi_log_err("decode error, pic_parameter_set_id:%u\n", pic_parameter_set_id);
            hevc_ctx->pps[pic_parameter_set_id].is_refresh = 1;
            hevc_ctx->pps[pic_parameter_set_id].valid = 0;
            return HEVC_DEC_ERR;
        }
        hevc_ctx->pps[pic_parameter_set_id].is_refresh = 1;
        hevc_ctx->pps[pic_parameter_set_id].valid = 1;
    }

    return HEVC_DEC_NORMAL;
}

static hi_void hevc_applay_ref_picture_set_proc_long_term(hevc_ctx *hevc_ctx, hi_s32 i, hi_s32 *is_reference)
{
    hi_u32 j;
    hi_s32 cur_poc;
    hi_s32 ref_poc;
    hevc_short_term_rpset *temp_rps = &(hevc_ctx->curr_slice.short_term_ref_pic_set);
    hevc_pic_param_set *pps = &hevc_ctx->pps[hevc_ctx->curr_slice.pic_parameter_set_id];
    hevc_seq_param_set *sps = &hevc_ctx->sps[pps->seq_parameter_set_id];
    const hi_s32 poc_cycle = 1 << sps->max_pic_order_cnt_lsb;

    for (j = temp_rps->num_negative_pics + temp_rps->num_positive_pics; j < temp_rps->num_of_pics; j++) {
        if (hevc_ctx->curr_slice.check_lt_msb[j]) {
            if ((hevc_ctx->dpb.fs[i]->frame.is_long_term) && (hevc_ctx->dpb.fs[i]->poc == temp_rps->poc[j])) {
                *is_reference = 1;
                hevc_ctx->dpb.fs[i]->is_reference = 1;
                hevc_ctx->dpb.fs[i]->frame_store_state = FS_IN_DPB;
            }
        } else if ((hevc_ctx->dpb.fs[i]->frame.is_long_term) &&
            ((hevc_ctx->dpb.fs[i]->poc % poc_cycle) == (temp_rps->poc[j] % poc_cycle))) {
            *is_reference = 1;
            hevc_ctx->dpb.fs[i]->is_reference = 1;
            hevc_ctx->dpb.fs[i]->frame_store_state = FS_IN_DPB;
        }

        if (*is_reference == 0) {
            cur_poc = hevc_ctx->dpb.fs[i]->poc;
            ref_poc = temp_rps->poc[j];

            if (!hevc_ctx->curr_slice.check_lt_msb[j]) {
                cur_poc = cur_poc % poc_cycle;
                ref_poc = ref_poc % poc_cycle;
            }

            if ((hevc_ctx->dpb.fs[i]->is_reference) && (cur_poc == ref_poc)) {
                *is_reference = 1;
                hevc_ctx->dpb.fs[i]->is_reference = 1;
                hevc_ctx->dpb.fs[i]->frame.is_long_term = 1;
                hevc_ctx->dpb.fs[i]->frame_store_state = FS_IN_DPB;
            }
        }
    }

    return;
}

static hi_void hevc_apply_reference_picture_set(hevc_ctx *hevc_ctx)
{
    hi_u32 i, j;
    hi_s32 is_reference;
    hevc_short_term_rpset *temp_rps = &(hevc_ctx->curr_slice.short_term_ref_pic_set);

    for (i = 0; i < hevc_ctx->dpb.used_size; i++) {
        is_reference = 0;

        /* long term reference */
        hevc_applay_ref_picture_set_proc_long_term(hevc_ctx, i, &is_reference);

        /* short term reference */
        for (j = 0; j < (temp_rps->num_negative_pics + temp_rps->num_positive_pics); j++) {
            if ((!hevc_ctx->dpb.fs[i]->frame.is_long_term) &&
                (hevc_ctx->dpb.fs[i]->poc == (hevc_ctx->curr_slice.poc + temp_rps->delta_poc[j]))) {
                is_reference = 1;
                hevc_ctx->dpb.fs[i]->is_reference = 1;
                hevc_ctx->dpb.fs[i]->frame_store_state = FS_IN_DPB;
            }
        }

        /* mark the picture as "unused for reference" if it is not in the Reference Picture Set */
        if ((hevc_ctx->dpb.fs[i]->poc != hevc_ctx->curr_slice.poc) && (is_reference == 0)) {
            hevc_ctx->dpb.fs[i]->is_reference = 0;
            hevc_ctx->dpb.fs[i]->frame.is_long_term = 0;
        }
    }

    return;
}

static hi_void hevc_update_lt_ref_list(hevc_ctx *hevc_ctx)
{
    hi_s32 i = 0, j = 0, k = 0;
    hi_s32 rps_poc;
    hi_s32 cur_poc;
    hi_u8  delta_poc_msb_cycle_flag;
    hi_s32 poc_cycle;
    hevc_short_term_rpset *rps = HI_NULL;
    hevc_pic_param_set    *pps = HI_NULL;
    hevc_seq_param_set    *sps = HI_NULL;

    pps = &hevc_ctx->pps[hevc_ctx->curr_slice.pic_parameter_set_id];
    sps = &hevc_ctx->sps[pps->seq_parameter_set_id];
    poc_cycle = 1 << sps->max_pic_order_cnt_lsb;

    rps = &(hevc_ctx->curr_slice.short_term_ref_pic_set);
    for (i = (hi_s32)rps->num_of_pics - 1; i > (hi_s32)(rps->num_negative_pics + rps->num_positive_pics - 1); i--) {
        if (rps->used_flag[i] == 0) {
            continue;
        }
        if (k >= HEVC_MAX_DPB_NUM) {
            return;
        }
        rps_poc = rps->poc[i];
        delta_poc_msb_cycle_flag = hevc_ctx->curr_slice.check_lt_msb[i];
        rps_poc = delta_poc_msb_cycle_flag ? rps_poc : (hi_s32)((hi_u32)rps_poc & ((hi_u32)poc_cycle - 1));
        for (j = 0; j < (hi_s32)hevc_ctx->dpb.used_size; j++) {
            cur_poc = hevc_ctx->dpb.fs[j]->poc;
            cur_poc = delta_poc_msb_cycle_flag ? cur_poc : (hi_s32)((hi_u32)cur_poc & ((hi_u32)poc_cycle - 1));
            if (cur_poc == rps_poc) {
                hevc_ctx->dpb.fs[j]->is_reference = 1;

                hevc_ctx->dpb.fs[j]->frame.is_short_term = 0;
                hevc_ctx->dpb.fs[j]->frame.is_long_term  = 1;
                hevc_ctx->dpb.fs_ltref[k++] = hevc_ctx->dpb.fs[j];
                break;
            }
        }
    }
    hevc_ctx->dpb.ltref_frames_in_buffer = k;
    while ((k < (hi_s32)hevc_ctx->dpb.size) && (k < HEVC_MAX_DPB_NUM)) {
        hevc_ctx->dpb.fs_ltref[k++] = (hevc_frame_store *)HI_NULL;
    }

    return;
}

static hi_void hevc_update_ref_list(hevc_ctx *hevc_ctx)
{
    hi_u32 i = 0, j = 0, k = 0;
    hevc_short_term_rpset *rps = &(hevc_ctx->curr_slice.short_term_ref_pic_set);
    hi_s32 poc, val;

    for (i = 0; i < rps->num_negative_pics; i++) {
        if (rps->used_flag[i] == 0) {
            continue;
        }
        if (k >= HEVC_MAX_DPB_NUM) {
            return;
        }
        poc = hevc_ctx->curr_slice.poc + rps->delta_poc[i];
        for (j = 0; j < hevc_ctx->dpb.used_size; j++) {
            if (poc == hevc_ctx->dpb.fs[j]->poc) {
                hevc_ctx->dpb.fs[j]->is_reference = 1;
                hevc_ctx->dpb.fs[j]->frame.is_short_term = 1;
                hevc_ctx->dpb.fs[j]->frame.is_long_term  = 0;
                hevc_ctx->dpb.fs_negative_ref[k++] = hevc_ctx->dpb.fs[j];
                break;
            }
        }
    }
    hevc_ctx->dpb.negative_ref_frames_in_buffer = k;
    while ((k < hevc_ctx->dpb.size) && (k < HEVC_MAX_DPB_NUM)) {
        hevc_ctx->dpb.fs_negative_ref[k++] = (hevc_frame_store *)HI_NULL;
    }

    k = 0;
    val = rps->num_negative_pics + rps->num_positive_pics;
    for (; (hi_s32)i < val; i++) {
        if (!rps->used_flag[i]) {
            continue;
        }
        poc = hevc_ctx->curr_slice.poc + rps->delta_poc[i];
        for (j = 0; j < hevc_ctx->dpb.used_size; j++) {
            if (poc == hevc_ctx->dpb.fs[j]->poc) {
                hevc_ctx->dpb.fs[j]->is_reference = 1;
                hevc_ctx->dpb.fs[j]->frame.is_short_term = 1;
                hevc_ctx->dpb.fs[j]->frame.is_long_term  = 0;
                hevc_ctx->dpb.fs_positive_ref[k++] = hevc_ctx->dpb.fs[j];
                break;
            }
        }
    }
    hevc_ctx->dpb.positive_ref_frames_in_buffer = k;

    while (k < hevc_ctx->dpb.size) {
        hevc_ctx->dpb.fs_positive_ref[k++] = (hevc_frame_store *)HI_NULL;
    }

    return;
}

static hi_void hevc_check_that_all_ref_pics_are_available_proc_long_term(hevc_ctx *hevc_ctx,
    hevc_short_term_rpset *temp_rps, hi_s32 *at_least_one_lost, hi_s32 *i_poc_lost)
{
    hi_u32 i, j, is_available;
    hevc_pic_param_set *pps = &hevc_ctx->pps[hevc_ctx->curr_slice.pic_parameter_set_id];
    hevc_seq_param_set *sps = &hevc_ctx->sps[pps->seq_parameter_set_id];
    const hi_s32 poc_cycle = 1 << sps->max_pic_order_cnt_lsb;

    for (i = temp_rps->num_negative_pics + temp_rps->num_positive_pics; i < temp_rps->num_of_pics; i++) {
        is_available = 0;
        /* loop through all pictures in the reference picture buffer */
        for (j = 0; j < hevc_ctx->dpb.used_size; j++) {
            if ((hevc_ctx->curr_slice.check_lt_msb[i]) && (hevc_ctx->dpb.fs[j]->frame.is_long_term) &&
                (hevc_ctx->dpb.fs[j]->poc == temp_rps->poc[i]) && (hevc_ctx->dpb.fs[j]->is_reference)) {
                is_available = 1;
            }
            if ((!hevc_ctx->curr_slice.check_lt_msb[i]) && (hevc_ctx->dpb.fs[j]->frame.is_long_term) &&
                ((hevc_ctx->dpb.fs[j]->poc % poc_cycle) == (temp_rps->poc[i] % poc_cycle)) &&
                (hevc_ctx->dpb.fs[j]->is_reference)) {
                is_available = 1;
            }
        }

        /* report that a picture is lost if it is in the ref picture set but not available as ref picture */
        if (is_available == 0) {
            if ((hevc_ctx->curr_slice.poc + temp_rps->delta_poc[i] >= hevc_ctx->poc_random_access) &&
                (temp_rps->used_flag[i])) {
                *at_least_one_lost = 1;
                *i_poc_lost = hevc_ctx->curr_slice.poc + temp_rps->delta_poc[i];
            }
        }
    }
    return;
}

static hi_void hevc_check_that_all_ref_pics_are_available_proc_short_term(hevc_ctx *hevc_ctx,
    hevc_short_term_rpset *temp_rps, hi_s32 *at_least_one_lost, hi_s32 *i_poc_lost)
{
    hi_u32 i, j, is_available;

    for (i = 0; i < temp_rps->num_negative_pics + temp_rps->num_positive_pics; i++) {
        is_available = 0;
        /* loop through all pictures in the ref picture buffer */
        for (j = 0; j < hevc_ctx->dpb.used_size; j++) {
            if ((!hevc_ctx->dpb.fs[j]->frame.is_long_term) &&
                (hevc_ctx->dpb.fs[j]->poc == hevc_ctx->curr_slice.poc + temp_rps->delta_poc[i]) &&
                (hevc_ctx->dpb.fs[j]->is_reference)) {
                is_available = 1;
            }
        }
        /* report that a picture is lost if it is in the ref picture set but not available as ref picture */
        if (is_available == 0) {
            if ((hevc_ctx->curr_slice.poc + temp_rps->delta_poc[i] >= hevc_ctx->poc_random_access) &&
                (temp_rps->used_flag[i])) {
                *at_least_one_lost = 1;
                *i_poc_lost = hevc_ctx->curr_slice.poc + temp_rps->delta_poc[i];
            }
        }
    }

    return;
}

static hi_s32 hevc_check_that_all_ref_pics_are_available(hevc_ctx *hevc_ctx, hi_s32* pi_lost_poc)
{
    hi_s32 at_least_one_lost = 0;
    hi_s32 is_poc_lost = 0;
    hevc_short_term_rpset *temp_rps = HI_NULL;

    if ((hevc_ctx->curr_slice.nal_unit_type == NAL_UNIT_CODED_SLICE_CRA) ||
        (hevc_ctx->curr_slice.nal_unit_type == NAL_UNIT_CODED_SLICE_IDR_N_LP) ||
        (hevc_ctx->curr_slice.nal_unit_type == NAL_UNIT_CODED_SLICE_IDR_W_RADL)) {
        return HEVC_DEC_NORMAL;
    }

    temp_rps = &(hevc_ctx->curr_slice.short_term_ref_pic_set);

    if (temp_rps->num_negative_pics + temp_rps->num_positive_pics >= HEVC_MAX_NUM_REF_PICS) {
        hi_log_err("num_negative_pics(%d) or num_positive_pics(%d) invalid!\n", temp_rps->num_negative_pics,
            temp_rps->num_positive_pics);
        return HEVC_DEC_ERR;
    }

    /* loop through all long-term pictures in the ref picture set to see if the picture should be kept as ref picture */
    hevc_check_that_all_ref_pics_are_available_proc_long_term(hevc_ctx, temp_rps, &at_least_one_lost, &is_poc_lost);

    /* loop through all short-term pictures in the ret picture set to see
     * if the picture should be kept as ref picture
     */
    hevc_check_that_all_ref_pics_are_available_proc_short_term(hevc_ctx, temp_rps, &at_least_one_lost, &is_poc_lost);

    if (at_least_one_lost) {
        *pi_lost_poc = is_poc_lost;
        return HEVC_DEC_ERR;
    }

    return HEVC_DEC_NORMAL;
}

static hi_void hevc_remove_frame_store_out_dpb(hevc_ctx *hevc_ctx, hi_u32 pos)
{
    hi_u32 i;

    hevc_ctx->dpb.fs[pos]->frame_store_state = FS_NOT_USED;
    hevc_ctx->dpb.fs[pos]->is_reference = 0;
    hevc_ctx->dpb.fs[pos] = (hevc_frame_store *)HI_NULL;

    for (i = pos; i <= (hevc_ctx->dpb.used_size - 1); i++) {
        hevc_ctx->dpb.fs[i] = hevc_ctx->dpb.fs[i + 1];
    }
    hevc_ctx->dpb.fs[hevc_ctx->dpb.used_size - 1] = (hevc_frame_store *)HI_NULL;
    hevc_ctx->dpb.used_size--;

    return;
}

static hi_s32 hevc_remove_unused_frame_store(hevc_ctx *hevc_ctx)
{
    hi_u32 i, j, record_used_size;
    hi_s32 is_removed = HEVC_FALSE;

    record_used_size = hevc_ctx->dpb.used_size;
    for (i = 0, j = 0; i < record_used_size; i++) {
        if (j >= HEVC_MAX_DPB_NUM) {
            break;
        }
        if (hevc_ctx->dpb.fs[j]->is_reference == 0) {
            hevc_remove_frame_store_out_dpb(hevc_ctx, j);
            is_removed = HEVC_TRUE;
        } else {
            j++;
        }
    }

    return is_removed;
}

static hi_s32 hevc_ref_pic_process(hevc_ctx *hevc_ctx)
{
    hi_s32 ret;
    hi_s32 ilost_poc = 0;

    hevc_apply_reference_picture_set(hevc_ctx);
    if (hevc_remove_unused_frame_store(hevc_ctx) != HEVC_TRUE) {
        hi_log_dbg("remove_unused_frame_store faild!\n");
        ret = HEVC_DEC_ERR;
        return ret;
    }

    ret = hevc_check_that_all_ref_pics_are_available(hevc_ctx, &ilost_poc);
    if (ret != HEVC_DEC_NORMAL) {
        hi_log_dbg("ref lost poc = %d\n", ilost_poc);
    }

    hevc_update_ref_list(hevc_ctx);
    hevc_update_lt_ref_list(hevc_ctx);

    return HEVC_DEC_NORMAL;
}

static hi_void hevc_pic_type_statistic(hevc_ctx *hevc_ctx)
{
    if (hevc_is_idr_unit(hevc_ctx->curr_slice.nal_unit_type) == 1) {
        hevc_ctx->curr_pic.pic_type = HEVC_IDR_FRAME;
    } else if (hevc_is_bla_unit(hevc_ctx->curr_slice.nal_unit_type) == 1) {
        hevc_ctx->curr_pic.pic_type = HEVC_BLA_FRAME;
    } else if (hevc_is_cra_unit(hevc_ctx->curr_slice.nal_unit_type) == 1) {
        hevc_ctx->curr_pic.pic_type = HEVC_CRA_FRAME;
    } else {
        switch (hevc_ctx->curr_slice.slice_type) {
            case HEVC_B_SLICE:
                hi_log_dbg("B_SLICE\n");
                hevc_ctx->curr_pic.pic_type = HEVC_B_FRAME;
                break;
            case HEVC_P_SLICE:
                hi_log_dbg("P_SLICE\n");
                if (hevc_ctx->curr_pic.pic_type != HEVC_B_FRAME) {
                    hevc_ctx->curr_pic.pic_type = HEVC_P_FRAME;
                }
                break;
            case HEVC_I_SLICE:
                hi_log_dbg("I_SLICE\n");
                if (hevc_ctx->curr_pic.pic_type != HEVC_B_FRAME
                        && hevc_ctx->curr_pic.pic_type != HEVC_P_FRAME) {
                    hevc_ctx->curr_pic.pic_type = HEVC_I_FRAME;
                }
                break;
            default:
                hevc_ctx->curr_pic.pic_type = HEVC_ERR_FRAME;
                break;
        }
    }

    return;
}

static hi_s32 hevc_alloc_frame_store(hevc_ctx *hevc_ctx)
{
    hi_u32 i = 0;

    hevc_ctx->curr_pic.state = HEVC_PIC_EMPTY;

    for (i = 0; i < HEVC_MAX_FRAME_STORE; i++) {
        if (hevc_ctx->frame_store[i].frame_store_state == FS_NOT_USED) {
            hevc_ctx->curr_pic.state                            = HEVC_PIC_DECODING;
            hevc_ctx->curr_pic.frame_store                      = &hevc_ctx->frame_store[i];
            hevc_ctx->curr_pic.frame_store->non_existing        = 0;
            hevc_ctx->curr_pic.frame_store->frame.is_long_term  = 0;
            hevc_ctx->curr_pic.frame_store->frame.is_short_term = 0;
            break;
        }
    }
    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_init_pic(hevc_ctx *hevc_ctx)
{
    hi_s32 ret;
    hi_s32 pic_width, pic_height, log2_ctb_size_y;
    hevc_video_param_set *vps      = HI_NULL;
    hevc_seq_param_set   *sps      = HI_NULL;
    hevc_pic_param_set   *pps      = HI_NULL;

    pic_width = hevc_ctx->curr_sps.pic_width_in_luma_samples;
    pic_height = hevc_ctx->curr_sps.pic_height_in_luma_samples;
    log2_ctb_size_y = hevc_ctx->curr_sps.log2_ctb_size_y;

    if ((hevc_ctx->curr_slice.pic_parameter_set_id < 0) ||
        (hevc_ctx->curr_slice.pic_parameter_set_id >= (hevc_ctx->max_pps_num))) {
        hi_log_err("pic_parameter_set_id:%u\n", hevc_ctx->curr_slice.pic_parameter_set_id);
        return HEVC_DEC_ERR;
    }

    pps = &hevc_ctx->pps[hevc_ctx->curr_slice.pic_parameter_set_id];
    sps = &hevc_ctx->sps[pps->seq_parameter_set_id];
    vps = &hevc_ctx->vps[sps->video_parameter_set_id];

    if ((hevc_ctx->curr_vps.video_parameter_set_id != vps->video_parameter_set_id) ||
        (vps->is_refresh) || (!hevc_ctx->allow_start_dec)) {
        vps->is_refresh = 0;
        if (memmove_s(&hevc_ctx->curr_vps, sizeof(hevc_video_param_set), vps, sizeof(hevc_video_param_set)) != EOK) {
            hi_log_err("call memmove_s failed\n");
            return HEVC_DEC_ERR;
        }
    }

    if ((hevc_ctx->curr_sps.seq_parameter_set_id != sps->seq_parameter_set_id) ||
        (sps->is_refresh) || (!hevc_ctx->allow_start_dec) || (pic_width != (hi_s32)sps->pic_width_in_luma_samples) ||
        (pic_height != (hi_s32)sps->pic_height_in_luma_samples) || (log2_ctb_size_y != (hi_s32)sps->log2_ctb_size_y)) {
        sps->is_refresh = 0;
        if (memmove_s(&hevc_ctx->curr_sps, sizeof(hevc_seq_param_set), sps, sizeof(hevc_seq_param_set) != EOK)) {
            hi_log_err("call memmove_s failed\n");
            return HEVC_DEC_ERR;
        }
    }

    if ((hevc_ctx->curr_pps.pic_parameter_set_id != pps->pic_parameter_set_id) ||
        (pps->is_refresh) || (!hevc_ctx->allow_start_dec) || (pic_width != (hi_s32)sps->pic_width_in_luma_samples) ||
        (pic_height != (hi_s32)sps->pic_height_in_luma_samples) || (log2_ctb_size_y != (hi_s32)sps->log2_ctb_size_y)) {
        pps->is_refresh = 0;
        if (memmove_s(&hevc_ctx->curr_pps, sizeof(hevc_pic_param_set), pps, sizeof(hevc_pic_param_set)) != EOK) {
            hi_log_err("call memmove_s failed\n");
            return HEVC_DEC_ERR;
        }
    }

    ret = hevc_alloc_frame_store(hevc_ctx);
    if (ret != HEVC_DEC_NORMAL) {
        hi_log_err("hevc_alloc_frame_store error\n");
        return HEVC_DEC_ERR;
    }

    hevc_ctx->curr_pic.state = HEVC_PIC_DECODING;
    hevc_ctx->curr_pic.thispoc = hevc_ctx->curr_slice.poc;
    hevc_ctx->curr_pic.frame_store->poc = hevc_ctx->curr_slice.poc;
    hevc_ctx->curr_pic.pic_type = HEVC_I_FRAME;
    hevc_ctx->total_slice_num = 0;

    return HEVC_DEC_NORMAL;
}

static hi_void hevc_init_dec_buffers(hevc_ctx *hevc_ctx)
{
    hi_u32 i, j;

    pos();

    /* Init dpb */
    hevc_ctx->dpb.size = HEVC_MAX_DPB_NUM;
    hevc_ctx->dpb.used_size                     = 0;
    hevc_ctx->dpb.negative_ref_frames_in_buffer = 0;
    hevc_ctx->dpb.positive_ref_frames_in_buffer = 0;
    hevc_ctx->dpb.ltref_frames_in_buffer        = 0;
    hevc_ctx->dpb.max_long_term_pic_idx         = 0;

    for (i = 0; i < HEVC_MAX_DPB_NUM; i++) {
        hevc_ctx->dpb.fs_ltref[i]        = HI_NULL;
        hevc_ctx->dpb.fs_negative_ref[i] = HI_NULL;
        hevc_ctx->dpb.fs_positive_ref[i] = HI_NULL;
        hevc_ctx->dpb.fs[i]              = HI_NULL;
    }

    /* Init Frame store */
    for (i = 0; i < HEVC_MAX_FRAME_STORE; i++) {
        hevc_ctx->frame_store[i].non_existing      = 0;
        hevc_ctx->frame_store[i].frame_store_state  = FS_NOT_USED;
        hevc_ctx->frame_store[i].is_reference      = 0;
        hevc_ctx->frame_store[i].poc               = 0;
        hevc_ctx->frame_store[i].frame.frame_store = (struct hevc_frame_store *)&hevc_ctx->frame_store[i];
    }

    /* Init ListX */
    for (i = 0; i < 0x2; i++) {
        for (j = 0; j < HEVC_MAX_LIST_SIZE; j++) {
            hevc_ctx->list_x[i][j] = HI_NULL;
        }
        hevc_ctx->curr_slice.listx_size[i] = 0;
    }

    return;
}

static hi_s32 compare_pic_by_poc_asc(hi_void *arg1, hi_void *arg2)
{
    if ((*(hevc_frame_store**)arg1)->poc < (*(hevc_frame_store**)arg2)->poc) {
        return -1;
    }

    if ((*(hevc_frame_store**)arg1)->poc > (*(hevc_frame_store**)arg2)->poc) {
        return 1;
    } else {
        return 0;
    }
}

#define STKSIZ (8 * sizeof(hi_void*) - 2)

#define CUTOFF 8            /* testing shows that this is good value */

static hi_void swap_kn(char *a, char *b, size_t width)
{
    char tmp;

    if (a != b) {
        while (width--) {
            tmp = *a;
            *a++ = *b;
            *b++ = tmp;
        }
    }
}

static hi_void shortsort(char *lo, char *hi, size_t width, int (*comp)(hi_void *, hi_void *))
{
    char *p = HI_NULL;
    char *max = HI_NULL;

    while (hi > lo) {
        max = lo;
        if (width == 0) {
            break;
        }
        for (p = lo + width; p <= hi; p += width) {
            if (comp(p, max) > 0) {
                max = p;
            }
        }
        swap_kn(max, hi, width);
        hi -= width;
    }
}

static hi_void hevc_qsort(hi_void *base, size_t num, size_t width, int (*comp)(hi_void *, hi_void *))
{
    char *lo = HI_NULL;
    char *hi = HI_NULL;
    char *mid = HI_NULL;
    char *loguy = HI_NULL;
    char *higuy = HI_NULL;
    size_t size;
    char *lostk[STKSIZ] = {0};
    char *histk[STKSIZ] = {0};
    int stkptr;

    if (num < 0x2 || width == 0) {
        return;
    }

    stkptr = 0;

    lo = base;
    hi = (char *)base + width * (num - 1);

recurse:

    size = (hi - lo) / width + 1;

    if (size <= CUTOFF) {
        shortsort(lo, hi, width, comp);
    } else {
        mid = lo + (size / 0x2) * width;

        if (comp(lo, mid) > 0) {
            swap_kn(lo, mid, width);
        }
        if (comp(lo, hi) > 0) {
            swap_kn(lo, hi, width);
        }
        if (comp(mid, hi) > 0) {
            swap_kn(mid, hi, width);
        }

        loguy = lo;
        higuy = hi;

        for (;;) {
            if (mid > loguy) {
                do  {
                    loguy += width;
                } while (loguy < mid && comp(loguy, mid) <= 0);
            }

            if (mid <= loguy) {
                do  {
                    loguy += width;
                } while (loguy <= hi && comp(loguy, mid) <= 0);
            }

            do  {
                higuy -= width;
            } while (higuy > mid && comp(higuy, mid) > 0);

            if (higuy < loguy) {
                break;
            }
            swap_kn(loguy, higuy, width);

            if (mid == higuy) {
                mid = loguy;
            }
        }

        higuy += width;
        if (mid < higuy) {
            do  {
                higuy -= width;
            } while (higuy > mid && comp(higuy, mid) == 0);
        }
        if (mid >= higuy) {
            do  {
                higuy -= width;
            } while (higuy > lo && comp(higuy, mid) == 0);
        }

        if (higuy - lo >= hi - loguy) {
            if (lo < higuy) {
                lostk[stkptr] = lo;
                histk[stkptr] = higuy;
                ++stkptr;
            }

            if (loguy < hi) {
                lo = loguy;
                goto recurse;
            }
        } else {
            if (loguy < hi) {
                lostk[stkptr] = loguy;
                histk[stkptr] = hi;
                ++stkptr;
            }

            if (lo < higuy) {
                hi = higuy;
                goto recurse;
            }
        }
    }

    --stkptr;
    if (stkptr >= 0) {
        lo = lostk[stkptr];
        hi = histk[stkptr];
        goto recurse;
    } else {
        return;
    }
}

static hi_s32 hevc_insert_frm_in_dpb(hevc_ctx *hevc_ctx, hi_u32 pos, hevc_curr_pic *curr_pic)
{
    if (pos >= HEVC_MAX_DPB_NUM) {
        hi_log_err("with invalid pos(%u)", pos);
        return HEVC_DEC_ERR;
    }

    hevc_ctx->dpb.fs[pos] = curr_pic->frame_store;
    hevc_ctx->dpb.fs[pos]->frame_store_state = FS_IN_DPB;
    curr_pic->is_ref_idc = 1;
    hevc_ctx->dpb.fs[pos]->is_reference = (curr_pic->is_ref_idc == 0) ? 0 : 1;
    hevc_ctx->dpb.fs[pos]->frame.frame_store = (struct hevc_frame_store *)curr_pic->frame_store;
    hevc_ctx->dpb.fs[pos]->pic_type = hevc_ctx->dpb.fs[pos]->frame.pic_type = curr_pic->pic_type;
    hevc_ctx->dpb.fs[pos]->poc = curr_pic->thispoc;
    hevc_ctx->dpb.fs[pos]->frame.poc = curr_pic->thispoc;

    hevc_qsort((hi_void *)hevc_ctx->dpb.fs, (pos + 1), sizeof(hevc_frame_store*), compare_pic_by_poc_asc);

    hevc_ctx->dpb.used_size++;

    curr_pic->state = HEVC_PIC_EMPTY;

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_dec_order_process(hevc_ctx *hevc_ctx)
{
    hi_s32 ret;

    if (hevc_remove_unused_frame_store(hevc_ctx) != HEVC_DEC_NORMAL) {
        hi_log_err("remove_unused_frame_store faild!\n");
        ret = HEVC_DEC_ERR;
        return ret;
    }

    ret = hevc_insert_frm_in_dpb(hevc_ctx, hevc_ctx->dpb.used_size, &hevc_ctx->curr_pic);
    if (ret != HEVC_DEC_NORMAL) {
        hi_log_err(" hevc_insert_frm_in_dpb Failed.");
        return HEVC_DEC_ERR;
    }

    return ret;
}

static hi_s32 hevc_store_pic_in_dpb(hevc_ctx *hevc_ctx)
{
    hi_s32 ret;

    ret = hevc_dec_order_process(hevc_ctx);
    if (ret != HEVC_DEC_NORMAL) {
        hi_log_info(" hevc_dec_order_process Failed.");
    }

    return ret;
}

static hi_s32 hevc_write_pic_msg(hevc_ctx *hevc_ctx)
{
    hi_s32 cnt;
    hevc_ctx->hevc_frm_poc = hevc_ctx->curr_pic.thispoc;
    hevc_ctx->hevc_frm_type = HEVC_ERR_FRAME;
    hevc_ctx->hevc_ref_num = 0;
    for (cnt = 0; cnt < 16; cnt++) { /* 16 loops */
        hevc_ctx->hevc_ref_poc[cnt] = 0;
    }
    hi_log_dbg("hevc_frm_poc:%d\n", hevc_ctx->hevc_frm_poc);

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_check_list_x(const hevc_ctx *hevc_ctx)
{
    hi_u32 i;
    hi_u32 list0_size, list1_size;
    const hevc_slice_segment_header *slice = &hevc_ctx->curr_slice;

    if (hevc_ctx->curr_slice.dependent_slice_segment_flag) {
        hi_log_err("dependent_slice_segment_flag invalid");
        return HEVC_DEC_ERR;
    }

    list0_size = slice->listx_size[0];
    list1_size = slice->listx_size[1];

    if (list0_size >= HEVC_MAX_LIST_SIZE) {
        hi_log_err("ListX ERROR: list0_size(%u) >= maxlistsize(%u)\n", list0_size, HEVC_MAX_LIST_SIZE);
        return HEVC_DEC_ERR;
    }

    if (list1_size >= HEVC_MAX_LIST_SIZE) {
        hi_log_err("ListX ERROR: list1_size(%u) >= maxlistsize(%u)\n", list1_size, HEVC_MAX_LIST_SIZE);
        return HEVC_DEC_ERR;
    }

    for (i = 0; i < list0_size; i++) {
        if (hevc_ctx->list_x[0][i] == HI_NULL) {
            hi_log_err("list_x[0][%u] = HI_NULL", i);
            return HEVC_DEC_ERR;
        }

        if (hevc_ctx->list_x[0][i]->frame_store == HI_NULL) {
            hi_log_err("list_x[0][%u]->frame_store = HI_NULL", i);
            return HEVC_DEC_ERR;
        }
    }

    for (i = 0; i < list1_size; i++) {
        if (hevc_ctx->list_x[1][i] == HI_NULL) {
            hi_log_err("list_x[1][%u] = HI_NULL", i);
            return HEVC_DEC_ERR;
        }

        if (hevc_ctx->list_x[1][i]->frame_store == HI_NULL) {
            hi_log_err("list_x[1][%u]->frame_store = HI_NULL", i);
            return HEVC_DEC_ERR;
        }
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_write_slice_msg_proc_list0(hevc_ctx *hevc_ctx)
{
    hi_u32 i;
    hi_s32 m;
    hi_s32 ref_pic_ok;

    for (i = 0; i < hevc_ctx->curr_slice.listx_size[0]; i++) {
        ref_pic_ok = 0;
        for (m = 0; m < hevc_ctx->hevc_ref_num; m++) {
            if (hevc_ctx->hevc_ref_poc[m] == hevc_ctx->list_x[0][i]->poc) {
                ref_pic_ok = 1;
                break;
            }
        }
        if (ref_pic_ok == 0) {
            hevc_ctx->hevc_ref_poc[hevc_ctx->hevc_ref_num++] = hevc_ctx->list_x[0][i]->poc;
            if (hevc_ctx->hevc_ref_num >= 16) { /* hevc_ref_num less than 16 */
                hi_log_err("p_hevc_ctx->hevc_ref_num(%u) invalid!\n", hevc_ctx->hevc_ref_num);
                return HEVC_DEC_ERR;
            }
        }
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_write_slice_msg_proc_list1(hevc_ctx *hevc_ctx)
{
    hi_u32 i;
    hi_s32 m;
    hi_s32 ref_pic_ok;

    for (i = 0; i < hevc_ctx->curr_slice.listx_size[1]; i++) {
        ref_pic_ok = 0;
        for (m = 0; m < hevc_ctx->hevc_ref_num; m++) {
            if (hevc_ctx->hevc_ref_poc[m] == hevc_ctx->list_x[1][i]->poc) {
                ref_pic_ok = 1;
                break;
            }
        }
        if (ref_pic_ok == 0) {
            hevc_ctx->hevc_ref_poc[hevc_ctx->hevc_ref_num++] = hevc_ctx->list_x[1][i]->poc;
            if (hevc_ctx->hevc_ref_num >= 16) { /* hevc_ref_num less than 16 */
                hi_log_err("p_hevc_ctx->hevc_ref_num(%u) invalid!\n", hevc_ctx->hevc_ref_num);
                return HEVC_DEC_ERR;
            }
        }
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_write_slice_msg(hevc_ctx *hevc_ctx)
{
    if (hevc_check_list_x(hevc_ctx) != HEVC_DEC_NORMAL) {
        hi_log_err("hevc_check_list_x failed\n");
        return HEVC_DEC_ERR;
    }

    hevc_ctx->total_slice_num++;

    if (hevc_ctx->curr_slice.slice_type == HEVC_I_SLICE) {
        hi_log_info("HEVC_I_SLICE\n");
    } else if (hevc_ctx->curr_slice.slice_type == HEVC_P_SLICE) {
        hi_log_info("HEVC_P_SLICE\n");
    } else if (hevc_ctx->curr_slice.slice_type == HEVC_B_SLICE) {
        hi_log_info("HEVC_B_SLICE\n");
    } else {
        hi_log_info("HEVC_NON_SLICE\n");
    }

    hi_log_info("listx_size[0]:%u\n", hevc_ctx->curr_slice.listx_size[0]);
    if (hevc_write_slice_msg_proc_list0(hevc_ctx) != HEVC_DEC_NORMAL) {
        return HEVC_DEC_ERR;
    }
    if (hevc_ctx->curr_slice.listx_size[0] > 0) {
        hi_log_info("\n");
    }

    hi_log_info("listx_size[1]:%u\n", hevc_ctx->curr_slice.listx_size[1]);
    if (hevc_write_slice_msg_proc_list1(hevc_ctx) != HEVC_DEC_NORMAL) {
        return HEVC_DEC_ERR;
    }
    if (hevc_ctx->curr_slice.listx_size[1] > 0) {
        hi_log_info("\n");
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_init_list_x(hevc_ctx *hevc_ctx)
{
    hevc_storable_pic *temp_list_x[0x2][HEVC_MAX_LIST_SIZE] = {HI_NULL};
    hevc_ref_pic_lists_moddification *rpl_modify = HI_NULL;
    hi_u32 i, idx, ref_frame_num;
    hi_u32 neg_ref_frame_num;
    hi_u32 pos_ref_frame_num;
    hi_u32 lt_ref_frame_num;

    if (hevc_ctx == HI_NULL) {
        return HEVC_DEC_ERR;
    }

    idx = 0;
    if ((hevc_ctx->dpb.negative_ref_frames_in_buffer >= HEVC_MAX_DPB_NUM) ||
        (hevc_ctx->dpb.positive_ref_frames_in_buffer >= HEVC_MAX_DPB_NUM)) {
        return HEVC_DEC_ERR;
    }

    for (i = 0; i < hevc_ctx->dpb.negative_ref_frames_in_buffer; i++) {
        if ((hevc_ctx->dpb.fs_negative_ref[i]->is_reference == 1) &&
            (hevc_ctx->dpb.fs_negative_ref[i]->frame.is_long_term == 0) &&
            (hevc_ctx->dpb.fs_negative_ref[i]->frame.is_short_term == 1)) {
            if (idx < HEVC_MAX_LIST_SIZE) {
                temp_list_x[0][idx++] = &hevc_ctx->dpb.fs_negative_ref[i]->frame;
            }
        }
    }
    neg_ref_frame_num = idx;

    for (i = 0; i < hevc_ctx->dpb.positive_ref_frames_in_buffer; i++) {
        if ((hevc_ctx->dpb.fs_positive_ref[i]->is_reference == 1) &&
            (hevc_ctx->dpb.fs_positive_ref[i]->frame.is_long_term == 0) &&
            (hevc_ctx->dpb.fs_positive_ref[i]->frame.is_short_term == 1)) {
            if (idx < HEVC_MAX_LIST_SIZE) {
                temp_list_x[0][idx++] = &hevc_ctx->dpb.fs_positive_ref[i]->frame;
            }
        }
    }

    if (idx >= HEVC_MAX_LIST_SIZE) {
        return HEVC_DEC_ERR;
    }

    pos_ref_frame_num = idx - neg_ref_frame_num;

    /* long term handling */
    for (i = 0; i < hevc_ctx->dpb.ltref_frames_in_buffer; i++) {
        if ((hevc_ctx->dpb.fs_ltref[i]->is_reference == 1) &&
            (hevc_ctx->dpb.fs_ltref[i]->frame.is_long_term == 1) &&
            (hevc_ctx->dpb.fs_ltref[i]->frame.is_short_term) == 0) {
            temp_list_x[0][idx++] = &hevc_ctx->dpb.fs_ltref[i]->frame;
        }
    }
    lt_ref_frame_num = idx - neg_ref_frame_num - pos_ref_frame_num;
    ref_frame_num = idx;

    if (ref_frame_num == 0) {
        hevc_ctx->curr_slice.listx_size[0] = 0;
        hevc_ctx->curr_slice.listx_size[1] = 0;
        if (memset_s(hevc_ctx->list_x, sizeof(hevc_ctx->list_x), 0x0, sizeof(hevc_ctx->list_x))) {
            hi_log_err("memset_s failed.\n");
        }

        return HEVC_DEC_NORMAL;
    }

    if (hevc_ctx->curr_slice.slice_type == HEVC_B_SLICE) {
        idx = 0;
        for (i = 0; i < pos_ref_frame_num; i++) {
            if ((neg_ref_frame_num + i) < HEVC_MAX_LIST_SIZE) {
                temp_list_x[1][idx++] = temp_list_x[0][neg_ref_frame_num + i];
            }
        }
        for (i = 0; i < neg_ref_frame_num; i++) {
            temp_list_x[1][idx++] = temp_list_x[0][i];
        }
        for (i = 0; i < lt_ref_frame_num; i++) {
            temp_list_x[1][idx++] = temp_list_x[0][neg_ref_frame_num + pos_ref_frame_num + i];
        }
    }

    /* set max size */
    hevc_ctx->curr_slice.listx_size[0] = hevc_ctx->curr_slice.num_ref_idx[0];
    hevc_ctx->curr_slice.listx_size[1] = hevc_ctx->curr_slice.num_ref_idx[1];

    idx = 0;
    rpl_modify = &(hevc_ctx->curr_slice.ref_pic_lists_modification);
    for (i = 0; i < hevc_ctx->curr_slice.listx_size[0]; i++) {
        idx = rpl_modify->ref_pic_list_modification_flag_l0 ? rpl_modify->list_entry_l0[i] : i % ref_frame_num;
        hevc_ctx->list_x[0][i] = temp_list_x[0][idx];
    }

    if (hevc_ctx->curr_slice.slice_type == HEVC_B_SLICE) {
        for (i = 0; i < hevc_ctx->curr_slice.listx_size[1]; i++) {
            idx = rpl_modify->ref_pic_list_modification_flag_l1 ? rpl_modify->list_entry_l1[i] : i % ref_frame_num;
            hevc_ctx->list_x[1][i] = temp_list_x[1][idx];
        }

        /* for generalized b slice */
        if (hevc_ctx->curr_slice.listx_size[1] == 0) {
            if (memmove_s(hevc_ctx->list_x[1], sizeof(hevc_ctx->list_x[1]),
                hevc_ctx->list_x[0], sizeof(hevc_ctx->list_x[0])) != EOK) {
                hi_log_err("memmove_s failed.\n");
                return HEVC_DEC_ERR;
            }
            hevc_ctx->curr_slice.listx_size[1] = hevc_ctx->curr_slice.listx_size[0];
        }
    }

    /* set the unused list entries to a valid one */
    for (i = hevc_ctx->curr_slice.listx_size[0]; i < (HEVC_MAX_LIST_SIZE); i++) {
        hevc_ctx->list_x[0][i] = hevc_ctx->list_x[0][0];
    }
    for (i = hevc_ctx->curr_slice.listx_size[1]; i < (HEVC_MAX_LIST_SIZE); i++) {
        hevc_ctx->list_x[1][i] = hevc_ctx->list_x[1][0];
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_repair_list(hevc_ctx *hevc_ctx)
{
    hi_u32 i, i_list, i_list_cnt;
    hevc_storable_pic *repair_pic = (hevc_storable_pic *)HI_NULL;

    switch (hevc_ctx->curr_slice.slice_type) {
        case HEVC_P_SLICE:
            i_list_cnt = 1;
            break;
        case HEVC_B_SLICE:
            i_list_cnt = 0x2;
            break;
        case HEVC_I_SLICE:
            i_list_cnt = 0;
            break;
        default:
            hi_log_err("unkown slice type:%u\n", hevc_ctx->curr_slice.slice_type);
            return HEVC_DEC_ERR;
    }

    for (i_list = 0; i_list < i_list_cnt; i_list++) {
        if ((hi_s32)hevc_ctx->curr_slice.listx_size[i_list] <= 0) {
            continue;
        }
        for (i = 0; i < hevc_ctx->curr_slice.listx_size[i_list]; i++) {
            if ((hevc_storable_pic *)HI_NULL != hevc_ctx->list_x[i_list][i]) {
                repair_pic = hevc_ctx->list_x[i_list][i];
                break;
            }
        }

        for (i = 0; i < hevc_ctx->curr_slice.listx_size[i_list]; i++) {
            if ((hevc_storable_pic *)HI_NULL == hevc_ctx->list_x[i_list][i]) {
                hi_log_err("list_x = HI_NULL");
                hevc_ctx->list_x[i_list][i] = repair_pic;
            }
        }
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_dec_list(hevc_ctx *hevc_ctx)
{
    hi_s32 ret;

    if (hevc_ctx->curr_slice.slice_type == HEVC_I_SLICE) {
        hevc_ctx->curr_slice.listx_size[0] = 0;
        hevc_ctx->curr_slice.listx_size[1] = 0;
        return HEVC_DEC_NORMAL;
    }

    ret = hevc_init_list_x(hevc_ctx);
    if (ret != HEVC_DEC_NORMAL) {
        hi_log_err("hevc_init_list_x error.");
        return HEVC_DEC_ERR;
    }

    ret = hevc_repair_list(hevc_ctx);
    if (ret != HEVC_DEC_NORMAL) {
        hi_log_err("hevc_repair_list error.");
        return HEVC_DEC_ERR;
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_is_refefence_nalu(const hevc_ctx *hevc_ctx)
{
    return ((hevc_ctx->curr_slice.nal_unit_type <= NAL_UNIT_RESERVED_VCL_R15) &&
            (hevc_ctx->curr_slice.nal_unit_type % 0x2 != 0)) ||
            ((hevc_ctx->curr_slice.nal_unit_type >= NAL_UNIT_CODED_SLICE_BLA_W_LP) &&
            (hevc_ctx->curr_slice.nal_unit_type <= NAL_UNIT_RESERVED_IRAP_VCL23));
}

static hi_s32 hevc_dec_pred_weight_table_proc_b_slice(hevc_ctx *hevc_ctx, hevc_seq_param_set *sps,
    hevc_pred_weight_table *pwt)
{
    hi_u32 i, j;

    if (hevc_ctx->curr_slice.num_ref_idx[1] >= HEVC_MAX_NUM_REF_PICS) {
        hi_log_err("p_hevc_ctx->curr_slice.num_ref_idx[1](%u) invalid.\n", hevc_ctx->curr_slice.num_ref_idx[1]);
        return HEVC_DEC_ERR;
    }

    for (i = 0; i < hevc_ctx->curr_slice.num_ref_idx[1]; i++) {
        pwt->luma_weight_l1_flag[i] = hevc_u_v(hevc_ctx->bs_p, 1, "luma_weight_l1_flag");
    }
    if (sps->chroma_format_idc != 0) {
        for (i = 0; i < hevc_ctx->curr_slice.num_ref_idx[1]; i++) {
            pwt->chroma_weight_l1_flag[i] = hevc_u_v(hevc_ctx->bs_p, 1, "chroma_weight_l1_flag");
        }
    }
    for (i = 0; i < hevc_ctx->curr_slice.num_ref_idx[1]; i++) {
        if (pwt->luma_weight_l1_flag[i]) {
            hevc_se_v(hevc_ctx->bs_p, "delta_luma_weight_l1");
            hevc_se_v(hevc_ctx->bs_p, "luma_offset_l1");
        }
        if ((sps->chroma_format_idc != 0) && (pwt->chroma_weight_l1_flag[i])) {
            for (j = 0; j < 0x2; j++) {
                hevc_se_v(hevc_ctx->bs_p, "delta_chroma_weight_l1");
                hevc_se_v(hevc_ctx->bs_p, "delta_chroma_offset_l1");
            }
        }
    }
    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_dec_pred_weight_table(hevc_ctx *hevc_ctx)
{
    hi_u32 i, j;
    hevc_seq_param_set    *sps = HI_NULL;
    hevc_pic_param_set    *pps = HI_NULL;
    hevc_pred_weight_table  pwt = {0};

    pps = &hevc_ctx->pps[hevc_ctx->curr_slice.pic_parameter_set_id];
    sps = &hevc_ctx->sps[pps->seq_parameter_set_id];

    if (((hevc_ctx->curr_slice.slice_type == HEVC_P_SLICE) && (pps->weighted_pred_flag)) ||
        ((hevc_ctx->curr_slice.slice_type == HEVC_B_SLICE) && (pps->weighted_bipred_flag))) {
        if (hevc_ctx->curr_slice.num_ref_idx[0] >= HEVC_MAX_NUM_REF_PICS) {
            hi_log_err("hevc_ctx->curr_slice.num_ref_idx[0](%u) invalid.\n", hevc_ctx->curr_slice.num_ref_idx[0]);
            return HEVC_DEC_ERR;
        }

        hevc_ue_v(hevc_ctx->bs_p, "luma_log2_weight_denom");

        if (sps->chroma_format_idc != 0) {
            hevc_se_v(hevc_ctx->bs_p, "delta_chroma_log2_weight_denom");
        }

        for (i = 0; i < hevc_ctx->curr_slice.num_ref_idx[0]; i++) {
            pwt.luma_weight_l0_flag[i] = hevc_u_v(hevc_ctx->bs_p, 1, "luma_weight_l0_flag");
        }
        if (sps->chroma_format_idc != 0) {
            for (i = 0; i < hevc_ctx->curr_slice.num_ref_idx[0]; i++) {
                pwt.chroma_weight_l0_flag[i] = hevc_u_v(hevc_ctx->bs_p, 1, "chroma_weight_l0_flag");
            }
        }

        for (i = 0; i < hevc_ctx->curr_slice.num_ref_idx[0]; i++) {
            if (pwt.luma_weight_l0_flag[i]) {
                hevc_se_v(hevc_ctx->bs_p, "delta_luma_weight_l0");
                hevc_se_v(hevc_ctx->bs_p, "luma_offset_l0");
            }
            if ((sps->chroma_format_idc == 0) || (!pwt.chroma_weight_l0_flag[i])) {
                continue;
            }
            for (j = 0; j < 0x2; j++) {
                hevc_se_v(hevc_ctx->bs_p, "delta_chroma_weight_l0");
                hevc_se_v(hevc_ctx->bs_p, "delta_chroma_offset_l0");
            }
        }

        if (hevc_ctx->curr_slice.slice_type == HEVC_B_SLICE) {
            if (hevc_dec_pred_weight_table_proc_b_slice(hevc_ctx, sps, &pwt) != HEVC_DEC_NORMAL) {
                return HEVC_DEC_ERR;
            }
        }
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_vps_sps_pps_check(hevc_ctx *hevc_ctx)
{
    hevc_video_param_set *vps = HI_NULL;
    hevc_seq_param_set   *sps = HI_NULL;
    hevc_pic_param_set   *pps = HI_NULL;

    /* check pps is get or not */
    if (hevc_ctx->curr_slice.pic_parameter_set_id < 0 ||
        hevc_ctx->curr_slice.pic_parameter_set_id >= (hevc_ctx->max_pps_num)) {
        hi_log_dbg("hevc_vps_sps_pps_check pic_parameter_set_id(%d) out of range",
            hevc_ctx->curr_slice.pic_parameter_set_id);
        return HEVC_DEC_ERR;
    }

    pps = &hevc_ctx->pps[hevc_ctx->curr_slice.pic_parameter_set_id];
    if (!pps->valid) {
        hi_log_dbg("pps with this pic_parameter_set_id = %d havn't be decoded",
            hevc_ctx->curr_slice.pic_parameter_set_id);
        return HEVC_DEC_ERR;
    }

    /* check sps is get or not */
    if (pps->seq_parameter_set_id < 0 || pps->seq_parameter_set_id >= (hevc_ctx->max_sps_num)) {
        hi_log_dbg("hevc_vps_sps_pps_check seq_parameter_set_id(%d) out of range", pps->seq_parameter_set_id);
        return HEVC_DEC_ERR;
    }

    sps = &hevc_ctx->sps[pps->seq_parameter_set_id];
    if (!sps->valid) {
        hi_log_dbg("sps with this seq_parameter_set_id = %d havn't be decoded", pps->seq_parameter_set_id);
        return HEVC_DEC_ERR;
    }

    /* check vps is get or not */
    if ((hi_s32)sps->video_parameter_set_id >= (hevc_ctx->max_vps_num)) {
        hi_log_dbg("hevc_vps_sps_pps_check video_parameter_set_id = %d out of range", sps->video_parameter_set_id);
        return HEVC_DEC_ERR;
    }

    vps = &hevc_ctx->vps[sps->video_parameter_set_id];
    if (!vps->valid) {
        hi_log_dbg("vps with this video_parameter_set_id = %d havn't be decoded", sps->video_parameter_set_id);
        return HEVC_DEC_ERR;
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_is_new_pic(hevc_ctx *hevc_ctx)
{
    hi_s32 ret;

    if (hevc_ctx->poc_random_access == HEVC_MAX_INT) {
        if (hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_CRA        ||
            hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_W_LP   ||
            hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_N_LP   ||
            hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_W_RADL ||
            (((hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_TRAIL_N) ||
            (hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_TRAIL_R)) &&
            (hevc_ctx->curr_slice.slice_type == HEVC_I_SLICE))) {
            hevc_ctx->poc_random_access = hevc_ctx->curr_slice.poc;
        } else if ((hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_IDR_W_RADL) ||
            (hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_IDR_N_LP)) {
            hevc_ctx->poc_random_access = -HEVC_MAX_INT;
        } else {
            return IS_SKIP_PIC;
        }
    }

    /* check if picture should be skipped because of association with a previous BLA picture */
    if (hevc_ctx->prev_rap_is_bla && hevc_ctx->curr_slice.poc < hevc_ctx->poc_cra &&
        (hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_RASL_R ||
        hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_RASL_N)) {
    }

    if (!hevc_ctx->curr_slice.dependent_slice_segment_flag) {
        if (hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_IDR_W_RADL ||
            hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_IDR_N_LP) {
            hevc_ctx->poc_cra = hevc_ctx->curr_slice.poc;
            hevc_ctx->prev_rap_is_bla = HEVC_FALSE;
        } else if (hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_CRA) {
            hevc_ctx->poc_cra = hevc_ctx->curr_slice.poc;
            hevc_ctx->prev_rap_is_bla = HEVC_FALSE;
        } else if (hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_W_LP ||
            hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_W_RADL ||
            hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_N_LP) {
            hevc_ctx->poc_cra = hevc_ctx->curr_slice.poc;
            hevc_ctx->prev_rap_is_bla = HEVC_TRUE;
        }
    }

    ret = hevc_ctx->curr_slice.first_slice_segment_in_pic_flag;

    return ret;
}

static hi_s32 hevc_get_rap_pic_flag(hevc_ctx *hevc_ctx)
{
    return hevc_ctx->curr_slice.nal_unit_type == NAL_UNIT_CODED_SLICE_IDR_W_RADL ||
        hevc_ctx->curr_slice.nal_unit_type == NAL_UNIT_CODED_SLICE_IDR_N_LP ||
        hevc_ctx->curr_slice.nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_N_LP ||
        hevc_ctx->curr_slice.nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_W_RADL ||
        hevc_ctx->curr_slice.nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_W_LP ||
        hevc_ctx->curr_slice.nal_unit_type == NAL_UNIT_CODED_SLICE_CRA;
}

static hi_s32 hevc_get_ldr_pic_flag(hevc_ctx *hevc_ctx)
{
    return hevc_ctx->curr_slice.nal_unit_type == NAL_UNIT_CODED_SLICE_IDR_W_RADL ||
        hevc_ctx->curr_slice.nal_unit_type == NAL_UNIT_CODED_SLICE_IDR_N_LP;
}

static hi_s32 hevc_dec_ref_pic_lists_modification(const hevc_ctx *hevc_ctx,
    const hevc_slice_segment_header *slice, hevc_ref_pic_lists_moddification *rp_list_modification,
    hi_s32 num_rps_curr_temp_list)
{
    hi_u32 i, length, temp;

    temp = num_rps_curr_temp_list;
    length = 1;
    num_rps_curr_temp_list--;
    num_rps_curr_temp_list = (hi_u32)num_rps_curr_temp_list >> 1;
    while (num_rps_curr_temp_list) {
        length++;
        num_rps_curr_temp_list = (hi_u32)num_rps_curr_temp_list >> 1;
    }

    rp_list_modification->ref_pic_list_modification_flag_l0 = hevc_u_v(hevc_ctx->bs_p, 1,
                                                                       "ref_pic_list_modification_flag_l0");
    if (rp_list_modification->ref_pic_list_modification_flag_l0 && (temp > 1)) {
        if (slice->num_ref_idx[0] >= HEVC_MAX_NUM_REF_PICS) {
            hi_log_err("slice->num_ref_idx[0](%d) invalid", slice->num_ref_idx[0]);
            return HEVC_DEC_ERR;
        }

        for (i = 0; i < slice->num_ref_idx[0]; i++) {
            rp_list_modification->list_entry_l0[i] = hevc_u_v(hevc_ctx->bs_p, length, "list_entry_l0");
        }
    }

    if (slice->slice_type == HEVC_B_SLICE) {
        rp_list_modification->ref_pic_list_modification_flag_l1 = hevc_u_v(hevc_ctx->bs_p, 1,
                                                                           "ref_pic_list_modification_flag_l1");
        if (rp_list_modification->ref_pic_list_modification_flag_l1 && (temp > 1)) {
            if (slice->num_ref_idx[1] >= HEVC_MAX_NUM_REF_PICS) {
                hi_log_err("slice->num_ref_idx[0](%d) invalid", slice->num_ref_idx[1]);
                return HEVC_DEC_ERR;
            }

            for (i = 0; i < slice->num_ref_idx[1]; i++) {
                rp_list_modification->list_entry_l1[i] = hevc_u_v(hevc_ctx->bs_p, length, "list_entry_l1");
            }
        }
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_dec_slice_sgment_header_check_pps_id(hevc_ctx *hevc_ctx)
{
    if ((hevc_ctx->curr_slice.pic_parameter_set_id < 0) ||
        (hevc_ctx->curr_slice.pic_parameter_set_id >= (hevc_ctx->max_pps_num))) {
        hi_log_err("pic_parameter_set_id = %d out of range", hevc_ctx->curr_slice.pic_parameter_set_id);
        return HEVC_DEC_ERR;
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_dec_slice_sgment_header(hevc_ctx *hevc_ctx, hi_u32 is_dec_slice)
{
    hi_s32 rap_pic_flag, idr_pic_flag;
    hi_s32 num_cus, max_parts, slice_address;
    hi_u32 req_bits_outer = 0;
    const hi_u32 req_bits_inner = 0;
    hi_u32 icu_address = 0, inner_address = 0, bits_for_long_term_pic_in_sps = 0;
    hi_u32 i = 0, j = 0, is_sao_enabled = 0, is_dbf_enabled = 0;
    hi_s32 num_rps_curr_temp_list = 0, offset = 0;
    hi_s32 poc_ls_blt = 0, lt_idx_sps = 0;
    hi_s32 prev_delta_msb = 0, delta_poc_msb_cycle_lt = 0;
    hi_u32 max_poc_lsb = 0, poc_lsb = 0, poc_msb = 0;
    hi_u32 pre_poc_lsb = 0, pre_poc_msb = 0;
    hi_s32 poc_lt_curr = 0;
    hi_u32 max_collocate_ref_ldx = 0, max_num_entry_point_offsets = 0;
    hi_u32 num_bits = 0;
    hi_u32 ue;
    hi_s32 ret = 0;
    hi_s32 bits_left = 0;
    hevc_seq_param_set    *sps = HI_NULL;
    hevc_pic_param_set    *pps = HI_NULL;
    hevc_short_term_rpset *rps = HI_NULL;

    pos();

    hevc_ctx->curr_slice.slice_type = HEVC_ERR_SLICE;

    hevc_ctx->curr_slice.first_slice_segment_in_pic_flag = hevc_u_v(hevc_ctx->bs_p, 1,
                                                                    "first_slice_segment_in_pic_flag");

    rap_pic_flag = hevc_get_rap_pic_flag(hevc_ctx);
    idr_pic_flag = hevc_get_ldr_pic_flag(hevc_ctx);

    if (rap_pic_flag) {
        hevc_ctx->curr_slice.no_output_of_prior_pics_flag = hevc_u_v(hevc_ctx->bs_p, 1, "no_output_of_prior_pics_flag");
    }

    hevc_ctx->curr_slice.pic_parameter_set_id = hevc_ue_v(hevc_ctx->bs_p, "slice_pic_parameter_set_id");
    if (hevc_dec_slice_sgment_header_check_pps_id(hevc_ctx) != HEVC_DEC_NORMAL) {
        return HEVC_DEC_ERR;
    }

    if (hevc_vps_sps_pps_check(hevc_ctx) != HEVC_DEC_NORMAL) {
        hevc_ctx->curr_slice.poc = (hevc_ctx->total_slice_num > 0) ? hevc_ctx->last_slice_poc : 0;
        hevc_ctx->curr_slice.new_pic_type = hevc_is_new_pic(hevc_ctx);
        hi_log_dbg("hevc_vps_sps_pps_check != HEVC_DEC_NORMAL\n");
        return HEVC_DEC_ERR;
    }

    pps = &hevc_ctx->pps[hevc_ctx->curr_slice.pic_parameter_set_id];
    sps = &hevc_ctx->sps[pps->seq_parameter_set_id];

    if ((pps->dependent_slice_segments_enabled_flag) && (!hevc_ctx->curr_slice.first_slice_segment_in_pic_flag)) {
        hevc_ctx->curr_slice.dependent_slice_segment_flag = hevc_u_v(hevc_ctx->bs_p, 1, "dependent_slice_segment_flag");
    } else {
        hevc_ctx->curr_slice.dependent_slice_segment_flag = HEVC_FALSE;
    }

    if ((sps->max_cu_width * sps->max_cu_height) == 0) {
        hi_log_dbg("max_cu_width = 0 or max_cu_height =0");
        return HEVC_DEC_ERR;
    }

    num_cus = ((sps->pic_width_in_luma_samples + sps->max_cu_width - 1) / sps->max_cu_width) *
               ((sps->pic_height_in_luma_samples + sps->max_cu_height - 1) / sps->max_cu_height);
    max_parts = (1 << (sps->max_cu_depth << 1));

    while (num_cus > (1 << (hi_u32)req_bits_outer)) {
        req_bits_outer++;
    }

    if (!hevc_ctx->curr_slice.first_slice_segment_in_pic_flag) {
        hevc_ctx->curr_slice.slice_segment_address = hevc_u_v(hevc_ctx->bs_p, (hi_s32)(req_bits_inner + req_bits_outer),
                                                              "slice_segment_address");
        if (hevc_ctx->curr_slice.slice_segment_address < 0 || hevc_ctx->curr_slice.slice_segment_address >=
            (hi_s32)((sps->ctb_num_width) * (sps->ctb_num_height))) {
            hi_log_dbg("slice_segment_address(%d) out of range", hevc_ctx->curr_slice.slice_segment_address);
            return HEVC_DEC_ERR;
        }
        icu_address   = (hi_u32)hevc_ctx->curr_slice.slice_segment_address >> req_bits_inner;
        inner_address = hevc_ctx->curr_slice.slice_segment_address - (icu_address << req_bits_inner);
    }
    slice_address = max_parts * icu_address + inner_address;
    hevc_ctx->curr_slice.dependent_slice_curstart_cuaddr = slice_address;
    hevc_ctx->curr_slice.dependent_slice_curend_cuaddr   = num_cus * max_parts;
    hevc_ctx->curr_slice.poc = hevc_ctx->last_slice_poc;

    hevc_ctx->curr_slice.slice_type = HEVC_I_SLICE;
    if (!hevc_ctx->curr_slice.dependent_slice_segment_flag) {
        if ((hevc_ctx->bs_p->total_pos + (hi_s32)pps->num_extra_slice_header_bits) > (hevc_ctx->bs_p->bs_len * 0x8)) {
            hi_log_dbg("%s, %d, num_extra_slice_header_bits out of range, \
                total_pos = %d, num_extra_slice_header_bits = %d, bs_len = %d\n",
                __func__, __LINE__, hevc_ctx->bs_p->total_pos,
                pps->num_extra_slice_header_bits, hevc_ctx->bs_p->bs_len * 0x8);
            return HEVC_DEC_ERR;
        }

        for (i = 0; i < pps->num_extra_slice_header_bits; i++) {
            ue = hevc_u_v(hevc_ctx->bs_p, 1, "slice_reserved_flag");
        }
        HI_UNUSED(ue);

        hevc_ctx->curr_slice.slice_type = hevc_ue_v(hevc_ctx->bs_p, "slice_type");
        if (hevc_ctx->curr_slice.slice_type < 0 || hevc_ctx->curr_slice.slice_type > 0x2) {
            hi_log_dbg("slice_type = %d out of range(0,2]", hevc_ctx->curr_slice.slice_type);
            return HEVC_DEC_ERR;
        }

        hevc_ctx->curr_slice.pic_output_flag = (!pps->output_flag_present_flag) ? HEVC_TRUE :
            hevc_u_v(hevc_ctx->bs_p, 1, "pic_output_flag");

        if (!idr_pic_flag) {
            hevc_ctx->curr_slice.pic_order_cnt_lsb = hevc_u_v(hevc_ctx->bs_p, sps->bits_for_poc, "pic_order_cnt_lsb");
            /* calc poc of current slice */
            poc_lsb = hevc_ctx->curr_slice.pic_order_cnt_lsb;
            max_poc_lsb = 1 << sps->max_pic_order_cnt_lsb;
            pre_poc_lsb = hevc_ctx->prev_slice_poc % max_poc_lsb;
            pre_poc_msb = hevc_ctx->prev_slice_poc - pre_poc_lsb;

            if ((poc_lsb < pre_poc_lsb) && ((pre_poc_lsb - poc_lsb) >= (max_poc_lsb / 0x2))) {
                poc_msb = pre_poc_msb + max_poc_lsb;
            } else if ((poc_lsb > pre_poc_lsb) && ((poc_lsb - pre_poc_lsb) > (max_poc_lsb / 0x2))) {
                poc_msb = pre_poc_msb - max_poc_lsb;
            } else {
                poc_msb = pre_poc_msb;
            }

            if (hevc_ctx->curr_slice.nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_W_LP ||
                hevc_ctx->curr_slice.nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_W_RADL ||
                hevc_ctx->curr_slice.nal_unit_type == NAL_UNIT_CODED_SLICE_BLA_N_LP) {
                poc_msb = 0;
            }
            hevc_ctx->curr_slice.poc = poc_lsb + poc_msb;
            hevc_ctx->last_slice_poc = hevc_ctx->curr_slice.poc;

            if ((hevc_ctx->curr_slice.nuh_temporal_id == 0) && (hevc_is_refefence_nalu(hevc_ctx) &&
                (hevc_ctx->curr_slice.nal_unit_type != NAL_UNIT_CODED_SLICE_RASL_R) &&
                (hevc_ctx->curr_slice.nal_unit_type != NAL_UNIT_CODED_SLICE_RADL_R))) {
                hevc_ctx->curr_slice.prev_poc = hevc_ctx->curr_slice.poc;
                hevc_ctx->prev_slice_poc = hevc_ctx->curr_slice.poc;
            }

            hevc_ctx->curr_slice.short_term_ref_pic_set_sps_flag = hevc_u_v(hevc_ctx->bs_p, 1,
                                                                            "short_term_ref_pic_set_sps_flag");

            if (!hevc_ctx->curr_slice.short_term_ref_pic_set_sps_flag) {
                ret = hevc_dec_short_term_ref_pic_set(hevc_ctx, sps, &(hevc_ctx->curr_slice.short_term_ref_pic_set),
                                                      sps->num_short_term_ref_pic_sets);
                if (ret != HEVC_DEC_NORMAL) {
                    hi_log_dbg("SH hevc_dec_short_term_ref_pic_set error.");
                    return HEVC_DEC_ERR;
                }
            } else {
                while ((1u << num_bits) < sps->num_short_term_ref_pic_sets) {
                    num_bits++;
                }
                if (num_bits > 0) {
                    hevc_ctx->curr_slice.short_term_ref_pic_set_idx = hevc_u_v(hevc_ctx->bs_p, num_bits,
                                                                               "short_term_ref_pic_set_idx");
                } else {
                    hevc_ctx->curr_slice.short_term_ref_pic_set_idx = 0;
                }
                if (hevc_ctx->curr_slice.short_term_ref_pic_set_idx < 0 ||
                    hevc_ctx->curr_slice.short_term_ref_pic_set_idx > (hi_s32)sps->num_short_term_ref_pic_sets - 1) {
                    hi_log_dbg("short_term_ref_pic_set_idx out of range");
                    hi_warn_print_u32(hevc_ctx->curr_slice.short_term_ref_pic_set_idx);
                    return HEVC_DEC_ERR;
                }
                hevc_ctx->curr_slice.short_term_ref_pic_set =
                    sps->short_term_ref_pic_set[hevc_ctx->curr_slice.short_term_ref_pic_set_idx];
            }
            rps = &(hevc_ctx->curr_slice.short_term_ref_pic_set);

            if (sps->long_term_ref_pics_present_flag) {
                offset = rps->num_negative_pics + rps->num_positive_pics;
                if (sps->num_long_term_ref_pic_sps > 0) {
                    hevc_ctx->curr_slice.num_long_term_sps = hevc_ue_v(hevc_ctx->bs_p, "num_long_term_sps");
                    if (hevc_ctx->curr_slice.num_long_term_sps > sps->num_long_term_ref_pic_sps) {
                        hi_log_dbg("num_long_term_sps=%u out of range", hevc_ctx->curr_slice.num_long_term_sps);
                        return HEVC_DEC_ERR;
                    }
                }
                bits_for_long_term_pic_in_sps = 0;
                while (sps->num_long_term_ref_pic_sps > ((hi_u32)(1 << bits_for_long_term_pic_in_sps))) {
                    bits_for_long_term_pic_in_sps++;
                }
                hevc_ctx->curr_slice.num_long_term_pics = hevc_ue_v(hevc_ctx->bs_p, "num_long_term_pics");
                rps->num_of_longterm_pics = hevc_ctx->curr_slice.num_long_term_sps +
                    hevc_ctx->curr_slice.num_long_term_pics;

                if ((rps->num_negative_pics + rps->num_positive_pics + rps->num_of_longterm_pics) >
                    HEVC_MAX_NUM_REF_PICS) {
                    hi_log_dbg("SH ERROR, rps->num_negative_pics=%u\n",  rps->num_negative_pics);
                    return HEVC_DEC_ERR;
                }

                for (i = 0, j = offset + rps->num_of_longterm_pics - 1; i < rps->num_of_longterm_pics; j--, i++) {
                    if (i < hevc_ctx->curr_slice.num_long_term_sps) {
                        lt_idx_sps = 0;
                        if (bits_for_long_term_pic_in_sps) {
                            hevc_ctx->curr_slice.lt_idx_sps[i] =
                                hevc_u_v(hevc_ctx->bs_p, bits_for_long_term_pic_in_sps, "lt_idx_sps");
                            lt_idx_sps = hevc_ctx->curr_slice.lt_idx_sps[i];
                            if (lt_idx_sps < 0 || lt_idx_sps > (hi_s32)sps->num_long_term_ref_pic_sps - 1) {
                                hi_log_dbg("lt_idx_sps=%u out of range\n", lt_idx_sps);
                                return HEVC_DEC_ERR;
                            }
                        }

                        poc_ls_blt = sps->lt_ref_pic_poc_lsb_sps[lt_idx_sps];
                        rps->used_flag[j] = sps->used_by_curr_pic_lt_sps_flag[lt_idx_sps];
                    } else {
                        hevc_ctx->curr_slice.poc_lsb_lt[i] = hevc_u_v(hevc_ctx->bs_p, sps->bits_for_poc, "poc_lsb_lt");
                        poc_ls_blt = hevc_ctx->curr_slice.poc_lsb_lt[i];
                        hevc_ctx->curr_slice.used_by_curr_pic_lt_flag[i] = hevc_u_v(hevc_ctx->bs_p, 1,
                                                                                    "used_by_curr_pic_lt_flag");
                        rps->used_flag[j] = hevc_ctx->curr_slice.used_by_curr_pic_lt_flag[i];
                    }

                    hevc_ctx->curr_slice.poc_ls_blt[i] = poc_ls_blt;
                    hevc_ctx->curr_slice.delta_poc_msb_present_flag[i] = hevc_u_v(hevc_ctx->bs_p, 1,
                                                                                  "delta_poc_msb_present_flag");
                    if (hevc_ctx->curr_slice.delta_poc_msb_present_flag[i]) {
                        hevc_ctx->curr_slice.delta_poc_msb_cycle_lt[i] = hevc_ue_v(hevc_ctx->bs_p,
                                                                                   "delta_poc_msb_cycle_lt");
                        if (i == 0 || i == hevc_ctx->curr_slice.num_long_term_sps) {
                            delta_poc_msb_cycle_lt = hevc_ctx->curr_slice.delta_poc_msb_cycle_lt[i];
                        } else {
                            delta_poc_msb_cycle_lt = hevc_ctx->curr_slice.delta_poc_msb_cycle_lt[i] + prev_delta_msb;
                        }
                        hevc_ctx->curr_slice.delta_poc_msb_cycle_t[j] = delta_poc_msb_cycle_lt;

                        hevc_ctx->curr_slice.check_lt_msb[j] = 1;
                    } else {
                        delta_poc_msb_cycle_lt = (i == 0 || i == hevc_ctx->curr_slice.num_long_term_sps) ? 0 :
                            prev_delta_msb;
                        hevc_ctx->curr_slice.check_lt_msb[j] = 0;
                    }
                    prev_delta_msb = delta_poc_msb_cycle_lt;
                }

                for (i = 0, j = offset + rps->num_of_longterm_pics - 1; i < rps->num_of_longterm_pics; j--, i++) {
                    if (hevc_ctx->curr_slice.delta_poc_msb_present_flag[i]) {
                        poc_lt_curr = hevc_ctx->curr_slice.poc -
                            hevc_ctx->curr_slice.delta_poc_msb_cycle_t[j] * max_poc_lsb -
                            poc_lsb + hevc_ctx->curr_slice.poc_ls_blt[i];
                        rps->poc[j] = poc_lt_curr;
                        rps->delta_poc[j] = poc_lt_curr - hevc_ctx->curr_slice.poc;
                    } else {
                        rps->poc[j] = hevc_ctx->curr_slice.poc_ls_blt[i];
                        rps->delta_poc[j] = hevc_ctx->curr_slice.poc_ls_blt[i] - hevc_ctx->curr_slice.poc;
                    }
                }

                rps->num_of_pics = offset + rps->num_of_longterm_pics;
                if (rps->num_of_pics > HEVC_MAX_NUM_REF_PICS) {
                    hi_log_dbg("rps->num_of_pics：%u > HEVC_MAX_NUM_REF_PICS:%u\n",
                        rps->num_of_pics, HEVC_MAX_NUM_REF_PICS);
                    return HEVC_DEC_ERR;
                }
            }

            hevc_ctx->curr_slice.slice_temporal_mvp_enable_flag = (sps->sps_temporal_mvp_enable_flag) ?
                hevc_u_v(hevc_ctx->bs_p, 1, "slice_temporal_mvp_enable_flag") : HEVC_FALSE;
        } else {
            hevc_ctx->curr_slice.poc = 0;
            hevc_ctx->last_slice_poc = hevc_ctx->curr_slice.poc;
            if (0 == hevc_ctx->curr_slice.nuh_temporal_id) {
                hevc_ctx->curr_slice.prev_poc = 0;
                hevc_ctx->prev_slice_poc = 0;
            }
        }

        if (sps->sample_adaptive_offset_enabled_flag) {
            hevc_ctx->curr_slice.slice_sao_luma_flag = hevc_u_v(hevc_ctx->bs_p, 1, "slice_sao_luma_flag");
            hevc_ctx->curr_slice.slice_sao_chroma_flag = hevc_u_v(hevc_ctx->bs_p, 1, "slice_sao_chroma_flag");
        }

        if (idr_pic_flag) {
            hevc_ctx->curr_slice.slice_temporal_mvp_enable_flag = HEVC_FALSE;
        }

        if (hevc_ctx->curr_slice.slice_type != HEVC_I_SLICE) {
            hevc_ctx->curr_slice.num_ref_idx_active_override_flag = hevc_u_v(hevc_ctx->bs_p, 1,
                                                                             "num_ref_idx_active_override_flag");
            if (hevc_ctx->curr_slice.num_ref_idx_active_override_flag) {
                hevc_ctx->curr_slice.num_ref_idx_l0_active = hevc_ue_v(hevc_ctx->bs_p,
                                                                       "num_ref_idx_l0_active_minus1") + 1;
                if (hevc_ctx->curr_slice.num_ref_idx_l0_active > HEVC_MAX_NUM_REF_PICS) {
                    hi_log_dbg("num_ref_idx_l0_active:%u  out of range", hevc_ctx->curr_slice.num_ref_idx_l0_active);
                    return HEVC_DEC_ERR;
                }

                hevc_ctx->curr_slice.num_ref_idx[0] = hevc_ctx->curr_slice.num_ref_idx_l0_active;

                if (hevc_ctx->curr_slice.slice_type == HEVC_B_SLICE) {
                    hevc_ctx->curr_slice.num_ref_idx_l1_active = hevc_ue_v(hevc_ctx->bs_p,
                                                                           "num_ref_idx_l1_active_minus1") + 1;
                    if (hevc_ctx->curr_slice.num_ref_idx_l1_active > HEVC_MAX_NUM_REF_PICS) {
                        hi_log_dbg("num_ref_idx_l1_active:%u out of range",
                            hevc_ctx->curr_slice.num_ref_idx_l1_active);
                        return HEVC_DEC_ERR;
                    }
                    hevc_ctx->curr_slice.num_ref_idx[1] = hevc_ctx->curr_slice.num_ref_idx_l1_active;
                } else {
                    hevc_ctx->curr_slice.num_ref_idx_l1_active = 0;
                    hevc_ctx->curr_slice.num_ref_idx[1] = 0;
                }
            } else {
                hevc_ctx->curr_slice.num_ref_idx[0] = pps->num_ref_idx_l0_default_active;
                hevc_ctx->curr_slice.num_ref_idx[1] = (hevc_ctx->curr_slice.slice_type != HEVC_B_SLICE) ? 0 :
                    pps->num_ref_idx_l1_default_active;
            }
        }

        if (hevc_ctx->curr_slice.slice_type == HEVC_I_SLICE) {
            num_rps_curr_temp_list = 0;
        } else {
            if (rps == HI_NULL) {
                hi_log_dbg("rps is null.");
                return HEVC_DEC_ERR;
            }

            if (rps->num_of_pics > HEVC_MAX_NUM_REF_PICS) {
                hi_log_dbg("rps->num_of_pics:%u out of range.", rps->num_of_pics);
                return HEVC_DEC_ERR;
            }

            for (i = 0; i < rps->num_of_pics; i++) {
                if (rps->used_flag[i]) {
                    num_rps_curr_temp_list++;
                }
            }
        }

        if (hevc_ctx->curr_slice.slice_type != HEVC_I_SLICE) {
            if (pps->lists_modification_present_flag && num_rps_curr_temp_list > 1) {
                ret = hevc_dec_ref_pic_lists_modification(hevc_ctx, &hevc_ctx->curr_slice,
                    &(hevc_ctx->curr_slice.ref_pic_lists_modification), num_rps_curr_temp_list);
                if (ret != HEVC_DEC_NORMAL) {
                    hi_log_dbg("SH hevc_dec_ref_pic_lists_modification error.");
                    return HEVC_DEC_ERR;
                }
            }
        }
        if (hevc_ctx->curr_slice.slice_type == HEVC_B_SLICE) {
            hevc_ctx->curr_slice.mvd_l1_zero_flag = hevc_u_v(hevc_ctx->bs_p, 1, "mvd_l1_zero_flag");
        }
        if ((hevc_ctx->curr_slice.slice_type != HEVC_I_SLICE) && (pps->cabac_init_present_flag)) {
            hevc_ctx->curr_slice.cabac_init_flag = hevc_u_v(hevc_ctx->bs_p, 1, "cabac_init_flag");
        }
        if (hevc_ctx->curr_slice.slice_temporal_mvp_enable_flag) {
            hevc_ctx->curr_slice.collocated_from_l0_flag = (hevc_ctx->curr_slice.slice_type != HEVC_B_SLICE) ? 1 :
                hevc_u_v(hevc_ctx->bs_p, 1, "collocated_from_l0_flag");
            if ((hevc_ctx->curr_slice.slice_type != HEVC_I_SLICE) &&
                ((hevc_ctx->curr_slice.collocated_from_l0_flag && (hevc_ctx->curr_slice.num_ref_idx[0] > 1)) ||
                (!hevc_ctx->curr_slice.collocated_from_l0_flag && (hevc_ctx->curr_slice.num_ref_idx[1] > 1)))) {
                hevc_ctx->curr_slice.collocated_ref_idx = hevc_ue_v(hevc_ctx->bs_p, "collocated_ref_idx");
                max_collocate_ref_ldx = (hevc_ctx->curr_slice.collocated_from_l0_flag) ?
                    (hevc_ctx->curr_slice.num_ref_idx_l0_active - 1) : (hevc_ctx->curr_slice.num_ref_idx_l1_active - 1);
                if (hevc_ctx->curr_slice.collocated_ref_idx < 0 ||
                    hevc_ctx->curr_slice.collocated_ref_idx > (hi_s32)max_collocate_ref_ldx) {
                    hi_log_dbg("collocated_from_l0_flag, collocated_ref_idx out of range.");
                    return HEVC_DEC_ERR;
                }
            }
        }
        if ((pps->weighted_pred_flag && (hevc_ctx->curr_slice.slice_type == HEVC_P_SLICE)) ||
            (pps->weighted_bipred_flag && (hevc_ctx->curr_slice.slice_type == HEVC_B_SLICE))) {
            ret = hevc_dec_pred_weight_table(hevc_ctx);
            if (ret != HEVC_DEC_NORMAL) {
                hi_log_dbg("SH hevc_dec_pred_weight_table error.");
                return HEVC_DEC_ERR;
            }
        }

        if (hevc_ctx->curr_slice.slice_type != HEVC_I_SLICE) {
            hevc_ctx->curr_slice.max_num_merge_cand = MRG_MAX_NUM_CANDS -
            hevc_ue_v(hevc_ctx->bs_p, "five_minus_max_num_merge_cand");
            if (hevc_ctx->curr_slice.max_num_merge_cand < 1 || hevc_ctx->curr_slice.max_num_merge_cand > 0x5) {
                hi_log_dbg("SH max_num_merge_cand out of range(1,5).");
                return HEVC_DEC_ERR;
            }
        }
        hevc_ctx->curr_slice.slice_qp_delta = hevc_se_v(hevc_ctx->bs_p, "slice_qp_delta");
        hevc_ctx->curr_slice.slice_qp = hevc_ctx->curr_slice.slice_qp_delta + pps->pic_init_qp;
        if (hevc_ctx->curr_slice.slice_qp < (hi_s32)(-sps->qp_bd_offset_y) ||
            hevc_ctx->curr_slice.slice_qp > 51) { /* range is 0 to 51 */
            hi_log_dbg("SH slice_qp  out of range ");
            return HEVC_DEC_ERR;
        }

        if (pps->pic_slice_chroma_qp_offsets_present_flag) {
            hevc_ctx->curr_slice.slice_cb_qp_offset = hevc_se_v(hevc_ctx->bs_p, "slice_cb_qp_offset");

            if (hevc_ctx->curr_slice.slice_cb_qp_offset < -12 || /* range is -12 to 12 */
                hevc_ctx->curr_slice.slice_cb_qp_offset > 12) { /* range is -12 to 12 */
                hi_log_dbg("SH slice_cb_qp_offset out of range[-12,12].");
                return HEVC_DEC_ERR;
            }

            if ((hevc_ctx->curr_slice.slice_cb_qp_offset + pps->pic_cb_qp_offset) < -12 || /* range is -12 to 12 */
                (hevc_ctx->curr_slice.slice_cb_qp_offset + pps->pic_cb_qp_offset) > 12) { /* range is -12 to 12 */
                hi_log_dbg("SH slice_cb_qp_offset+pic_cb_qp_offset out of range[-12,12].");
                return HEVC_DEC_ERR;
            }

            hevc_ctx->curr_slice.slice_cr_qp_offset = hevc_se_v(hevc_ctx->bs_p, "slice_cr_qp_offset");

            if (hevc_ctx->curr_slice.slice_cr_qp_offset < -12 || /* range is -12 to 12 */
                hevc_ctx->curr_slice.slice_cr_qp_offset > 12) { /* range is -12 to 12 */
                hi_log_dbg("SH slice_cr_qp_offset  out of range[-12,12].");
                return HEVC_DEC_ERR;
            }

            if ((hevc_ctx->curr_slice.slice_cr_qp_offset + pps->pic_cr_qp_offset) < -12 || /* range is -12 to 12 */
                (hevc_ctx->curr_slice.slice_cr_qp_offset + pps->pic_cr_qp_offset) > 12) { /* range is -12 to 12 */
                hi_log_dbg("SH slice_cr_qp_offset+pps->pic_cr_qp_offset  out of range[-12,12].");
                return HEVC_DEC_ERR;
            }
        }

        if (pps->deblocking_filter_control_present_flag) {
            hevc_ctx->curr_slice.deblocking_filter_override_flag = (pps->deblocking_filter_override_enabled_flag) ?
                hevc_u_v(hevc_ctx->bs_p, 1, "deblocking_filter_override_flag") : 0;
            if (hevc_ctx->curr_slice.deblocking_filter_override_flag) {
                hevc_ctx->curr_slice.slice_disable_deblocking_filter_flag = hevc_u_v(hevc_ctx->bs_p, 1,
                    "slice_disable_deblocking_filter_flag");
                if (!hevc_ctx->curr_slice.slice_disable_deblocking_filter_flag) {
                    hevc_ctx->curr_slice.slice_beta_offset_div2 = hevc_se_v(hevc_ctx->bs_p, "slice_beta_offset_div2");
                    if (hevc_ctx->curr_slice.slice_beta_offset_div2 < -6 || /* range is -6 to 6 */
                        hevc_ctx->curr_slice.slice_beta_offset_div2 > 6) { /* range is -6 to 6 */
                        hi_log_dbg("SH slice_beta_offset_div2:%d out of range(-6,6).",
                            hevc_ctx->curr_slice.slice_beta_offset_div2);
                        hevc_ctx->curr_slice.slice_beta_offset_div2 = pps->pps_beta_offset_div2;
                    }
                    hevc_ctx->curr_slice.slice_tc_offset_div2 = hevc_se_v(hevc_ctx->bs_p, "slice_tc_offset_div2");
                    if (hevc_ctx->curr_slice.slice_tc_offset_div2  < -6 || /* range is -6 to 6 */
                        hevc_ctx->curr_slice.slice_tc_offset_div2  > 6) { /* range is -6 to 6 */
                        hi_log_dbg("SH slice_tc_offset_div2 out of range(-6,6).");
                        hevc_ctx->curr_slice.slice_tc_offset_div2 = pps->pps_tc_offset_div2;
                    }
                }
            } else {
                hevc_ctx->curr_slice.slice_disable_deblocking_filter_flag = pps->pic_disable_deblocking_filter_flag;
                hevc_ctx->curr_slice.slice_beta_offset_div2 = pps->pps_beta_offset_div2;
                hevc_ctx->curr_slice.slice_tc_offset_div2   = pps->pps_tc_offset_div2;
            }
        }

        is_sao_enabled = (!sps->sample_adaptive_offset_enabled_flag) ? (HEVC_FALSE) :
            (hevc_ctx->curr_slice.slice_sao_luma_flag || hevc_ctx->curr_slice.slice_sao_chroma_flag);
        is_dbf_enabled = !(hevc_ctx->curr_slice.slice_disable_deblocking_filter_flag);
        if (pps->loop_filter_across_slices_enabled_flag && (is_sao_enabled || is_dbf_enabled)) {
            hevc_ctx->curr_slice.slice_loop_filter_across_slices_enabled_flag = hevc_u_v(hevc_ctx->bs_p, 1,
                "slice_loop_filter_across_slices_enabled_flag");
        } else {
            hevc_ctx->curr_slice.slice_loop_filter_across_slices_enabled_flag =
                pps->loop_filter_across_slices_enabled_flag;
        }
    }

    if (pps->tiles_enabled_flag || pps->entropy_coding_sync_enabled_flag) {
        hevc_ctx->curr_slice.num_entry_point_offsets = hevc_ue_v(hevc_ctx->bs_p, "num_entry_point_offsets");

        if (pps->tiles_enabled_flag == 0 && pps->entropy_coding_sync_enabled_flag == 1) {
            max_num_entry_point_offsets = sps->ctb_num_height - 1;
        } else if (pps->tiles_enabled_flag == 1 && pps->entropy_coding_sync_enabled_flag == 0) {
            max_num_entry_point_offsets = pps->num_tile_columns * pps->num_tile_rows - 1;
        } else {
            max_num_entry_point_offsets = pps->num_tile_columns * sps->ctb_num_height - 1;
        }

        if (hevc_ctx->curr_slice.num_entry_point_offsets > min(max_num_entry_point_offsets, 255)) {
            hi_log_dbg("curr_slice.num_entry_point_offsets  out of range.");
            return HEVC_DEC_ERR;
        }

        if (hevc_ctx->curr_slice.num_entry_point_offsets > 0) {
            hevc_ctx->curr_slice.offset_len = 1 + hevc_ue_v(hevc_ctx->bs_p, "offset_len_minus1");
            if (hevc_ctx->curr_slice.offset_len < 1 || hevc_ctx->curr_slice.offset_len > 32) { /* range is 1 to 32 */
                hi_log_dbg("curr_slice.offset_len(%d) out of range[1,32].");
                return HEVC_DEC_ERR;
            }
        }

        for (i = 0; i < hevc_ctx->curr_slice.num_entry_point_offsets; i++) {
            hevc_ctx->curr_slice.entry_point_offset[i] = hevc_u_v(hevc_ctx->bs_p, hevc_ctx->curr_slice.offset_len,
                                                                  "entry_point_offset_minus1");
        }
    } else {
        hevc_ctx->curr_slice.num_entry_point_offsets = 0;
    }

    if (pps->slice_segment_header_extension_present_flag) {
        hevc_ctx->curr_slice.slice_segment_header_extension_length = hevc_ue_v(hevc_ctx->bs_p,
            "slice_segment_header_extension_length");
        if (hevc_ctx->curr_slice.slice_segment_header_extension_length > 256) { /* range is 0 to 256 */
            hi_log_dbg("slice_segment_header_extension_length out of range [0,256]");
            return HEVC_DEC_ERR;
        }

        bits_left = bs_resid_bits(hevc_ctx->bs_p);
        if (bits_left < (hi_s32)hevc_ctx->curr_slice.slice_segment_header_extension_length) {
            hi_log_dbg("bits_left(%d)<slice_segment_header_extension_length(%d)\n", bits_left,
                hevc_ctx->curr_slice.slice_segment_header_extension_length);
            return HEVC_DEC_ERR;
        }

        for (i = 0; i < hevc_ctx->curr_slice.slice_segment_header_extension_length; i++) {
            hevc_ctx->curr_slice.slice_segment_header_extension_data_byte = hevc_u_v(hevc_ctx->bs_p, 0x8,
                "slice_segment_header_extension_data_byte");
        }
    }

    if (hevc_ctx->curr_slice.dependent_slice_curstart_cuaddr == 0) {
        if (hevc_ctx->new_sequence) {
            if (rap_pic_flag) {
                if (is_dec_slice) {
                    hevc_ctx->new_sequence = HEVC_FALSE;
                }
                hevc_ctx->no_rasl_out_put_flag = HEVC_TRUE;
            }
        } else {
            if (rap_pic_flag) {
                hevc_ctx->no_rasl_out_put_flag = HEVC_FALSE;
            }
        }
    }

    hevc_ctx->no_out_put_of_prior_pics_flag = HEVC_FALSE;
    if (hevc_ctx->no_rasl_out_put_flag && hevc_ctx->curr_slice.poc != 0 && rap_pic_flag) {
        hevc_ctx->no_out_put_of_prior_pics_flag = (hevc_ctx->curr_slice.nal_unit_type == NAL_UNIT_CODED_SLICE_CRA) ?
            HEVC_TRUE : HEVC_FALSE;
    }

    hevc_ctx->curr_slice.new_pic_type = hevc_is_new_pic(hevc_ctx);

    return HEVC_DEC_NORMAL;
}

static hi_void hevc_sort_ref(hevc_ctx *hevc_ctx)
{
    hi_s32 x, y;
    hi_s32 min;

    for (x = 0; x < hevc_ctx->hevc_ref_num; x++) {
        min = hevc_ctx->hevc_ref_poc[x];
        for (y = x; y < hevc_ctx->hevc_ref_num; y++) {
            if (min > hevc_ctx->hevc_ref_poc[y]) {
                min = hevc_ctx->hevc_ref_poc[y];
                hevc_ctx->hevc_ref_poc[y] = hevc_ctx->hevc_ref_poc[x];
                hevc_ctx->hevc_ref_poc[x] = min;
            }
        }
    }
    for (x = 0; x < hevc_ctx->hevc_ref_num; x++) {
        hi_log_info(" %d, ", hevc_ctx->hevc_ref_poc[x]);
    }

    hi_log_info("\n");

    return;
}

static hi_s32 hevc_count_ref(hevc_ctx *hevc_ctx)
{
    char *str_type __attribute__((unused)) = HI_NULL;

    hevc_ctx->hevc_frm_type = hevc_ctx->curr_pic.pic_type;
    if (hevc_ctx->hevc_frm_type == HEVC_IDR_FRAME) {
        str_type = "IDR";
    } else if (hevc_ctx->hevc_frm_type == HEVC_BLA_FRAME) {
        str_type = "BLA";
    } else if (hevc_ctx->hevc_frm_type == HEVC_CRA_FRAME) {
        str_type = "CRA";
    } else if (hevc_ctx->hevc_frm_type == HEVC_I_FRAME) {
        str_type = "I";
    } else if (hevc_ctx->hevc_frm_type == HEVC_P_FRAME) {
        str_type = "P";
    } else if (hevc_ctx->hevc_frm_type == HEVC_B_FRAME) {
        str_type = "B";
    } else {
        str_type = "N";
    }

    hi_log_info("Frm:%u\n", hevc_ctx->hevc_frm_cnt);
    hi_log_info("Poc:%u\n", hevc_ctx->hevc_frm_poc);
    hi_log_info("Ref:%u", hevc_ctx->hevc_ref_num);

    hevc_ctx->hevc_frm_cnt++;
    if (hevc_ctx->hevc_ref_num > 0) {
        hevc_sort_ref(hevc_ctx);
    }

    hevc_ctx->dmx_hevc_frm_cnt = hevc_ctx->hevc_frm_cnt;
    hevc_ctx->dmx_hevc_frm_poc = hevc_ctx->hevc_frm_poc;
    hevc_ctx->dmx_hevc_frm_type = hevc_ctx->hevc_frm_type;
    hevc_ctx->dmx_hevc_ref_num = hevc_ctx->hevc_ref_num;
    if (memcpy_s(hevc_ctx->dmx_hevc_ref_poc, sizeof(hevc_ctx->dmx_hevc_ref_poc),
        hevc_ctx->hevc_ref_poc, 16 * 4) != EOK) { /* 16 * 4 */
        hi_log_err("call memcpy_s is failed\n");
        return HEVC_DEC_ERR;
    }

    return HEVC_DEC_NORMAL;
}

static hi_s32 hevc_dec_slice_proc_new_pic(hevc_ctx *hevc_ctx)
{
    hi_s32 ret;

    if (hevc_ctx->curr_pic.state == HEVC_PIC_DECODING) {
        hevc_count_ref(hevc_ctx);
        ret = hevc_store_pic_in_dpb(hevc_ctx);
        if (ret != HEVC_DEC_NORMAL) {
            hi_log_info("hevc_store_pic_in_dpb failed!\n");
            return HEVC_DEC_ERR;
        }
    }

    ret = hevc_ref_pic_process(hevc_ctx);
    if (ret != HEVC_DEC_NORMAL) {
        hi_log_info("hevc_ref_pic_process failed!\n");
    }

    ret = hevc_init_pic(hevc_ctx);
    if (ret != HEVC_DEC_NORMAL) {
        hi_log_info("hevc_init_pic err!\n");
        return HEVC_DEC_ERR;
    }

    ret = hevc_write_pic_msg(hevc_ctx);
    if (ret != HEVC_DEC_NORMAL) {
        hi_log_info("hevc_write_pic_msg failed!\n");
        return HEVC_DEC_ERR;
    }

    /* robustness: drop all the slice that if this frame does'nt go with init_pic to alloc resource */
    if (hevc_ctx->curr_pic.state == HEVC_PIC_EMPTY) {
        hi_log_info("cur pic not init yet, discard this slice!\n");
        return HEVC_DEC_ERR;
    }

    return ret;
}

static hi_s32 hevc_dec_slice(hevc_ctx *hevc_ctx)
{
    pos();

    if (hevc_ctx == HI_NULL) {
        hi_log_err("hevc_ctx is HI_NULL.\n");
        return HEVC_DEC_ERR;
    }

    if (memset_s(&hevc_ctx->curr_slice, sizeof(hevc_slice_segment_header), 0x0, sizeof(hevc_slice_segment_header))) {
        hi_log_err("memset_s failed.\n");
    }
    hevc_ctx->curr_slice.nal_unit_type = hevc_ctx->curr_nal->nal_unit_type;

    if (hevc_dec_slice_sgment_header(hevc_ctx, 1) != HEVC_DEC_NORMAL) {
        hi_log_info("hevc_dec_slice_sgment_header failed");
        return HEVC_DEC_ERR;
    }

    if (hevc_is_flush_unit(hevc_ctx->curr_slice.nal_unit_type) ||
        hevc_ctx->no_out_put_of_prior_pics_flag == HEVC_TRUE) {
        hevc_init_dec_buffers(hevc_ctx);
    }

    hi_log_info("new_pic_type:%u slice_num:%u\n", hevc_ctx->curr_slice.new_pic_type, hevc_ctx->total_slice_num);

    if (hevc_ctx->curr_slice.new_pic_type == IS_NEW_PIC) {
        if (hevc_dec_slice_proc_new_pic(hevc_ctx) != HEVC_DEC_NORMAL) {
            return HEVC_DEC_ERR;
        }
    }

    hevc_pic_type_statistic(hevc_ctx);

    if (!hevc_ctx->curr_slice.dependent_slice_segment_flag) {
        /* one slice one RefList */
        /* do the poc management in storePicInDpb */
        /* flag the dpb.fs_negative_ref  dpb.fs_positive_ref */
        if (hevc_dec_list(hevc_ctx) != HEVC_DEC_NORMAL) {
            return HEVC_DEC_ERR;
        }
    }

    if (hevc_write_slice_msg(hevc_ctx) != HEVC_DEC_NORMAL) {
        hi_log_info("hevc_write_slice_msg err.");
        return HEVC_DEC_ERR;
    }

    hevc_ctx->prev_pic_parameter_set_id = hevc_ctx->curr_slice.pic_parameter_set_id;
    hevc_ctx->prev_poc = hevc_ctx->curr_slice.poc;
    hevc_ctx->allow_start_dec = 1;

    return HEVC_DEC_NORMAL;
}

hi_s32 hevc_init(hevc_ctx *hevc_ctx_p)
{
    if (memset_s(hevc_ctx_p, sizeof(hevc_ctx), 0x0, sizeof(hevc_ctx))) {
        hi_log_err("memset_s failed.\n");
    }
    hevc_ctx_p->max_vps_num   = HEVC_MAX_VIDEO_PARAM_SET_ID;
    hevc_ctx_p->max_sps_num   = HEVC_MAX_SEQ_PARAM_SET_ID;
    hevc_ctx_p->max_pps_num   = HEVC_MAX_PIC_PARAM_SET_ID;

    if (memset_s(hevc_ctx_p->vps, (hevc_ctx_p->max_vps_num) * sizeof(hevc_video_param_set),
        0x0, (hevc_ctx_p->max_vps_num) * sizeof(hevc_video_param_set))) {
        hi_log_err("memset_s failed.\n");
    }
    if (memset_s(hevc_ctx_p->sps, (hevc_ctx_p->max_sps_num) * sizeof(hevc_seq_param_set),
        0x0, (hevc_ctx_p->max_sps_num) * sizeof(hevc_seq_param_set))) {
        hi_log_err("memset_s failed.\n");
    }
    if (memset_s(hevc_ctx_p->pps, (hevc_ctx_p->max_pps_num) * sizeof(hevc_pic_param_set),
        0x0, (hevc_ctx_p->max_pps_num) * sizeof(hevc_pic_param_set))) {
        hi_log_err("memset_s failed.\n");
    }
    hevc_ctx_p->curr_vps.video_parameter_set_id = hevc_ctx_p->max_vps_num ;
    hevc_ctx_p->curr_pps.pic_parameter_set_id   = hevc_ctx_p->max_sps_num ;
    hevc_ctx_p->curr_sps.seq_parameter_set_id   = hevc_ctx_p->max_pps_num ;

    hevc_init_scaling_order_table(hevc_ctx_p);

    hevc_ctx_p->last_display_poc = -HEVC_MAX_INT;

    hevc_init_dec_para(hevc_ctx_p);

    hevc_ctx_p->prev_pic_parameter_set_id = hevc_ctx_p->max_pps_num;
    hevc_ctx_p->prev_poc = 9999; /* 9999 poc */

    /* Report error frame for invalid data in frame 1 */
    hevc_ctx_p->hevc_frm_poc = 0;
    hevc_ctx_p->hevc_frm_type = HEVC_ERR_FRAME;
    hevc_ctx_p->hevc_ref_num = 0;

    hevc_ctx_p->dmx_hevc_frm_poc = 0;
    hevc_ctx_p->dmx_hevc_frm_type = HEVC_ERR_FRAME;
    hevc_ctx_p->dmx_hevc_ref_num = 0;

    return HEVC_DEC_NORMAL;
}

hi_s32 hevc_get_first_nal(hi_s32 inst_idx)
{
    fidx_ctx *ctx = &g_fidx_iis[inst_idx];
    sc_info *this_sc = &ctx->this_sc;

    ctx->first_nal_offset = this_sc->global_offset;

    if (ctx->last_sei_offset < ctx->first_nal_offset && ctx->last_sei_offset >= 0) {
        ctx->first_nal_offset = ctx->last_sei_offset;
    }
    if (ctx->last_pps_offset < ctx->first_nal_offset && ctx->last_pps_offset >= 0) {
        ctx->first_nal_offset = ctx->last_pps_offset;
    }
    if (ctx->last_sps_offset < ctx->first_nal_offset && ctx->last_sps_offset >= 0) {
        ctx->first_nal_offset = ctx->last_sps_offset;
    }
    if (ctx->last_vps_offset < ctx->first_nal_offset && ctx->last_vps_offset >= 0) {
        ctx->first_nal_offset = ctx->last_vps_offset;
    }
    ctx->last_sei_offset = -1;
    ctx->last_pps_offset = -1;
    ctx->last_sps_offset = -1;
    ctx->last_vps_offset = -1;
    return 0;
}

hi_s32 hevc_make_frame(hi_s32 inst_idx)
{
    fidx_ctx *ctx = &g_fidx_iis[inst_idx];
    frame_pos *frame_pos = &ctx->new_frame_pos;
    hevc_ctx *hevc_ctx = ctx->hevc_ctx;

    frame_pos->frame_size = ctx->first_nal_offset - ctx->new_frm_offset;
    frame_pos->global_offset = ctx->new_frm_offset;
    ctx->new_frm_offset = ctx->first_nal_offset;
    if (frame_pos->frame_size <= 0) {
        return FIDX_ERR;
    }
    hi_log_info("hevc_make_frame frame_size = %d glboffset %llx nfmoffset %llx\n", frame_pos->frame_size,
        frame_pos->global_offset, ctx->new_frm_offset);

    frame_pos->cur_poc = hevc_ctx->dmx_hevc_frm_poc;
    frame_pos->ref_num = hevc_ctx->dmx_hevc_ref_num;
    if (memcpy_s(frame_pos->ref_poc, sizeof(frame_pos->ref_poc),
        hevc_ctx->dmx_hevc_ref_poc, 16 * 4) != EOK) { /* 16*4 */
        hi_log_err("call memcpy_s is failed\n");
        return HEVC_DEC_ERR;
    }

    if (hevc_ctx->dmx_hevc_frm_type == HEVC_IDR_FRAME) {
        frame_pos->frame_type = FIDX_FRAME_TYPE_IDR;
    } else if (hevc_ctx->dmx_hevc_frm_type == HEVC_BLA_FRAME) {
        frame_pos->frame_type = FIDX_FRAME_TYPE_BLA;
    } else if (hevc_ctx->dmx_hevc_frm_type == HEVC_CRA_FRAME) {
        frame_pos->frame_type = FIDX_FRAME_TYPE_CRA;
    } else if (hevc_ctx->dmx_hevc_frm_type == HEVC_I_FRAME) {
        frame_pos->frame_type = FIDX_FRAME_TYPE_I;
    } else if (hevc_ctx->dmx_hevc_frm_type == HEVC_P_FRAME) {
        frame_pos->frame_type = FIDX_FRAME_TYPE_P;
    } else if (hevc_ctx->dmx_hevc_frm_type == HEVC_B_FRAME) {
        frame_pos->frame_type = FIDX_FRAME_TYPE_B;
    } else {
        frame_pos->frame_type = FIDX_FRAME_TYPE_UNKNOWN;
    }

    if (frame_pos->frame_type == FIDX_FRAME_TYPE_IDR || frame_pos->frame_type == FIDX_FRAME_TYPE_BLA ||
        frame_pos->frame_type == FIDX_FRAME_TYPE_CRA || frame_pos->frame_type == FIDX_FRAME_TYPE_I) {
        frame_pos->pts = ctx->next_pts;
        ctx->next_pts = ctx->pts;
        ctx->pts  = 0xffffffff;
    } else {
        frame_pos->pts = ctx->next_pts;
        ctx->next_pts = ctx->pts;
        ctx->pts = 0xffffffff;
    }

    return FIDX_OK;
}

#define SLICE_CASE \
    case NAL_UNIT_CODED_SLICE_TRAIL_R: \
    case NAL_UNIT_CODED_SLICE_TRAIL_N: \
    case NAL_UNIT_CODED_SLICE_TLA_R: \
    case NAL_UNIT_CODED_SLICE_TSA_N: \
    case NAL_UNIT_CODED_SLICE_STSA_R: \
    case NAL_UNIT_CODED_SLICE_STSA_N: \
    case NAL_UNIT_CODED_SLICE_BLA_W_LP:\
    case NAL_UNIT_CODED_SLICE_BLA_W_RADL: \
    case NAL_UNIT_CODED_SLICE_BLA_N_LP: \
    case NAL_UNIT_CODED_SLICE_IDR_W_RADL: \
    case NAL_UNIT_CODED_SLICE_IDR_N_LP: \
    case NAL_UNIT_CODED_SLICE_CRA: \
    case NAL_UNIT_CODED_SLICE_RADL_N: \
    case NAL_UNIT_CODED_SLICE_RADL_R: \
    case NAL_UNIT_CODED_SLICE_RASL_N: \
    case NAL_UNIT_CODED_SLICE_RASL_R: \

static hi_s32 process_sc_hevc_proc_nal_unit_type(hi_s32 inst_idx)
{
    hi_s32 ret = FIDX_OK;
    fidx_ctx *ctx = &g_fidx_iis[inst_idx];
    sc_info  *this_sc = &ctx->this_sc;
    hevc_ctx *hevc_ctx = ctx->hevc_ctx;

    switch (hevc_ctx->curr_nal->nal_unit_type) {
        case NAL_UNIT_VPS:
            ret = hevc_dec_vps(hevc_ctx);
            ctx->last_vps_offset = this_sc->global_offset;
            break;
        case NAL_UNIT_SPS:
            ret = hevc_dec_sps(hevc_ctx);
            ctx->last_sps_offset = this_sc->global_offset;
            break;
        case NAL_UNIT_PPS:
            ret = hevc_dec_pps(hevc_ctx);
            ctx->last_pps_offset = this_sc->global_offset;
            break;
        case NAL_UNIT_PREFIX_SEI:
            ctx->last_sei_offset = this_sc->global_offset;
            break;
        case NAL_UNIT_SUFFIX_SEI:
            break;
        SLICE_CASE
            ret = hevc_dec_slice(hevc_ctx);

            if (hevc_ctx->curr_slice.new_pic_type == IS_NEW_PIC) {
                hevc_get_first_nal(inst_idx);

                if (hevc_make_frame(inst_idx) == FIDX_OK) {
                    out_put_frame();
                }
            }
            break;
        default:
            hi_log_dbg("nal = Non\n");
            break;
    }

    return ret;
}

hi_s32 process_sc_hevc(hi_s32 inst_idx)
{
    fidx_ctx *ctx = &g_fidx_iis[inst_idx];
    sc_info *this_sc = &ctx->this_sc;
    hevc_ctx *hevc_ctx = ctx->hevc_ctx;
    hi_bool bs_wrong;

    bs_wrong = is_sc_wrong();

    fidx_assert_ret(ctx->this_scvalid != 0, "ThisSC is not valid\n");
    fidx_assert_ret(!bs_wrong, "not enough data for ThisSC\n");

    pos();
    hi_log_info("this_scdata_len:%d\n", ctx->this_scdata_len);
    if (ctx->new_frm_offset < 0) {
        ctx->new_frm_offset = this_sc->global_offset;
    }

    bs_init(hevc_ctx->bs_p, (hi_u8 *)(&ctx->hevc_scdata[0]), ctx->this_scdata_len);

    hevc_ctx->curr_nal->forbidden_zero_bit = bs_get(hevc_ctx->bs_p, 1);
    hevc_ctx->curr_nal->nal_unit_type = bs_get(hevc_ctx->bs_p, 0x6);
    hevc_ctx->curr_nal->nuh_reserved_zero_6bits = bs_get(hevc_ctx->bs_p, 0x6);
    hevc_ctx->curr_nal->nuh_temporal_id = bs_get(hevc_ctx->bs_p, 0x3);
    if (hevc_ctx->curr_nal->nuh_temporal_id == 0x0) {
        hi_log_err("nuh_temporal_id_plus1 shall not be equal to 0");
        return HEVC_DEC_ERR;
    }
    hevc_ctx->curr_nal->nuh_temporal_id -= 1;

    hi_log_info("nal_unit_type:%u\n", hevc_ctx->curr_nal->nal_unit_type);

    if ((hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_EOS) || (hevc_ctx->curr_nal->nal_unit_type == NAL_UNIT_EOB)) {
        hevc_ctx->new_sequence = HEVC_TRUE;
    }

    hi_log_info("entry proc hevc globaloffset:%u", this_sc->global_offset);

    return process_sc_hevc_proc_nal_unit_type(inst_idx);
}

/*
 * feed start code to FIDX.
 * there are 2 method to feed necessary information to FIDX:
 * 1. feed stream directly. Call FIDX_MakeFrameIndex()
 * 2. feed start code. In this method, the start code must be scanned outside,
 *    This call this function to create index.
 */
hi_s32 fidx_feed_start_code(hi_s32 inst_idx, const findex_scd *sc)
{
    fidx_ctx *ctx = HI_NULL;
    frame_pos pes_frame = {0};

    ctx = &g_fidx_iis[inst_idx];

    /* Get SC info */
    ctx->this_sc.sc_id = sc->start_code;
    ctx->this_sc.global_offset = sc->global_offset;
    ctx->this_sc.offset_inpacket = 0;
    ctx->this_sc.packet_count = 0;

    /* fill SC data */
    if (ctx->video_standard == VIDSTD_HEVC) {
        /* adapt this_sc_data for general checking. */
        ctx->this_scdata[0] = sc->start_code;
        if (memcpy_s(ctx->this_scdata + 1, sizeof(ctx->this_scdata) - 1, sc->extra_scdata + 0x4, 0x8) != EOK) {
            hi_log_err("call memcpy_s is failed\n");
            return HEVC_DEC_ERR;
        }

        ctx->hevc_scdata = sc->extra_scdata + 0x3; /* +3 for skip 00 00 01 */
        ctx->this_scdata_len = sc->extra_real_scdata_size - 0x3;
    } else {
        ctx->this_scdata[0] = sc->start_code;
        if (memcpy_s(ctx->this_scdata + 1, sizeof(ctx->this_scdata) - 1, sc->data_after_sc, 0x8) != EOK) {
            hi_log_err("call memcpy_s is failed\n");
            return HEVC_DEC_ERR;
        }
        ctx->this_scdata_len = 1 + 0x8;
    }

    ctx->this_scvalid = 1;

    /* if this SC is a PES SC, output it here simply, otherwise process it according to the video standard */
    if (is_pes_sc(sc->start_code, ctx->video_standard) == 1) {
        /* the PTS after PES SC is valid, record it */
        ctx->pts  = sc->pts_us;

        /* report the PES position */
        pes_frame.frame_type = FIDX_FRAME_TYPE_PESH;
        pes_frame.global_offset = ctx->this_sc.global_offset;
        pes_frame.offset_inpacket = ctx->this_sc.offset_inpacket;
        pes_frame.packet_count = ctx->this_sc.packet_count;
        pes_frame.pts = sc->pts_us;

        if (g_out_put_frame_position != HI_NULL) {
            (hi_void)g_out_put_frame_position(ctx->param, &pes_frame);
        }

        /* record the PTS of first frame from record beginning */
        if (unlikely(ctx->next_pts == 0)) {
            ctx->next_pts = sc->pts_us;
        }

        ctx->this_scvalid = 0;
        ctx->this_scdata_len = 0;
    } else {
        ananyse_sc();
        ctx->this_scvalid = 0;
        ctx->this_scdata_len = 0;
    }

    return HI_SUCCESS;
}

hi_s32 fidx_feed_hevc_index_pts(hi_s32 inst_idx, const findex_scd *sc)
{
    fidx_ctx *ctx = HI_NULL;
    frame_pos pes_frame = {0};

    ctx = &g_fidx_iis[inst_idx];
    if (ctx == HI_NULL) {
        hi_log_err("this_sc IS NULL\n");
    }

    /* Get SC info */
    ctx->this_sc.sc_id = sc->start_code;
    ctx->this_sc.global_offset = sc->global_offset;
    ctx->this_sc.offset_inpacket = 0;
    ctx->this_sc.packet_count = 0;

    /* if this SC is a PES SC, output it here simply, otherwise process it according to the video standard */
    if (is_pes_sc(sc->start_code, ctx->video_standard) == 1) {
        /* the PTS after PES SC is valid, record it */
        ctx->pts = sc->pts_us;

        /* report the PES position */
        pes_frame.frame_type = FIDX_FRAME_TYPE_PESH;
        pes_frame.global_offset = ctx->this_sc.global_offset;
        pes_frame.offset_inpacket = ctx->this_sc.offset_inpacket;
        pes_frame.packet_count = ctx->this_sc.packet_count;
        pes_frame.pts = sc->pts_us;

        if (g_out_put_frame_position != HI_NULL) {
            (hi_void)g_out_put_frame_position(ctx->param, &pes_frame);
        }

        /* record the PTS of first frame from record beginning */
        if (unlikely(ctx->next_pts == 0)) {
            ctx->next_pts = sc->pts_us;
        }

        ctx->this_scvalid = 0;
        ctx->this_scdata_len = 0;
        return HI_SUCCESS;
    }

    return HI_FAILURE;
}

