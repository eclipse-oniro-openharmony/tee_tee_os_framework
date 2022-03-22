/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2020. All rights reserved.
 * Description: ssm export function defines
 * Author: hisilicon
 * Create: 2020-01-10
 */

#ifndef __HI_TEE_SSM_H__
#define __HI_TEE_SSM_H__

#include "hi_type_dev.h"

#define SSM_MAX_HDCP_TYPE_NUM         3
#define SSM_MAX_RESOLUTION_LVL_NUM    5

typedef enum {
    LOGIC_MOD_ID_DEMUX,
    LOGIC_MOD_ID_TSCIPHER,
    LOGIC_MOD_ID_CIPHER,
    LOGIC_MOD_ID_VMCU,
    LOGIC_MOD_ID_VDH,
    LOGIC_MOD_ID_AUD_DSP,
    LOGIC_MOD_ID_VENC,
    LOGIC_MOD_ID_VPSS,
    LOGIC_MOD_ID_VDP,
    LOGIC_MOD_ID_GPU,
    LOGIC_MOD_ID_HWC,
    LOGIC_MOD_ID_JPEG_DEC,
    LOGIC_MOD_ID_JPEG_ENC,
    LOGIC_MOD_ID_NPU,
    LOGIC_MOD_ID_VI,
    LOGIC_MOD_ID_MAX,
} hi_tee_logic_mod_id;

typedef struct {
    hi_handle module_handle;
} hi_tee_ssm_module_info;

typedef enum {
    HI_TEE_SSM_INTENT_WATCH = 0,
    HI_TEE_SSM_INTENT_RECORD,
    HI_TEE_SSM_INTENT_EXPORT,
    HI_TEE_SSM_INTENT_MAX
} hi_tee_ssm_intent;

typedef enum {
    BUFFER_ID_INVALID,

    BUFFER_ID_INTERNAL_BUF_DMX,

    BUFFER_ID_INTERNAL_BUF_TSCIPHER,

    BUFFER_ID_CIPHER_CENC_BUF,
    BUFFER_ID_INTERNAL_BUF_MCIPHER,

    BUFFER_ID_VID_RAWLIST_MCU_ONLY,
    BUFFER_ID_VID_SEGLIST_MCU_ONLY,
    BUFFER_ID_VID_STDCTX_MCU_ONLY,
    BUFFER_ID_VID_PICMSG_MCU_ONLY,
    BUFFER_ID_VID_SLICEMSG_MCU_ONLY,
    BUFFER_ID_VID_METADATA_MCU_ONLY,
    BUFFER_ID_VID_SCDRAW_BUF,
    BUFFER_ID_VID_SCDSEG_BUF,
    BUFFER_ID_VID_SCDMSG,
    BUFFER_ID_VID_VDHPMV_BUF,
    BUFFER_ID_VID_VDHEXT_BUF_VID_ONLY,
    BUFFER_ID_VID_FRMBIN_VDH_ONLY,
    BUFFER_ID_INTERNAL_BUF_VDEC,

    BUFFER_ID_INTERNAL_BUF_AUDDSP,

    BUFFER_ID_INTERNAL_BUF_VENC,

    BUFFER_ID_INTERNAL_BUF_VPSS,

    BUFFER_ID_VDP_SD_WRITEBACK_ONLY,
    BUFFER_ID_INTERNAL_BUF_VDP,

    BUFFER_ID_INTERNAL_BUF_GPU,

    BUFFER_ID_INTERNAL_BUF_HWC,

    BUFFER_ID_INTERNAL_BUF_JPEG_DEC,

    BUFFER_ID_INTERNAL_BUF_JPEG_ENC,

    BUFFER_ID_INTERNAL_BUF_NPU,

    /* external buffer */
    BUFFER_ID_DMX_VID_ES_BUF,

    BUFFER_ID_DMX_AUD_ES_BUF,

    BUFFER_ID_MCIPHER_VID_ES_BUF,

    BUFFER_ID_MCIPHER_AUD_ES_BUF,

    BUFFER_ID_MCIPHER_TS_BUF,

    BUFFER_ID_PVR_RECORD_TS_BUF,

    BUFFER_ID_PVR_PLAYBACK_TS_BUF,

    BUFFER_ID_VID_FRM_BUF,

    BUFFER_ID_VPSS_OUTPUT_BUF,

    BUFFER_ID_VDP_OUTPUT_BUF,

    BUFFER_ID_SECURE_INFOR_BUF,

    BUFFER_ID_VIDEO_CAPTURE_ENCODE_OUTPUT_BUF,

    BUFFER_ID_TRANSCODE_ENCODE_OUTPUT_BUF,
    BUFFER_ID_MIRA_ENCODE_OUTPUT_BUF,

    BUFFER_ID_GRAPHIC_OUPUT_BUF,

    BUFFER_ID_NPU_OUTPUT_BUF,

    BUFFER_ID_MAX  // 0-43
} hi_tee_ssm_buffer_id;

typedef struct {
    hi_handle               session_handle;
    hi_tee_ssm_buffer_id    buf_id;
    hi_u64                  buf_smmu_handle;
    hi_u32                  buf_len;
    hi_handle               module_handle;
} hi_tee_ssm_buffer_attach_info;

typedef struct {
    hi_handle                session_handle; /* session handle, only valid for session buffer */
    hi_handle                module_handle;  /* module handle which module the buffer will be attached to */
    hi_tee_ssm_buffer_id     buf_id;         /* buffer ID */
    hi_u64                   buf_handle;       /* buffer Addr */
    hi_u64                   buf_size;       /* buffer size */
} hi_tee_ssm_buffer_check_info;

typedef struct {
    hi_u32 table[SSM_MAX_HDCP_TYPE_NUM][SSM_MAX_RESOLUTION_LVL_NUM];
} hi_tee_ssm_policy_table;

hi_s32 hi_tee_ssm_create(hi_tee_ssm_intent intent, hi_handle *addr);

hi_s32 hi_tee_ssm_add_resource(hi_handle session_handle, hi_tee_ssm_module_info *mod_info_addr);

hi_s32 hi_tee_ssm_attach_buffer(hi_tee_ssm_buffer_attach_info *attach_info_addr, hi_u64 *sec_info_addr);

hi_s32 hi_tee_ssm_destroy(hi_handle target_handle);

hi_s32 hi_tee_ssm_get_intent(hi_handle session_handle, hi_tee_ssm_intent *intent_addr);

hi_s32 hi_tee_ssm_set_uuid(hi_handle session_handle);

hi_s32 hi_tee_ssm_check_uuid(hi_handle session_handle);

hi_s32 hi_tee_ssm_check_buf(const hi_tee_ssm_buffer_check_info *check_info);

hi_s32 hi_tee_ssm_set_iommu_tag(hi_tee_logic_mod_id module_id);

hi_s32 hi_tee_ssm_send_policy_table(hi_handle session_handle, hi_tee_ssm_policy_table *policy_tbl);

hi_s32 hi_tee_ssm_init();

hi_s32 hi_tee_ssm_set_reg(hi_u32 addr, hi_u32 val);

#endif

