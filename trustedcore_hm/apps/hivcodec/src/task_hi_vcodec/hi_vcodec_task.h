/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: added for hm-teeos
 * Author: hanxuanwei
 * Create: 2018-05-21
 */

#ifndef HI_TASK_VDEC_H
#define HI_TASK_VDEC_H
#include "tee_internal_api.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"
#include <sre_syscalls_ext.h>
#include <stdint.h>
#include <sre_syscalls_id_ext.h>

#define HI_VCODEC_INVOKE_CODE_A 0x6728661c
#define HI_VCODEC_INVOKE_CODE_B 0x5b9c660c

#define CLIENT_CA_VDECODER    "/vendor/bin/hw/vendor.huawei.hardware.vdecoder@1.0-service"
#define VDECODER_UID          1000

#define MEDIADRMSERVER_NAME   "/system/bin/mediadrmserver"
#define MEDIA_UID             1013

#define MEDIASERVER_NAME      "/system/bin/mediaserver"

#define CLIENT_CA_MEDIACODEC  "/vendor/bin/hw/android.hardware.media.omx@1.0-service"
#define MEDIA_CODEC_UID       1046

#define ROOT_UID              0
#define NAL_HEAD_LEN          64
#define MAX_COPY_SIZE         320
#ifdef VCODEC_ENG_VERSION
#define SAMPLE_OMXVDEC_NAME     "/vendor/bin/sample_omxvdec"
#define SAMPLE_OMXVENC_NAME     "/vendor/bin/sample_omxvenc"
#endif
enum {
    HIVCODEC_CMD_ID_INIT = 1,
    HIVCODEC_CMD_ID_EXIT,
    HIVCODEC_CMD_ID_SUSPEND,
    HIVCODEC_CMD_ID_RESUME,
    HIVCODEC_CMD_ID_CONTROL,
    HIVCODEC_CMD_ID_RUN_PROCESS,
    HIVCODEC_CMD_ID_GET_IMAGE,
    HIVCODEC_CMD_ID_RELEASE_IMAGE,
    HIVCODEC_CMD_ID_CONFIG_INPUT_BUFFER,
#ifdef VCODEC_ENG_VERSION
    HIVCODEC_CMD_ID_READ_PROC,
    HIVCODEC_CMD_ID_WRITE_PROC,
#endif
    HIVCODEC_CMD_ID_MEM_CPY = 20,
    HIVCODEC_CMD_ID_CFG_MASTER,
#ifdef VCODEC_ENG_VERSION
    HIVCODEC_CMD_ID_MEM_CPY_PROC,
#endif
};

typedef struct {
    uint32_t hal_phyaddr;
    uint32_t share_phyaddr;
    uint32_t pmv_phyaddr;
    uint32_t scd_phyaddr;
    uint32_t ctx_phyaddr;
    uint32_t input_phyaddr;
} PHY_ADDR_INFO_S;

typedef struct {
    int32_t a;
    int32_t b;
} CHECK_VALUE_S;

typedef struct {
    int32_t chanID;
    uint32_t cmdID;
    CHECK_VALUE_S value;
} SEC_CONTROL_PARAM_S;

typedef struct {
    uint32_t smmu_err_rdaddr0;
    uint32_t smmu_err_rdaddr1;
    uint32_t smmu_err_wtaddr0;
    uint32_t smmu_err_wtaddr1;
    uint32_t err_addr_size;
    uint32_t smmu_page_base_addr0;
    uint32_t smmu_page_base_addr1;
    uint32_t smmu_common_base_addr;
} VENC_ADDR_INFO_S;

struct NalHead {
    uint32_t packetLen;  // 64 bytes align
    uint32_t invalidBytes;
    uint8_t type;
    uint8_t bottomField;
    uint8_t topField;
    uint8_t lastSlice;
    uint32_t channelId;
    uint32_t pts0;
    uint32_t pts1;
    uint32_t reserved[10];
};

#endif
