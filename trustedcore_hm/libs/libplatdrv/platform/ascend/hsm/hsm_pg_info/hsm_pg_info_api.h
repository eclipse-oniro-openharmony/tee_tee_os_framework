/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: hsm pg info get api head file
* Author: huawei
* Create: 2020/9/3
*/

#ifndef HSM_PG_INFO_API_H
#define HSM_PG_INFO_API_H

#include <stdint.h>

#define PG_INFO_DDR_ADDR 0x2D00000
#define PG_INFO_MAGIC 0x46494750
#define CHIP_OFFSET 0x8000000000U

#define RESERVED_SPACE1 20
#define RESERVED_SPACE2 19

#define CPU_BITMAP_IDX 0
#define AIC_BITMAP_IDX 2
#define DDR_BITMAP_IDX 5
#define HBM_BITMAP_IDX 6

#define CPU_TOTAL_NUM 16
#define DDR_TOTAL_NUM 2
#define HBM_TOTAL_NUM 8

#define CPU_PG_NUM 8
#define AICORE_PG_NUM 8
#define AIVECT_PG_NUM 7

#define IMAGE_TEE 0x00000000
#define IMAGE_LPM3  0x00000001
#define IMAGE_KERNEL 0x00000100
#define IMAGE_DTS 0x00000101
#define IMAGE_INITRD 0x00000200

#define SUBKEY_ID_NUM_MASK  0x1F
#define ROOT_PUBKEY_LEN 1024
#define RIM_CRL_REQ_SIZE 544

#define IMG_VER_MAGIC 0x5a5aa5a5

#define MAX_AICORE_PG_NUM 30
#define MAX_CORE_BITMAP_NUM 8

#define READ_PG_INFO_LEN 8
#define READ_PG_RSP_LEN 8
#define OUT_DATA_FULL_LEN 8
#define BIT_WIDTH_BYTE 8
#define TEE_PG_INFO_ADDR 0x2D00000

typedef struct {
    uint32_t flag;
    uint32_t NvCnt;
} img_ver_tail;

typedef enum {
    PG_MODULE_TYPE_CPU,
    PG_MODULE_TYPE_AIC,
    PG_MODULE_TYPE_AIV,
    PG_MODULE_TYPE_HBM,
    PG_MODULE_TYPE_MAX = PG_MODULE_TYPE_HBM,
    PG_MODULE_TYPE_INVALID,
} module_type;

typedef enum {
    PG_DATA_TYPE_FREQ,
    PG_DATA_TYPE_TOTAL_NUM,
    PG_DATA_TYPE_CORE_MAP,
    PG_DATA_TYPE_MAX = PG_DATA_TYPE_CORE_MAP,
    PG_DATA_TYPE_INVALID,
} data_type;

typedef struct {
    module_type module;
    data_type data;
} pg_cmd_data;

typedef struct COMMON_PG_INFO_ {
    uint32_t valid; // 0:full good,1:partial good
    uint32_t total_num; // physical core total num
    uint32_t bitmap_index; // buf idx
    uint32_t freq; // (1 Mhz) core working frequency
} COMMON_PG_INFO;

// struct size:256 Byte
typedef struct PG_INFO_MNG_ {
    uint32_t magic; // 0x50474946 PGIF
    uint32_t length; // struct size
    uint32_t version; // 0x100 v1.0
    uint32_t boardId; // reserved,default:0
    uint32_t chipNum; // toal chip number on the SMP system, AMP:1
    COMMON_PG_INFO cpu_info;
    COMMON_PG_INFO aic_info;
    COMMON_PG_INFO aiv_info;
    COMMON_PG_INFO hbm_info; // totalNum:8:8 dha -connect- 4 hbm device
    uint8_t bitMap[MAX_CORE_BITMAP_NUM]; // 1:good,0:bad
    uint32_t end[RESERVED_SPACE1];
    uint32_t reserved[RESERVED_SPACE2];
    uint64_t checkSum; // from magic to end
} PG_INFO_MNG;

extern uint32_t g_dev_id_max;

TEE_Result syscall_tee_read_pg_info(uint32_t dev_id, uint32_t module, uint32_t data_type, uint64_t *out_data);

#endif
