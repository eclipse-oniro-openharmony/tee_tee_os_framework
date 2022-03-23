/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: scmi api header file
* Author: pengcong
* Create: 2019/12/25
*/
#ifndef SCMI_API_H
#define SCMI_API_H

#include <hsm_dev_id.h>

#define SCMI_CHANNEL_FREE           0x0
#define SCMI_CHANNEL_OCCUPIED       0x1
#define SCMI_CHANNEL_3              0x3
#define MAILBOX_CHANNEL_MAX         4
#define MAILBOX_CHANNEL_SIZE        128
#define MAILBOX_MAX_LEN_IN_BYTE     512

#define SHIFT_LEN_32                32
#define SCMI_MASK_NUM               0xFFFFFFFF
#define RANDOM_ADDR_OFFSET          0xF00000
#define HISS_RANDOM_ADDR            0x3D00000
#define HISS_RANDOM_MAP_SIZE        0xFFFF
#define HISS_RANDOM_CMD             0xBB060001
#define HISS_RANDOM_PARA_NUM        0x1
#define HISS_RANDOM_DATA_LEN        0x4
#define HISS_RANDOM_NUM_LEN         0x4

#define TA_ID_LEN_WORD_FOUR         4
#define HMAC_LEN_WORD_EIGHT         8
#define SCMI_PROCESS_SUCCESS        0x1000000

#define INT_SCMI0_HISS_NUMBLER      323
#define INT_SCMI0_HISS_NUMBLER_P1   627
#define HWI_DEF_SCMI_PRIORITY       0
#define INT_FUN_SCMI                0x0
#define ARRAY_INDEX0                0
#define ARRAY_INDEX1                1
#define ARRAY_INDEX2                2
#define ARRAY_INDEX3                3
#define ARRAY_INDEX4                4
#define TEE_DDR_ADDR_START          0x4400000
#define TEE_DDR_ADDR_END            0xA400000
#define TEE_RANDOM_MAX_LEN          (1024 *1024)
#define DEV_ID_MAX                  1

typedef struct Scmi_Command {
    uint32_t cmd;
    uint32_t ta_index;
    uint32_t ta_id[TA_ID_LEN_WORD_FOUR];
    uint32_t job_id;
    uint32_t addr_addr_l;
    uint32_t addr_addr_h;
    uint32_t ddr_data_len;
    uint32_t ddr_para_num;
    uint32_t param_len_0;
    uint32_t param_len_1;
    uint32_t param_len_2;
    uint32_t param_len_3;
    uint32_t param_len_4;
    uint32_t param_len_5;
    uint32_t param_len_6;
    uint32_t param_len_7;
    uint32_t cnt;
    uint32_t hmac[HMAC_LEN_WORD_EIGHT];
} SCMI_COMMAND;

typedef struct Scmi_Back_Data {
    uint32_t ta_index;
    uint32_t job_id;
    uint32_t mode;
    uint32_t job_state;
    uint32_t process_result;
    uint32_t verify_result;
    uint32_t reserved;
    uint32_t ddr_addr_l;
    uint32_t ddr_addr_h;
    uint32_t ddr_data_len;
    uint32_t ddr_para_num;
    uint32_t param_len_0;
    uint32_t param_len_1;
    uint32_t param_len_2;
    uint32_t param_len_3;
    uint32_t param_len_4;
    uint32_t param_len_5;
    uint32_t param_len_6;
    uint32_t param_len_7;
    uint32_t hmac[HMAC_LEN_WORD_EIGHT];
} SCMI_BACK_DATA;

uint32_t scmi_interrupt_init(void);

#endif
