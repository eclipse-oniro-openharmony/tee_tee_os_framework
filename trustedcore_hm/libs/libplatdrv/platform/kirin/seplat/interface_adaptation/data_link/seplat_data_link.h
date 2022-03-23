/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Provides abstract seplat data_link interfaces for bl2.
 * Create: 2021/1/15
 */
#ifndef SEPLAT_DATA_LINK_H
#define SEPLAT_DATA_LINK_H

#include "types.h"

#define SEPLAT_CHIP_SOFT_RESET 0
#define SEPLAT_CHIP_HARD_RESET 1

enum seplat_data_link_common_errno {
    SEPLAT_ERRCODE_DATA_LINK_DATA_TRANS_OUTLEN_NULL    = 0x01,
    SEPLAT_ERRCODE_DATA_LINK_GET_FDT_HANDLE_ERR        = 0x02,
    SEPLAT_ERRCODE_DATA_LINK_FIND_NODE_ERR             = 0x03,
    SEPLAT_ERRCODE_DATA_LINK_FIND_INTERFACE_ERR        = 0x04,
    SEPLAT_ERRCODE_DATA_LINK_FIND_RST_GPIO_ERR         = 0x05,
    SEPLAT_ERRCODE_DL_INTERFACE_NOT_INITED             = 0x06,
    SEPLAT_ERRCODE_DL_INTERFACE_IO_TYPE_ERR            = 0x07,
    SEPLAT_ERRCODE_DL_INTERFACE_IO_NUM_ERR             = 0x08,
};

int32_t seplat_data_link_init(void);

int32_t seplat_data_trans(uint8_t *cmd, uint32_t cmd_len, uint8_t *rsp, uint32_t rsp_len, uint32_t *data_len);

int32_t seplat_chip_reset(uint32_t type);

int32_t seplat_power_save(uint8_t vote_id, uint8_t mode);

#endif