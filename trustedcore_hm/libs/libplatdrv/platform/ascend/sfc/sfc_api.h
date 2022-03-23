/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: SFC nor flash driver api head file
* Author: huawei
* Create: 2020/3/25
*/

#ifndef SFC_API_H
#define SFC_API_H

#include <stdint.h>
#include <hsm_dev_id.h>

#define SFC_SUCCESS                     0x0
#define SFC_INPUT_PARAMS_ERR            0xEFEF0001U
#define SFC_INPUT_PARAMS_ERR1           0xEFEF0002U
#define SFC_INPUT_PARAMS_NOT_ALIGN      0xEFEF0003U
#define SFC_FAILED                      0xFFFFFFFFU

#define FLASH_DATA_BUF_MAPPED 0xDCBA6789U
#define FLASH_DATA_BUF_NOT_MAPPED 0xABCD1234U

extern uint64_t g_flash_buff[DEV_NUM_MAX];

uint32_t flash_read(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id);

uint32_t flash_write(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id);

uint32_t flash_erase(uint32_t offset, uint32_t length, uint32_t chip_id);

uint32_t get_flash_info(uint8_t *out_info, uint32_t len, uint32_t chip_id);

#endif
