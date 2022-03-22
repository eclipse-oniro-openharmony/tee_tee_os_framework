/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: sfc libs api file
* Author: huawei
* Create: 2020/11/2
*/

#ifndef SFC_LIB_API_H
#define SFC_LIB_API_H

#include <stdint.h>

#define SEC_LIB_RESULT_SUCCESS 0x0
#define SEC_LIB_RESULT_FAILED 0x5A5A5A5A

uint32_t lib_mdc_flash_read(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id);
uint32_t lib_mdc_flash_write(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id);
uint32_t lib_mdc_flash_erase(uint32_t offset, uint32_t length, uint32_t chip_id);

#endif
