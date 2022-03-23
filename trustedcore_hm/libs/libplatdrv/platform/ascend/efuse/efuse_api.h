/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: efuse api file
* Author: huawei
* Create: 2019/07/30
*/
#ifndef EFUSE_API_H
#define EFUSE_API_H

#define SUCCESS                                           0x0
#define FAIL                                              0x1

#define ERR_EFUSE_FLASH_POWER_INPUT_PARAM                 0xC3A55A01U
#define ERR_EFUSE_WRITE_INPUT_PARAM                       0xC3A55A02U
#define ERR_EFUSE_BLOCK_NUM_INPUT                         0xC3A55A03U
#define ERR_EFUSE_START_BIT_SIZE_INPUT_PARAM              0xC3A55A04U
#define ERR_EFUSE_BURN_INPUT_PARAM                        0xC3A55A05U
#define ERR_EFUSE_DONT_FIND_EFUSE_MAPPING                 0xC3A55A06U
#define ERR_EFUSE_CHECK_INPUT_PARAM                       0xC3A55A07U
#define ERR_EFUSE_WR_COMMON_ARRAY_SIZE_WRONG              0xC3A55A08U
#define ERR_EFUSE_DATA_CHECK_FAILED                       0xC3A55A09U
#define ERR_EFUSE_WRITE_FAILED                            0xC3A55A0AU
#define ERR_EFUSE_READ_CONFIG_VALUE_TIMEOUT               0xC3A55A0BU
#define ERR_EFUSE_READ_CONFIG_PARAM                       0xC3A55AABU
#define ERR_EFUSE_READ_OPERATION_ERROR                    0xC3A55ABBU
#define ERR_EFUSE_CHECK_BUFFER_DATA_FAILED                0xC3A55A0DU
#define ERR_EFUSE_DJTAG_CHECK_TIMEOUT                     0xC3A55A0EU

#define EFUSE_FLASH_POWER_ON                              0x1
#define EFUSE_FLASH_POWER_OFF                             0x0
#define BYTE_TO_BIT                                       8
#define EFUSE_BLOCK_NUM0                                  0x0
#define EFUSE_BLOCK_NUM1                                  0x1

#define EFUSE_NVCNT_START                                 288
#define EFUSE_NVCNT_LEN                                   32

/*
* function: write efuse data into efuse buffer
* @param[in]: efuse_block_num -- efuse block num that you want to write
* @param[in]: start_bit -- efuse start bit that you want to write
* @param[in]: dest_size -- efuse size(bit) that you want to write
* @param[in]: input -- efuse data info(bit) that you want to write
* @returnval: SUCCESS(0x0) means operation is OK, others value means operation failed
*/
uint32_t write_efuse_api(uint32_t efuse_block_num, uint32_t start_bit, uint32_t dest_size,
    uint8_t *input, uint32_t dev_id);

/*
* function: to burn efuse data
* @param[in]: efuse_block_num -- efuse block that you want to burn
* @returnval: SUCCESS(0x0) means operation is OK, others value means operation failed
*/
uint32_t burn_efuse_api(uint32_t efuse_block_num, uint32_t dev_id);

/*
* function: checking efuse data is excepted or not
* @param[in]: efuse_block_num -- efuse block that you want to check
* @param[in]: start_bit -- efuse start bit that you want to check
* @param[in]: dest_size -- efuse size(bit) that you want to check
* @param[in]: input -- using [input] info to check those efuse data that has flashed,
*                      and uint32_t is input info's basic unit
* @returnval: SUCCESS(0x0) means checking operation is OK, others value means failed
*/
uint32_t check_efuse_api(uint32_t efuse_block_num, uint32_t start_bit, uint32_t dest_size,
    uint8_t *input, uint32_t dev_id);

/*
* function: turn on or turn off efuse flash power
* @param[in]: onoff = 0x1 means turn on efuse flash power
*             onoff = 0x0 means turn off efuse flash power
* @returnval: SUCCESS(0x0) means operation is OK, others value means operation failed
*/
uint32_t control_efuse_flash_power_api(uint32_t onoff);

uint32_t efuse_check_ns_forbid(uint32_t dev_id);

#endif
