/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
* Description: internal function of efuse
* Author: pengcong
* Create: 2019/07/30
*/
#ifndef __EFUSE_INTERNAL_API_H__
#define __EFUSE_INTERNAL_API_H__

uint32_t itrustee_write_efuse(uint32_t efuse_block_num, uint32_t start_bit, uint32_t dest_size,
    uint8_t *input, uint32_t dev_id);
uint32_t itrustee_burn_efuse(uint32_t efuse_block_num, uint32_t dev_id);
uint32_t itrustee_efuse_check(uint32_t efuse_block_num, uint32_t start_bit, uint32_t dest_size,
    uint8_t *check_data, uint32_t dev_id);
uint32_t read_efuse(uint32_t word, uint32_t chain_choose, uint32_t *out_data, uint32_t dev_id);
uint32_t bisr_reset(uint32_t dev_id);

#endif
