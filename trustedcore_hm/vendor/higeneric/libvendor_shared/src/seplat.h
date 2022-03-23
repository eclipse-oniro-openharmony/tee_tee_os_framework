/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Header file for seplat share interface.
 * Create: 2021/02/07
 */

#ifndef SEPLAT_H
#define SEPLAT_H

#include <stdint.h>

uint32_t seplat_get_dts_status(void);
uint32_t seplat_power_ctrl(uint32_t vote_id, uint32_t cmd, uint32_t op_type);

#endif /* SEPLAT_H */
