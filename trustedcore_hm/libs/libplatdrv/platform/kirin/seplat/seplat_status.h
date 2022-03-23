/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Header file for seplat dts status.
 * Create: 2021/02/02
 */

#ifndef SEPLAT_STATUS_H
#define SEPLAT_STATUS_H
#include <types.h>

#define SEPLAT_DTS_ABSENCE           0x7B3F64C5
#define SEPLAT_DTS_EXIST             (~0x7B3F64C5)

uint32_t seplat_get_dts_status(void);

#endif /* SEPLAT_STATUS_H */
