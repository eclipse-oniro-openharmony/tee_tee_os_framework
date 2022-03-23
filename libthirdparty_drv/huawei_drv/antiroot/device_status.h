/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: device root status
 * Author: h00470634 hepengfei7@huawei.com
 * Create: 2020-02-19
 */
#ifndef PLATDRV_DEVICE_STATUS_H
#define PLATDRV_DEVICE_STATUS_H
#include <stdint.h>

#define DEVICE_IS_ROOTED 1
#define DEVICE_NOT_ROOTED 0

int32_t is_device_rooted(void);

#endif /* ROOT_DEVICE_STATUS_H */
