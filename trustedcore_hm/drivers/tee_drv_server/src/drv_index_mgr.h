/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: declare driver index function
 * Create: 2021-07-19
 */
#ifndef TEE_DRV_SERVER_SRC_DRV_INDEX_MGR_H
#define TEE_DRV_SERVER_SRC_DRV_INDEX_MGR_H
#include <stdint.h>

#define DRV_INDEX_MAX 1024
int32_t alloc_drv_index(void);
void clear_drv_index(int32_t drv_index);

#endif
