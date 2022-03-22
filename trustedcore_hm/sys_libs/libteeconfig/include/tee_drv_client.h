/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: declare tee driver client api
 * Create: 2021-03-01
 */
#ifndef TEE_DRV_CLIENT_H
#define TEE_DRV_CLIENT_H
#include <stdint.h>

int64_t tee_drv_open(const char *drv_name, const void *param, uint32_t param_len);
int64_t tee_drv_ioctl(int64_t fd, uint32_t cmd_id, const void *param, uint32_t param_len);
int64_t tee_drv_close(int64_t fd);

#endif
