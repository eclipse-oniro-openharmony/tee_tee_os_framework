/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: driver module manage api
 * Create: 2020-09-28
 */
#ifndef DRV_MOD_CALL_H
#define DRV_MOD_CALL_H

#include <stdint.h>

#define MOD_EXIST (-2)

int32_t load_drv_mod(const char *drv_name, const char *lib_name);
int32_t unload_drv_mod(const char *drv_name, const char *lib_name);

#endif
