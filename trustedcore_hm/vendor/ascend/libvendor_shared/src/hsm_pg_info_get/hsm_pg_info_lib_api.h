/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: hsm pg info get lib head file
* Author: chenyao
* Create: 2020/9/3
*/

#ifndef HSM_PG_INFO_LIB_API
#define HSM_PG_INFO_LIB_API

#include <stdint.h>

uint32_t lib_pg_info_read(uint32_t dev_id, uint32_t module, uint32_t data, uint64_t *out_data);

#endif
