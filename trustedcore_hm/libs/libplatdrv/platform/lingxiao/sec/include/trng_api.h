/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
* Description: trng api head file
* Author: chenyao
* Create: 2019/12/30
*/
#ifndef __TRNG_API_H__
#define __TRNG_API_H__

#include <sys/hm_types.h>

int32_t trng_get_random(uint8_t *trng_addr, uint32_t len);

#endif
