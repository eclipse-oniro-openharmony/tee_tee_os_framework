/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: trng internal api head file
* Author: huawei
* Create: 2019/12/30
*/
#ifndef TRNG_INTERNAL_API_H
#define TRNG_INTERNAL_API_H

#include <stdint.h>

uint32_t trng_init(void);
uint32_t trng_get_data_use(uint8_t *trngstore_addr, uint32_t trng_len);

#endif
