/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: declear functions to oemkey
 * Create: 2021-7
 */
#ifndef OEMKEY_H
#define OEMKEY_H
#include <stdint.h>
#include <stdlib.h>

uint32_t tee_hal_get_provision_key(uint8_t *oem_key, size_t key_size);

#endif
