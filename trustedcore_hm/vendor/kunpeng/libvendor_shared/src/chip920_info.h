/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: declear functions to get chip info
 * Create: 2021-4
 */
#ifndef CHIP920_INFO_H
#define CHIP920_INFO_H
#include <stdint.h>
#include <unistd.h>

uint32_t get_certkey_info(uint8_t *cert_key, size_t len);
#endif
