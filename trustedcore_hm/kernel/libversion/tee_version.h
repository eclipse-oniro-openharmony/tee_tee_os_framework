/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: tee version define
 * Create: 2021-05
 */
#ifndef TEE_VERSION_H
#define TEE_VERSION_H

#include<stdint.h>
#include <stdbool.h>

bool get_tee_version(unsigned char *buf, uint32_t size);

#define RDR_VERSION_MAX_SIZE 128

#endif
