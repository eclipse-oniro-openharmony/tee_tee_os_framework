/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: misc-agent function declaration.
 * Create: 2020-01-13
 */
#ifndef LIBAGENT_TEE_MISC_H
#define LIBAGENT_TEE_MISC_H

#include <stdint.h>

int32_t get_time_of_data(uint32_t *seconds, uint32_t *millis, char *time_str, uint32_t time_str_len);

#endif
