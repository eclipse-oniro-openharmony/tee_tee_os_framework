/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee process log tag head file
 * Create: 2020-02-04
 */
#ifndef TEE_TAG_H
#define TEE_TAG_H

#include <stdint.h>

uint8_t get_log_source(const char *driver_tag);
char *get_log_tag(const char *driver_tag, const char *debug_prefix);
uint32_t get_log_thread_tag(void);
void set_log_use_tid_flag(void);
#endif
