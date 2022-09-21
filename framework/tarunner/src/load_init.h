/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: the functions to init library and tee hanle
 * Create: 2021-01-16
 */
#ifndef TA_MT_LOAD_INIT_H
#define TA_MT_LOAD_INIT_H

#include <stdint.h>

#define DECIMAL_BASE 10

int32_t get_priority(void);
int32_t extend_utables(void);
void clear_libtee(void);
void *get_libtee_handle(void);
void *ta_mt_dlopen(const char *name, int32_t flag);

#endif
