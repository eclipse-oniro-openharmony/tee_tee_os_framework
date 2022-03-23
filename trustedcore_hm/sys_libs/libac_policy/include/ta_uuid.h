/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: ta uuid headfile
 * Create: 2017-03-10
 */

#ifndef LIBAC_TA_UUID_H
#define LIBAC_TA_UUID_H

#include <stdbool.h>
#include <stdint.h>
#include <uidgid.h>

bool ac_map2task_valid_subj_sid(uint64_t sid);
bool ac_taskmap2task_valid_subj_sid(uint64_t sid);
bool ac_ta_add_valid_obj(const char *s);
bool ac_teecall_valid_obj(uint8_t rights);

#endif
