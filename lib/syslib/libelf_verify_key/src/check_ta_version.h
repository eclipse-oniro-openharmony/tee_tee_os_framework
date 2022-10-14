/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: ta permission check function defines
 * Create: 2021-02-28
 */
#ifndef CHECK_TA_VERSION_H
#define CHECK_TA_VERSION_H

#include <stdbool.h>

bool ta_local_sign_check(void);

bool is_keywest_signature(void);
#endif
