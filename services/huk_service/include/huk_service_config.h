/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Description: huk service config.
 * Create: 2020-05-22
 */
#ifndef HUK_SERVICE_CONFIG_H
#define HUK_SERVICE_CONFIG_H

#include <tee_defines.h>

struct huk_access_table {
    uint32_t cmd_id;
    TEE_UUID uuid;
};
bool check_huk_access_permission(const uint32_t cmd_id, const TEE_UUID *uuid);
#endif
