/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: huk service config.
 * Create: 2020-05-22
 */
#ifndef HUK_SERVICE_CONFIG_H
#define HUK_SERVICE_CONFIG_H

#include <tee_defines.h>

bool is_huk_service_compatible_plat(void);
TEE_Result check_huk_access_permission(const TEE_UUID *uuid);
bool is_kds_uuid(const TEE_UUID *uuid);
bool is_ta_access_kds_permission(const TEE_UUID *uuid);
bool is_provisionkey_access(const TEE_UUID *uuid);
#endif
