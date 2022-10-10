/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: client auth func statement for ta
 * Create: 2020-02-15
 */
#ifndef LIBTAENTRY_CLIENT_AUTH_H
#define LIBTAENTRY_CLIENT_AUTH_H

#include <stdint.h>
#include <tee_defines.h>
#include "client_auth_pub_interfaces.h"

TEE_Result check_client_perm(uint32_t param_types, const TEE_Param params[TA_COMMAND_TEE_PARAM_NUM]);

#endif
