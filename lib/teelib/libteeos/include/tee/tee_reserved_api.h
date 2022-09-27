/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: tee_reserved_api.h
 * Create: 2019-09-09
 */
#ifndef __TEE_RESERVE_API_H
#define __TEE_RESERVE_API_H

#include "tee_defines.h"
#include "ta_framework.h"

void init_property(uint32_t login_method, TEE_UUID *client_uuid, const struct ta_property *prop);
void tee_log_init(const TEE_UUID *uuid);
void tee_log_exit(void);
void init_tee_internal_api(void);
void add_session_cancel_state(uint32_t session_id);
void del_session_cancel_state(uint32_t session_id);

#endif // __TEE_RESERVE_API_H
