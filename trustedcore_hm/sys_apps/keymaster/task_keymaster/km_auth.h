/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2019. All rights reserved.
 * Description: keymaster authentication header
 * Create: 2015-01-17
 */
#ifndef __KM_AUTH_H
#define __KM_AUTH_H

#include <dlist.h>
#include "tee_internal_api.h"
#include "keymaster_defs.h"
#include "km_types.h"
#include "km_keynode.h"
#include "keyblob.h"
int32_t authentication_key(const keyblob_head *key_blob, const keymaster_key_param_set_t *params_enforced);

keymaster_error_t authorize_update_finish(uint64_t op_handle, const keymaster_key_param_set_t *params_enforced);
void reset_key_record(void);

keymaster_error_t process_authorize_begin(keyblob_head *key_blob, const keymaster_key_param_set_t *params_enforced,
                                          key_auth *key_node);
int32_t check_km_params(const keymaster_key_param_set_t *hw_params_set,
    const keymaster_key_param_set_t *sw_params_set);

#endif
