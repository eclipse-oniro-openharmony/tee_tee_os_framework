/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: ta policy headfile
 * Create: 2017-03-10
 */

#ifndef LIBAC_TA_POLICY_H
#define LIBAC_TA_POLICY_H

#include "ac_policy.h"

#define GET_MAP_DEF(map)                                 \
struct ac_map* get_ac_map_##map();                       \
struct ac_map* get_ac_dyn_map_##map();
#define GET_KV_DEF(kv)                                   \
struct ac_map_key_value *get_kv_##kv(uint32_t *size);

GET_MAP_DEF(uid_to_sid)
GET_MAP_DEF(uuid_to_cred)
GET_MAP_DEF(name_to_sid)

GET_KV_DEF(uuid_to_cred)
GET_KV_DEF(uid_to_sid)
#endif
