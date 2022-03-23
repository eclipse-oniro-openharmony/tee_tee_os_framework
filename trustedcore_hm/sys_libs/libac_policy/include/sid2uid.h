/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: declare the functions get uid by sid.
 * Create: 2020-10
 */

#ifndef SID2UID_H
#define SID2UID_H

const struct ac_map_key_value *get_ac_map_kv_uid_to_sid();
uint32_t get_ac_map_kv_uid_to_sid_size();
int get_uid_by_sid(uint64_t sid, uid_t *uid);

#endif
