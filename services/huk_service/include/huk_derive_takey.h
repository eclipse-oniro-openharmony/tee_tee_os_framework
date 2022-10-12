/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: huk derive takey
 * Create: 2022-10-08
 */
#ifndef HUK_DERIVE_TAKEY_H
#define HUK_DERIVE_TAKEY_H

#include <tee_defines.h>
#include "huk_service_msg.h"

struct huk_access_table {
    uint32_t cmd_id;
    TEE_UUID uuid;
};

int32_t huk_srv_map_from_task(uint32_t in_task_id, uint64_t va_addr, uint32_t size,
    uint32_t out_task_id, uint64_t *virt_addr);
void huk_srv_task_unmap(uint64_t virt_addr, uint32_t size);
TEE_Result huk_task_takey_msg_check(const struct huk_srv_msg *msg);
TEE_Result do_derive_takey(const uint8_t *salt_tmp, uint32_t salt_size, uint8_t *key_tmp, uint32_t key_size,
    uint32_t inner_iter_num);
TEE_Result huk_task_derive_takey(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
    uint32_t self_pid, uint32_t sndr_pid, const TEE_UUID *uuid);

#endif
