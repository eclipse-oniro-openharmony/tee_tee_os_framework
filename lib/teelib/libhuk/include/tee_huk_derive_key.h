/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: huk derive key
 * Create: 2022-10-25
 */
#ifndef TEE_HUK_DERIVE_KEY_H
#define TEE_HUK_DERIVE_KEY_H

#include <tee_defines.h>

struct meminfo_t {
    uint64_t buffer;
    uint32_t size;
};

void *huk_alloc_shared_mem(uint32_t size);
void huk_free_shared_mem(uint8_t *p, uint32_t size);
TEE_Result tee_internal_derive_key(const uint8_t *salt, uint32_t saltsize, uint8_t *key, uint32_t keysize);

#endif