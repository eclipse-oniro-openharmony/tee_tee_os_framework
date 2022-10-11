/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: API of HUK service.
 * Create: 2020-05-22
 */
#ifndef HUK_SERVICE_TEE_INTERNAL_HUK_H
#define HUK_SERVICE_TEE_INTERNAL_HUK_H

#include <tee_defines.h>

struct platkey_type_size {
    uint32_t keytype;
    uint32_t keybuff_size;
};

struct meminfo_t {
    uint64_t buffer;
    uint32_t size;
};

/*
 * For compatible platforms, derive the key directly;
 * for new platforms, salt + the uuid obtained from the huk service, and then derive the key
 */
TEE_Result tee_internal_derive_key(const uint8_t *salt, uint32_t saltsize, uint8_t *key, uint32_t keysize);
TEE_Result get_device_id_prop(uint8_t *dst, uint32_t len);
#endif
