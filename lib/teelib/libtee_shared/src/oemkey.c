/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: oemkey interface
 * Create: 2021-7-19
 */

#include <stdint.h>
#include <hm_msg_type.h> /* for ARRAY_SIZE */
#include <sre_syscalls_id.h>
#include "securec.h"
#include "tee_defines.h"
#include "tee_sharemem.h"
#include "tee_log.h"

__attribute__((visibility("default"))) \
uint32_t tee_hal_get_provision_key(uint8_t *oem_key, size_t key_size)
{
#ifdef CONFIG_TEE_MISC_DRIVER
    uint32_t ret = tee_get_oemkey_info(oem_key, key_size);
    return ret;
#else
    (void)oem_key;
    (void)key_size;
    return TEE_ERROR_NOT_SUPPORTED;
#endif
}
