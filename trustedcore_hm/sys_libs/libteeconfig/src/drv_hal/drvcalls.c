/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * Description: drv call interface for TA
 * Create: 2018-11-20
 */

#include <stdio.h>
#include <string.h>
#include <sre_syscalls_id.h>
#include <sre_syscalls_id_ext.h>
#include <hmdrv.h>
#include <api/errno.h>
#include <securec.h>
#include <api/tee_common.h>
#include "tee_log.h"
#include "tee_bit_ops.h"
#include "hwi_drv_call.h"
#include "boot_sharedmem.h"
#include "tee_secfile_load_agent.h"
#include "tee_sharemem.h"
#include "drv_sharedmem.h"
#define MAX_NAME_LEN        32
#define DRV_MOD_PARAM_LEN   2
#define PRODCUT_MAX_LEN     64

uint32_t tee_hwi_msg_register(uint32_t uw_hwi_num)
{
    uint64_t args[] = {
        (uint64_t)uw_hwi_num,
    };
    return hm_drv_call(SW_SYSCALL_HWI_IPCREGISTER, args, ARRAY_SIZE(args));
}

uint32_t tee_hwi_msg_deregister(uint32_t uw_hwi_num)
{
    uint64_t args[] = {
        (uint64_t)uw_hwi_num,
    };
    return hm_drv_call(SW_SYSCALL_HWI_IPCDEREGISTER, args, ARRAY_SIZE(args));
}

int32_t get_tlv_sharedmem(const char *type, uint32_t type_size, void *buffer, uint32_t *buffer_size, bool clear_flag)
{
#ifdef CONFIG_TEE_MISC_DRIVER
    int32_t ret = tee_shared_mem(type, type_size, buffer, buffer_size, clear_flag);
    return ret;
#else
    uint64_t args[] = {
        (uint64_t)(uintptr_t)type,
        (uint64_t)type_size,
        (uint64_t)(uintptr_t)buffer,
        (uint64_t)(uintptr_t)buffer_size,
        (uint64_t)clear_flag,
    };

    return hm_drv_call(SW_SYSCALL_GET_TLV_TEESHAREDMEM, args, ARRAY_SIZE(args));
#endif
}

#define CHIP_TYPE_NAME_STRLEN 10
int32_t tee_get_chip_type(char *buffer, uint32_t buffer_len)
{
#ifdef TEE_SUPPORT_DYN_CONF
    if (buffer == NULL || buffer_len == 0 || buffer_len > CHIP_TYPE_LEN_MAX) {
        tloge("invalid buffer while get chip type\n");
        return -1;
    }
    uint32_t size = buffer_len;
    char chip_type_name[CHIP_TYPE_NAME_STRLEN] = { "chip_type" };
    int32_t ret = get_tlv_sharedmem(chip_type_name, CHIP_TYPE_NAME_STRLEN, buffer, &size, 0);
    if (ret != TLV_SHAREDMEM_SUCCESS) {
        tloge("get chip type from share mem failed\n");
        return ret;
    }

    if (strnlen(buffer, CHIP_TYPE_LEN_MAX) >= CHIP_TYPE_LEN_MAX) {
        tloge("chip type length is invalid\n");
        return -1;
    }

    return 0;
#else
    (void)buffer;
    (void)buffer_len;
    return -1;
#endif
}

__attribute__((visibility("default"))) \
int32_t tee_ext_get_dieid(uint32_t *in_buffer)
{
#ifdef CONFIG_SUPPORT_GET_DIEID
    uint64_t args[] = {
        (uint64_t)(uintptr_t)(in_buffer),
    };
    return hm_drv_call(SW_SYSCALL_TEE_HAL_GET_DIEID, args, ARRAY_SIZE(args));
#else
    (void)in_buffer;
    return TEE_ERROR_NOT_SUPPORTED;
#endif
}
