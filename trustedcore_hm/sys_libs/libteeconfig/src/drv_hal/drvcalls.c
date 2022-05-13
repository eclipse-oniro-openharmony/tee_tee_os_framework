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
#include "gatekeeper_drv_call.h"
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

__attribute__((visibility("default"))) \
int __get_platform_chip(uint32_t *platform, uint32_t *chip)
{
    if (platform != NULL)
        *platform = (uint32_t)TRUSTEDCORE_PLATFORM_CHOOSE;
    if (chip != NULL)
        *chip = (uint32_t)TRUSTEDCORE_CHIP_CHOOSE;

    return 0;
}

__attribute__((visibility("default"))) \
int __get_target_product(char *target_product, int *buff_size)
{
    int32_t size;
    uint32_t dst_len;
    char *target_product_value = TARGET_PRODUCT_VAL;

    if (target_product == NULL || buff_size == NULL)
        return HM_ERROR;

    size = *buff_size;
    if (size < 1 || size > PRODCUT_MAX_LEN)
        return HM_ERROR;

    dst_len = strnlen(target_product_value, PRODCUT_MAX_LEN);
    if (strncpy_s(target_product, (uint32_t)(size - 1), target_product_value, dst_len) != EOK)
        return HM_ERROR;

    if ((uint32_t)size > dst_len)
        *buff_size = dst_len;

    return 0;
}

int32_t __set_dynmem_config(const void *memconfig, uint32_t type)
{
    uint64_t args[] = { (uint64_t)(uintptr_t)memconfig, (uint64_t)type };
    return hm_drv_call(SW_SYSCALL_SET_DYNMEM_CONFIG, args, ARRAY_SIZE(args));
}

bool __add_key_factor(uint64_t secure_id, const uint8_t *key_factor, uint32_t key_len)
{
    uint64_t args[] = { secure_id,
                        (uint64_t)(uintptr_t)key_factor,
                        (uint64_t)key_len,
                      };

    return hm_drv_call(SW_SYSCALL_ADD_KEY_FACTOR, args, ARRAY_SIZE(args));
}

bool __delete_key_factor(uint64_t secure_id)
{
    uint64_t args[] = { secure_id };

    return hm_drv_call(SW_SYSCALL_DELETE_KEY_FACTOR, args, ARRAY_SIZE(args));
}

bool __get_key_factor(uint64_t secure_id, uint8_t *key_factor, uint32_t *key_len)
{
    uint64_t args[] = { secure_id,
                        (uint64_t)(uintptr_t)key_factor,
                        (uint64_t)(uintptr_t)key_len,
                      };

    return hm_drv_call(SW_SYSCALL_GET_KEY_FACTOR, args, ARRAY_SIZE(args));
}

/* get sharedmem outside of platdrv */
int32_t sre_get_shared_mem_info(enum sharedmem_types type, uint32_t *buffer, uint32_t size)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)buffer,
        (uint64_t)size,
        (uint64_t)type,
    };

    return hm_drv_call(SW_SYSCALL_GET_TEESHAREDMEM, args, ARRAY_SIZE(args));
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

static int32_t drv_mod_param_check(const char *drv_name, const char *lib_name)
{
    if (drv_name == NULL || lib_name == NULL)
        return HM_ERROR;

    if ((strnlen(drv_name, MAX_NAME_LEN) == MAX_NAME_LEN) || (strnlen(drv_name, MAX_NAME_LEN) == 0)) {
        tloge("drv name is invalid\n");
        return HM_ERROR;
    }

    /* reserved one char for '\0' */
    if ((strnlen(lib_name, MAX_NAME_LEN) == MAX_NAME_LEN) || (strnlen(lib_name, MAX_NAME_LEN) == 0)) {
        tloge("lib name is invalid\n");
        return HM_ERROR;
    }

    return 0;
}

int32_t load_drv_mod(const char *drv_name, const char *lib_name)
{
    int32_t ret = drv_mod_param_check(drv_name, lib_name);
    if (ret != 0)
        return HM_ERROR;

    uint64_t args[DRV_MOD_PARAM_LEN] = { (uint64_t)(uintptr_t)lib_name, (uint64_t)strlen(lib_name) };
    uint32_t lens[DRV_MOD_PARAM_LEN] = { (uint32_t)strlen(lib_name), 0 };

    ret = (int32_t)hm_drv_call_new(drv_name, SW_SYSCALL_OPEN_MOD, args, lens, (int32_t)ARRAY_SIZE(args));

    tee_unlink_lib(lib_name, true);

    return ret;
}

int32_t unload_drv_mod(const char *drv_name, const char *lib_name)
{
    int32_t ret = drv_mod_param_check(drv_name, lib_name);
    if (ret != 0)
        return HM_ERROR;

    uint64_t args[DRV_MOD_PARAM_LEN] = { (uint64_t)(uintptr_t)lib_name, (uint64_t)strlen(lib_name) };
    uint32_t lens[DRV_MOD_PARAM_LEN] = { (uint32_t)strlen(lib_name), 0 };

    return (int32_t)hm_drv_call_new(drv_name, SW_SYSCALL_CLOSE_MOD, args, lens, (int32_t)ARRAY_SIZE(args));
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
