/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: shared mem API
 * Create: 2020-06
 */
#include "boot_sharedmem.h"
#include <securec.h>
#include "tee_log.h"
#include "plat_cfg.h"
#include "sre_syscalls_id.h"
#include "sys/mman.h"
#include "shared_mem_api.h"
#include "drv_sharedmem.h"
#include <hm_mman_ext.h>
#include "drv_module.h"
#include "drv_param_type.h"
#include <plat_features.h>
#include "sre_access_control.h"
#include <hmdrv_stub.h>

#define MAP_INVALID_32BITADDR        0xFFFFFFFF
#define MAP_INVALID_64BITADDR        0xFFFFFFFFFFFFFFFF
#define SRE_MAX_NOMAP_MAP_COUNT      19
#define SHAREDMEM_DEFAULT_SIZE       0x1000

static uint64_t g_teeos_sharedmem_offset_map[] = {
    TEEOS_SHAREDMEM_OFFSET_MODEM,
    TEEOS_SHAREDMEM_OFFSET_FINGERPRINT,
    TEEOS_SHAREDMEM_OFFSET_ROOTSTATUS,
    TEEOS_SHAREDMEM_OFFSET_ESE,
    TEEOS_SHAREDMEM_OFFSET_COLORLOCK,
    TEEOS_SHAREDMEM_OFFSET_DSS,
    TEEOS_SHAREDMEM_OFFSET_MAILBOX,
    TEEOS_SHAREDMEM_OFFSET_SKYTONE,
    TEEOS_SHAREDMEM_OFFSET_NOMAP,
    TEEOS_SHAREDMEM_OFFSET_TBIMGINFO,
    TEEOS_SHAREDMEM_OFFSET_ES_CS,
    TEEOS_SHAREDMEM_OFFSET_SECFLASH,
    TEEOS_SHAREDMEM_OFFSET_SPI_DMA_BUF,
    TEEOS_SHAREDMEM_OFFSET_CERTKEY,
    TEEOS_SHAREDMEM_OFFSET_MEMORY_SGLIST
};

static uint32_t g_teeos_sharedmem_size[] = {
    TEEOS_SHAREDMEM_MODULE_SIZE_256,
    TEEOS_SHAREDMEM_MODULE_SIZE_256,
    TEEOS_SHAREDMEM_MODULE_SIZE_256,
    TEEOS_SHAREDMEM_MODULE_SIZE_256,
    TEEOS_SHAREDMEM_MODULE_SIZE_512,
    TEEOS_SHAREDMEM_MODULE_SIZE_256,
    TEEOS_SHAREDMEM_MODULE_SIZE_256,
    TEEOS_SHAREDMEM_MODULE_SIZE_256,
    TEEOS_SHAREDMEM_MODULE_SIZE_256,
    TEEOS_SHAREDMEM_MODULE_SIZE_512,
    TEEOS_SHAREDMEM_MODULE_SIZE_256,
    TEEOS_SHAREDMEM_MODULE_SIZE_256,
    TEEOS_SHAREDMEM_MODULE_SIZE_256,
    TEEOS_SHAREDMEM_MODULE_SIZE_128K,
    TEEOS_SHAREDMEM_MODULE_SIZE_4K
};

int32_t get_shared_mem_info(enum sharedmem_types type, uint32_t *buffer, uint32_t size)
{
    uint64_t offset;
    uint32_t max_size;
    int32_t ret;
    bool sharedmem_flag = get_sharedmem_flag();
    uint32_t sharedmem_vaddr = get_sharedmem_vaddr();
    if (!sharedmem_flag) {
        tloge("no shared mem at this platform or sharedmem init failed\n");
        return -1;
    }

    if (type >= TEEOS_SHARED_MEM_MAX || buffer == NULL) {
        tloge("invalid param, type=%d\n", type);
        return -1;
    }

    if (sharedmem_vaddr == 0) {
        tloge("sharedmem_vaddr error or no shared mem at this platform\n");
        return -1;
    }

    offset   = g_teeos_sharedmem_offset_map[type];
    max_size = g_teeos_sharedmem_size[type];
    if (size > max_size) {
        tloge("sharedmem size=0x%x invalid\n", size);
        return -1;
    }

    ret = memcpy_s(buffer, size, (void *)(uintptr_t)(sharedmem_vaddr + offset), size);
    if (ret != EOK) {
        tloge("copy sharedmem failed, type=%d", type);
        return -1;
    }

    if (type == TEEOS_SHARED_MEM_SECBOOT || type == TEEOS_SHARED_MEM_MAILBOX) {
        if (memset_s((void *)(uintptr_t)sharedmem_vaddr + offset, max_size, 0, max_size) != EOK) {
            tloge("memset sharedmem failed\n");
            return -1;
        }
    }
    return 0;
}

static int32_t sharedmem_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t ret;
    if (params == NULL || params->args == 0)
        return -1;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_GET_TEESHAREDMEM, permissions, GENERAL_GROUP_PERMISSION)
        if (args[1] > 0) {
            ACCESS_CHECK_A64(args[0], args[1]);
            ACCESS_WRITE_RIGHT_CHECK(args[0], args[1]);
        }
        ret = (uint32_t)get_shared_mem_info(args[2], (uint32_t *)(uintptr_t)args[0], (uint32_t)args[1]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_GET_TLV_TEESHAREDMEM, permissions, GENERAL_GROUP_PERMISSION)
        if (args[1] > 0) {
            ACCESS_CHECK_A64(args[0], args[1]);
            ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
        }

        ACCESS_CHECK_A64(args[3], sizeof(uint32_t));
        ACCESS_READ_RIGHT_CHECK(args[3], sizeof(uint32_t));

        if ((uint32_t *)(uintptr_t)args[3] != NULL) {
            ACCESS_CHECK_A64(args[2], *(uint32_t *)(uintptr_t)args[3]);
            ACCESS_WRITE_RIGHT_CHECK(args[2], *(uint32_t *)(uintptr_t)args[3]);
        }
        ret = (uint32_t)get_tlv_shared_mem((char *)(uintptr_t)args[0],
                                           (uint32_t)(uintptr_t)args[1],
                                           (void *)(uintptr_t)args[2],
                                           (uint32_t *)(uintptr_t)args[3],
                                           (bool)args[4]);
        args[0] = ret;
        SYSCALL_END;
    default:
        return -1;
    }

    return 0;
}

#ifndef CONFIG_TEE_MISC_DRIVER
DECLARE_TC_DRV(
    sharedmem_addr,
    0,
    0,
    0,
    TC_DRV_EARLY_INIT,
    sharedmem_addr_init,
    NULL,
    sharedmem_syscall,
    NULL,
    NULL
);
#else
int32_t sharedmem_addr_init_stub(void)
{
    tloge("when the misc driver in the system platdrv can not get shared mem\n");
    return 0;
}

DECLARE_TC_DRV(
    sharedmem_addr,
    0,
    0,
    0,
    TC_DRV_EARLY_INIT,
    sharedmem_addr_init_stub,
    NULL,
    sharedmem_syscall,
    NULL,
    NULL
);
#endif
