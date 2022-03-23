/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * Description: record root status for REE
 * Author: zhangguangyu zhangguangyu3@huawei.com
 * Create: 2016-3-31
 */
#include "sre_rwroot.h"
#include <string.h>
#include <errno.h>
#include <sys/usrsyscall_ext.h>
#include <register_ops.h>
#include <sre_syscalls_ext.h>
#include <sre_syscalls_id.h>
#include <sre_syscalls_id_ext.h>
#include <sre_access_control.h>
#include <drv_pal.h>
#include <hmdrv_stub.h>
#include <drv_module.h>
#include "device_status.h"
#include "boot_sharedmem.h"

#define CANARY_SIZE 16
/* use "can_before" "can_after" to protect status from memory overflow */
struct root_status {
    uint8_t can_before[CANARY_SIZE];
    uint32_t status;
    uint8_t can_after[CANARY_SIZE];
};

static struct root_status g_cur_root_status;
#define set_root_status(bit) (g_cur_root_status.status |= 1u << (bit))

/*
 * read oeminfo and fastboot lock ONLY once
 * 0: have not read
 * 1: has read
 */
static bool g_already_read = false;
static const char *g_lock_color_str[] = { "GREEN", "YELLOW", "ORANGE", "RED" }; /* read fastboot lock color */

static int32_t get_fastboot_lock_color(void)
{
    int32_t i;
    int32_t lock_color = LOCK_COLOR_MAX;
    uint32_t ret;
    int32_t sret;
    struct verify_boot_mem_struct verify_boot_mem = { { 0 }, { 0 }, { 0 }, 0 };

    ret = get_shared_mem_info(TEEOS_SHARED_MEM_COLORLOCK, (uint32_t *)&verify_boot_mem,
                              sizeof(verify_boot_mem));
    if (ret != RWROOT_RET_SUCCESS) {
        tloge("get verify boot info failed\n");
        return LOCK_COLOR_MAX;
    }

    for (i = 0; i < LOCK_COLOR_MAX; i++) {
        sret = memcmp(verify_boot_mem.lock_color, g_lock_color_str[i], strlen(g_lock_color_str[i]) + 1);
        if (sret == 0) {
            lock_color = i;
            break;
        }
    }

    if (lock_color == LOCK_COLOR_MAX) {
        tloge("no lock color match\n");
        return LOCK_COLOR_MAX;
    }

    return lock_color;
}

/* set OEMINFO_BIT and Fastboot lock color */
static void set_fastboot_bit(void)
{
    int32_t sta;

    if (g_already_read) {
        tlogd("g_already_read is 1, already read\n");
        return;
    } else {
        tlogd("g_already_read is 0, read now\n");
        g_already_read = true;
    }

    /*
     * oeminfo: 1 is rooted, 0 is not rooted, another return value is -1, it indicates that
     * the platform does not support root check.
     */
    sta = is_device_rooted();
    if (sta == DEVICE_IS_ROOTED) {
        set_root_status(OEMINFO_BIT);
        tlogd("OEMINFO_BIT is set to 1\n");
    }

    switch (get_fastboot_lock_color()) {
    case LOCK_GREEN:
        tlogd("fastboot_lock_color is 0x%x\n", LOCK_GREEN);
        break;
    case LOCK_YELLOW:
        set_root_status(FBLOCK_YELLOW_BIT);
        break;
    case LOCK_ORANGE:
        set_root_status(FBLOCK_ORANGE_BIT);
        break;
    case LOCK_RED:
        set_root_status(FBLOCK_RED_BIT);
        break;
    default:
        /*
         * get_fastboot_lock_color() has make sure there will be
         * no other color.
         */
        tloge("fastboot_lock_color is unkown\n");
        break;
    }
}

/* Write RootStatus */
static uint32_t write_root_status(uint32_t status)
{
    uint32_t tmp_status;
    /* write start from KERNELCODEBIT, not fastboot bits */
    uint32_t count = KERNELCODEBIT;

    tmp_status = status & WRITE_MASK;
    if (tmp_status == 0) {
        tloge("no usefull input!\n");
        return RWBOOT_RET_FAILURE;
    }
    tlogd("write entry status = 0x%x, tmp_status = 0x%x\n", status, tmp_status);

    /* not allow change bits from "1" back to "0" */
    while (count < TOTALBIT) {
        if ((tmp_status & (1u << count)) != 0)
            set_root_status(count);
        count++;
    }

    if ((g_cur_root_status.status & (1u << ROOTSTATE_BIT)) != 0)
        __set_kernel_root_state();

    tlogd("write success! status = 0x%x\n", g_cur_root_status.status);

    return RWROOT_RET_SUCCESS;
}

static uint32_t read_root_status(void)
{
    set_fastboot_bit();

    /*
     * we don't take OEMINFO_BIT | ROOTPROCBIT in count.
     * see detail in sre_rwroot.h
     */
    if ((g_cur_root_status.status & READ_MASK) != 0)
        set_root_status(ROOTSTATE_BIT);

    tlogd("read status 0x%x\n", g_cur_root_status.status);

    return g_cur_root_status.status;
}

static int32_t antiroot_status_syscall(int32_t swi_id, struct drv_param *params, uint64_t permissions)
{
    if (params == NULL || params->args == 0)
        return RWBOOT_RET_FAILURE;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        /* antiroot */
        SYSCALL_PERMISSION(SW_SYSCALL_ROOT_READ, permissions, GENERAL_GROUP_PERMISSION)
        args[0] = read_root_status();
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_ROOT_WRITE, permissions, ROOTSTATUS_GROUP_PERMISSION)
        args[0] = write_root_status((uint32_t)args[0]);
        SYSCALL_END;

        /* root check */
        SYSCALL_PERMISSION(SW_SYSCALL_IS_DEVICE_ROOTED, permissions, GENERAL_GROUP_PERMISSION)
        args[0] = (uint32_t)is_device_rooted();
        SYSCALL_END

     default:
        return RWBOOT_RET_FAILURE;
    }
    return RWROOT_RET_SUCCESS;
}

DECLARE_TC_DRV(
    antiroot_status_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    antiroot_status_syscall,
    NULL,
    NULL
);
