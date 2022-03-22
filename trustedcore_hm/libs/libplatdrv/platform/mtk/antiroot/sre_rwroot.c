/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * Description: record root status for REE
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

#define CANARY_SIZE 16
/* use "can_before" "can_after" to protect status from memory overflow */
struct root_status {
    uint8_t can_before[CANARY_SIZE];
    uint32_t status;
    uint8_t can_after[CANARY_SIZE];
};

static struct root_status g_cur_root_status;
#define set_root_status(bit) (g_cur_root_status.status |= 1u << (bit))

/* Write RootStatus */
static uint32_t write_root_status(uint32_t status)
{
    uint32_t tmp_status;
    /* write start from KERNELCODEBIT, not fastboot bits */
    uint32_t count = KERNELCODEBIT;
    tloge("lwk write root status");

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
    tloge("lwk read root status");
    //set_fastboot_bit();

    /*
     * we don't take OEMINFO_BIT | ROOTPROCBIT in count.
     * see detail in sre_rwroot.h
     */
    if ((g_cur_root_status.status & READ_MASK) != 0)
        set_root_status(ROOTSTATE_BIT);

    tloge("read status 0x%x\n", g_cur_root_status.status);

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
        args[0] = 0;
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

