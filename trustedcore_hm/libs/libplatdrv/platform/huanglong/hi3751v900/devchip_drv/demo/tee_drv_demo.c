/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * File Name: tee_drv_demo.c
 * Description: drv demo
 * Author: Hisilicon
 * Created: 2019-07-08
 */

#include "tee_drv_demo.h"
#include "tee_drv_demo_func_test.h"

#define USE_MACRO

#ifdef USE_MACRO
/* use the macro definition */
int demo_syscall(int swi_id, TSK_REGS_S *regs, unsigned long long permissions)
{
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_DEMO_HELLO, permissions, GENERAL_GROUP_PERMISSION)
            ACCESS_CHECK(regs->r1, sizeof(int))
            hi_tee_drv_hal_printf("Hello, DRV demo. r0 = 0x%x\n", regs->r0);
            hi_tee_drv_hal_printf("r1_addr = 0x%x, r1_value = 0x%x\n", regs->r1, *(int *)(uintptr_t)regs->r1);
            *(int *)(uintptr_t)regs->r1 = 0x123;
            regs->r0 = 0;  /* return value for api */
            SYSCALL_END
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_DEMO_FUNC_TEST, permissions, GENERAL_GROUP_PERMISSION)
            hi_tee_drv_hal_printf("[DRV DEMO] func test, cmd = 0x%x\n", regs->r0);
            tee_drv_demo_func_test(regs->r0);
            regs->r0 = 0;  /* return value for api */
            SYSCALL_END
        default:
            return -EINVAL;
    }
    return 0;
}
#else
/* use the functions */
int demo_syscall(int swi_id, TSK_REGS_S *regs, unsigned long long permissions)
{
    int ret;

    switch (swi_id) {
        case HI_TEE_SYSCALL_DEMO_HELLO: {
            ret = hi_tee_drv_hal_permission_check(permissions, GENERAL_GROUP_PERMISSION);
            if (ret != 0) {
                regs->r0 = OS_ERROR;
                tloge("permission denied to access swi_id 0x%x. n", swi_id);
                break;
            }

            ret = hi_tee_drv_hal_user_mmap((void **)&(regs->r1), sizeof(unsigned int));
            if (ret != 0) {
                tloge("cmd %x: hi_tee_drv_hal_user_mmap(0x%lx, 0x%lx) failed: %d.",
                      swi_id, regs->r1, sizeof(unsigned int), ret);
                regs->r0 = OS_ERROR;
                break;
            }
            hi_tee_drv_hal_printf("Hello, DRV demo. r0 = 0x%x\n", regs->r0);
            hi_tee_drv_hal_printf("r1_addr = 0x%x, r1_value = 0x%x\n", regs->r1, *(int *)(uintptr_t)regs->r1);
            *(int *)(uintptr_t)regs->r1 = 0x123;

            regs->r0 = ret;  /* return value for api */
            hi_tee_drv_hal_user_munmap((void *)(uintptr_t)regs->r1, sizeof(unsigned int));
            break;
        }
        case HI_TEE_SYSCALL_DEMO_FUNC_TEST: {
            hi_tee_drv_hal_printf("[DRV DEMO] func test, cmd = 0x%x\n", regs->r0);
            tee_drv_demo_func_test(regs->r0);
            regs->r0 = 0;  /* return value for api */
        }
        default:
            return -EINVAL;
    }
    return 0;
}
#endif

static int tee_drv_demo_ioctl(const unsigned int cmd, void *ioctl_args, const size_t size)
{
    int ret;
    const char *test = "hisilicon ioctl test seccuss!";
    hi_tee_ioctl_args *args = (hi_tee_ioctl_args *)ioctl_args;

    if (args == NULL || size != sizeof(hi_tee_ioctl_args)) {
        hi_tee_drv_hal_printf("DRV DEMO, invalid parameter\n");
        return -1;
    }

    switch (cmd) {
        case TEE_DEMO_IOCTL_HELLO:
            hi_tee_drv_hal_printf("DRV DEMO, TEE_DEMO_IOCTL_HELLO\n");
            hi_tee_drv_hal_user_mmap((void **)&args->arg1, args->arg2);
            hi_tee_drv_hal_printf("DRV DEMO, data: 0x%llx, str: \"%s\"\n", args->arg0, (char *)(uintptr_t)args->arg1);
            ret = memset_s((void *)(uintptr_t)args->arg1, args->arg2, 0, args->arg2);
            ret |= memcpy_s((void *)(uintptr_t)args->arg1, args->arg2, test, strlen(test));
            hi_tee_drv_hal_user_munmap((void *)(uintptr_t)args->arg1, args->arg2);
            break;
        default:
            ret = -1;
            break;
    }

    return ret;
}

unsigned int demo_init(void)
{
    return hi_tee_drv_hal_module_register(HI_ID_DEMO, tee_drv_demo_ioctl);
}

hi_tee_drv_hal_driver_init_late(drv_demo, 0, demo_init, demo_syscall, NULL, NULL);

