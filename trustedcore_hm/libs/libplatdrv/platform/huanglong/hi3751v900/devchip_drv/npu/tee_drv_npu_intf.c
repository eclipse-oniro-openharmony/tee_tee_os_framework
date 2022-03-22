/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee drv npu interface
 * Author: sdk
 * Create: 2020-02-19
 */

#include "hi_type_dev.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "drv_legacy_def.h"

#include "tee_drv_npu_func.h"
#include "tee_drv_npu_utils.h"
#include "tee_drv_ioctl_npu.h"
#include "hi_log.h"

/* functions */
static hi_s32 npu_copy_from_user(hi_void *to, unsigned long to_len, const hi_void *from, unsigned long from_len)
{
    hi_s32 ret;

    if (from_len == 0) {
        return HI_SUCCESS;
    }

    NPU_NULL_POINTER_RETURN(to);
    NPU_NULL_POINTER_RETURN(from);
    NPU_FATAL_CON_RETURN(to_len < from_len, HI_ERR_NPU_INVALID_PARA);

    hi_tee_drv_hal_read_right_check((void *)from, from_len);

    ret = memmove_s(to, to_len, from, from_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memmove_s, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 npu_copy_to_user(hi_void *to, unsigned long to_len, const hi_void *from, unsigned long from_len)
{
    hi_s32 ret;

    if (from_len == 0) {
        return HI_SUCCESS;
    }

    NPU_NULL_POINTER_RETURN(to);
    NPU_NULL_POINTER_RETURN(from);
    NPU_FATAL_CON_RETURN(to_len < from_len, HI_ERR_NPU_INVALID_PARA);

    hi_tee_drv_hal_write_right_check((void *)to, to_len);

    ret = memmove_s(to, to_len, from, from_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memmove_s, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 _tee_drv_npu_ioctl(hi_u32 cmd, hi_void *argp)
{
    hi_s32 ret;
    tee_npu_mgmt *tee_npu_mgmt_ptr = get_npu_mgmt();

    hi_u32 nr;
    hi_dbg_func_enter();

    nr = _IOC_NR(cmd);
    hi_log_dbg("cmd 0x%x, nr %d, size %d, local cmd 0x%x\n",
        cmd, nr, _IOC_SIZE(cmd), tee_npu_mgmt_ptr->npu_ioctl_entry[nr].cmd);
    NPU_NULL_POINTER_RETURN(argp);
    NPU_FATAL_CON_RETURN(nr >= NPU_TEE_IOCTL_CMD_COUNT, HI_ERR_NPU_INVALID_PARA);
    NPU_FATAL_CON_RETURN(tee_npu_mgmt_ptr->npu_ioctl_entry[nr].cmd != cmd, HI_ERR_NPU_INVALID_PARA);
    NPU_FATAL_CON_RETURN(tee_npu_mgmt_ptr->npu_ioctl_entry[nr].fun_entry == HI_NULL, HI_ERR_NPU_INVALID_PARA);

    ret = tee_npu_mgmt_ptr->npu_ioctl_entry[nr].fun_entry(argp);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    hi_dbg_func_exit();
    return ret;
}

static int tee_drv_npu_ioctl(const unsigned int cmd, hi_void *ioctl_args)
{
    hi_u8 local[NPU_TEE_IOCTL_ARG_MAX_SIZE] = { 0 };
    hi_s32 ret;

    NPU_FATAL_CON_RETURN(NPU_TEE_IOCTL_ARG_MAX_SIZE <= _IOC_SIZE(cmd), HI_ERR_NPU_INVALID_PARA);

    if (_IOC_SIZE(cmd) != 0x0) {
        ret = npu_copy_from_user(local, sizeof(local), ioctl_args, _IOC_SIZE(cmd));
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(npu_copy_from_user, ret);
            return ret;
        }
    }

    ret = _tee_drv_npu_ioctl(cmd, local);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    if (_IOC_DIR(cmd) & _IOC_READ) {
        ret = npu_copy_to_user(ioctl_args, _IOC_SIZE(cmd), local, _IOC_SIZE(cmd));
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(npu_copy_to_user, ret);
            return ret;
        }
    }

    return ret;
}

int tee_npu_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
    hi_log_dbg("npu_syscall swi_id 0x%x\n", swi_id);
    if (params == NULL || params->args == 0)
        return -1;
    uint64_t  *args = (uint64_t *)(uintptr_t)params->args;
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_NPU, permissions, GENERAL_GROUP_PERMISSION)
            /* register usage:
             * r0: cmd, r1: args
             *
             * Note: must call ACCESS_CHECK Convert the virtual address
             * of the api to the virtual address of drv.
             */
            hi_log_dbg("npu_syscall args[0] 0x%x, args[1] 0x%x\n", args[0], args[1]);
            ACCESS_CHECK(args[1], _IOC_SIZE(args[0]))

            switch (args[0]) {
                case NPU_TEE_IOCTL_GLB_INIT:
                default:
                    break;
            }
            args[0] = tee_drv_npu_ioctl(args[0], (hi_void *)args[1]);
            hi_log_dbg("npu_syscall return 0x%x\n", args[1]);
            SYSCALL_END
        default:
            return -EINVAL;
    }

    return 0;
}

/* for npu suspend and resume */
static hi_s32  npu_tee_suspend(hi_void)
{
    return HI_SUCCESS;
}

static hi_s32 npu_tee_resume(hi_void)
{
    return HI_SUCCESS;
}

hi_s32 npu_drv_setup(hi_void)
{
    return HI_SUCCESS;
}

hi_tee_drv_hal_driver_init_late(g_drv_npu, 0, npu_drv_setup, tee_npu_syscall, npu_tee_suspend, npu_tee_resume);

