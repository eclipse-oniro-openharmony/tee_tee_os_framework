/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee drv demux interface
 * Author: sdk
 * Create: 2019-05-31
 */

#include "hi_type_dev.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_syscall_id.h"

#include "tee_drv_demux_func.h"
#include "tee_drv_demux_utils.h"
#include "tee_drv_demux_ioctl.h"

/* functions */
static hi_s32 dmx_copy_from_user(hi_void *to, unsigned long to_len, const hi_void *from, unsigned long from_len)
{
    hi_s32 ret;

    if (from_len == 0) {
        return HI_SUCCESS;
    }

    dmx_null_pointer_return(to);
    dmx_null_pointer_return(from);
    dmx_err_condition_return(to_len < from_len, HI_ERR_DMX_INVALID_PARA);

    hi_tee_drv_hal_read_right_check((void *)from, from_len);

    ret = memmove_s(to, to_len, from, from_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memmove_s, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 dmx_copy_to_user(hi_void *to, unsigned long to_len, const hi_void *from, unsigned long from_len)
{
    hi_s32 ret;

    if (from_len == 0) {
        return HI_SUCCESS;
    }

    dmx_null_pointer_return(to);
    dmx_null_pointer_return(from);
    dmx_err_condition_return(to_len < from_len, HI_ERR_DMX_INVALID_PARA);

    hi_tee_drv_hal_write_right_check((void *)to, to_len);

    ret = memmove_s(to, to_len, from, from_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memmove_s, ret);
        return ret;
    }

    return HI_SUCCESS;
}

static hi_s32 _tee_drv_demux_ioctl(hi_u32 cmd, hi_void *argp)
{
    hi_s32 ret;
    tee_dmx_mgmt *tee_dmx_mgmt_ptr = get_dmx_mgmt();

    hi_u32 nr;
    hi_dbg_func_enter();

    nr = _IOC_NR(cmd);
    hi_log_dbg("cmd 0x%x, nr %d, size %d, local cmd 0x%x\n",
        cmd, nr, _IOC_SIZE(cmd), tee_dmx_mgmt_ptr->dmx_ioctl_entry[nr].cmd);
    dmx_null_pointer_return(argp);
    dmx_err_condition_return(nr >= DMX_TEE_IOCTL_CMD_COUNT, HI_ERR_DMX_INVALID_PARA);
    dmx_err_condition_return(tee_dmx_mgmt_ptr->dmx_ioctl_entry[nr].cmd != cmd, HI_ERR_DMX_INVALID_PARA);
    dmx_err_condition_return(tee_dmx_mgmt_ptr->dmx_ioctl_entry[nr].fun_entry == HI_NULL, HI_ERR_DMX_INVALID_PARA);

    ret = tee_dmx_mgmt_ptr->dmx_ioctl_entry[nr].fun_entry(argp);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    hi_dbg_func_exit();

    return ret;
}

static int tee_drv_demux_ioctl(const unsigned int cmd, hi_void *ioctl_args)
{
    hi_u8 local[DMX_TEE_IOCTL_ARG_MAX_SIZE] = { 0 };
    hi_s32 ret;

    dmx_err_condition_return(DMX_TEE_IOCTL_ARG_MAX_SIZE <= _IOC_SIZE(cmd), HI_ERR_DMX_INVALID_PARA);

    if (_IOC_SIZE(cmd) != 0x0) {
        ret = dmx_copy_from_user(local, sizeof(local), ioctl_args, _IOC_SIZE(cmd));
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(dmx_copy_from_user, ret);
            return ret;
        }
    }

    ret = _tee_drv_demux_ioctl(cmd, local);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    if (_IOC_DIR(cmd) & _IOC_READ) {
        ret = dmx_copy_to_user(ioctl_args, _IOC_SIZE(cmd), local, _IOC_SIZE(cmd));
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(dmx_copy_to_user, ret);
            return ret;
        }
    }

    return ret;
}

int tee_demux_syscall(int swi_id, TSK_REGS_S *regs, UINT64 permissions)
{
    hi_log_dbg("demux_syscall swi_id 0x%x\n", swi_id);

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_DMX, permissions, GENERAL_GROUP_PERMISSION)
            /* register usage:
             * r0: cmd, r1: args
             *
             * Note: must call ACCESS_CHECK Convert the virtual address
             * of the api to the virtual address of drv.
             */
            hi_log_dbg("demux_syscall regs->r0 0x%x, regs->r1 0x%x\n", regs->r0, regs->r1);
            ACCESS_CHECK(regs->r1, _IOC_SIZE(regs->r0))

            switch (regs->r0) {
                case DMX_TEE_IOCTL_GLB_INIT:
                default:
                    break;
            }
            regs->r0 = tee_drv_demux_ioctl(regs->r0, (hi_void *)regs->r1);
            hi_log_dbg("demux_syscall return 0x%x\n", regs->r0);
            SYSCALL_END
        default:
            return -EINVAL;
    }

    return 0;
}

/* for demux suspend and resume */
static hi_s32  demux_tee_suspend(hi_void)
{
    return HI_SUCCESS;
}

static hi_s32 demux_tee_resume(hi_void)
{
    return HI_SUCCESS;
}

hi_s32 demux_drv_setup(hi_void)
{
    hi_tee_drv_hal_printf("load secure demux success. build time:[%s, %s]\n", __DATE__,  __TIME__);
    return HI_SUCCESS;
}

hi_tee_drv_hal_driver_init_late(drv_dmx, 0, demux_drv_setup, tee_demux_syscall, demux_tee_suspend, demux_tee_resume);

