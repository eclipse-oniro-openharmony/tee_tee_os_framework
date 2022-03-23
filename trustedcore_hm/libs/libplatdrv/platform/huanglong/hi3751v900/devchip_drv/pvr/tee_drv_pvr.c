/*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
* Description: tee drv pvr function impl.
*/

#include "stdio.h"
#include "stdarg.h"
#include "hi_type_dev.h"
#include "hi_log.h"
#include "sre_access_control.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "hmdrv_stub.h"
#include "hi_tee_drv_mem.h"
#include "hi_tee_drv_common.h"
#include "tee_pvr.h"
#include "tee_pvr_utils.h"
#include "tee_drv_pvr.h"
#include "tee_drv_pvr_play.h"
#include "hi_tee_module_id.h"
#include "tee_internal_api.h"

#define pvr_map_sec_mem_to_cpu(sec_buf, phy_addr, data_size, ret) do { \
    (sec_buf).size = (data_size); \
    (sec_buf).smmu_addr = (phy_addr); \
    (ret) = hi_tee_drv_smmu_map_cpu(&(sec_buf), HI_FALSE); \
} while (0)

#define pvr_unmap_sec_mem(sec_buf) ((hi_void)hi_tee_drv_smmu_unmap_cpu((sec_buf)))

static hi_s32 check_play_copy_args(hi_u32 tsbuf, hi_u64 ree_buf, hi_u64 tee_buf, hi_u32 data_len)
{
    pvr_unused(tsbuf);
    /* add the limited(846*1024) for max for secure: forbid to copy much data to tee */
    if ((ree_buf == 0) || (tee_buf == 0) || (data_len == 0) || (data_len > 846 * 1024)) {
        hi_warn_print_info("Invalid input argument!");
        hi_warn_print_u64(ree_buf);
        hi_warn_print_u64(tee_buf);
        hi_warn_print_u32(data_len);
        return HI_TEE_ERROR_PVR_INVALID_PARAM;
    }

    return HI_SUCCESS;
}

/* copy ts data from ree to tee */
hi_s32 tee_drv_pvr_play_copy_from_ree(hi_u32 tsbuf, hi_mem_handle ns_addr_handle,
    hi_mem_handle sec_addr_handle, hi_u32 data_len)
{
    hi_s32 ret;
    hi_tee_smmu_buf ree_buf, sec_smmu_buf;
    hi_tee_smmu_buf sec_buf = {0};
    hi_u32 dst_size = data_len;
    hi_u64 tee_addr, ree_addr;

    hi_info_func_enter();

    /* 1. check parameter */
    ret = check_play_copy_args(tsbuf, ns_addr_handle.mem_handle, sec_addr_handle.mem_handle, data_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(check_play_copy_args, ret);
        return ret;
    }

    hi_tee_drv_mem_get_secsmmu_by_handle_id(&sec_smmu_buf, sec_addr_handle.mem_handle);
    tee_addr = sec_smmu_buf.smmu_addr + sec_addr_handle.addr_offset;

    /* 2.map the secural memory */
    pvr_map_sec_mem_to_cpu(sec_buf, tee_addr, data_len, ret);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(pvr_map_sec_mem_to_cpu, ret);
        goto MAP_FAILED;
    }

    ree_addr = ns_addr_handle.mem_handle + ns_addr_handle.addr_offset;

    /* 3. map the non-secural memory */
    ree_buf.virt = HI_NULL;
    ree_buf.smmu_addr = ree_addr;
    ree_buf.size = data_len;
    ret = hi_tee_drv_nssmmu_map_cpu(&ree_buf, HI_FALSE);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(hi_tee_drv_nssmmu_map_cpu, ret);
        pvr_unmap_sec_mem(&sec_buf);
        goto MAP_FAILED;
    }

    /* 4. do the copy */
    ret = drv_pvr_play_copy_ree_data_to_tee(sec_buf.virt, dst_size, ree_buf.virt, data_len);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(drv_pvr_play_copy_ree_data_to_tee, ret);
        pvr_unmap_sec_mem(&sec_buf);
        (hi_void)hi_tee_drv_nssmmu_unmap_cpu(&ree_buf);
        return ret;
    }

    /* 5. un-map the memory */
    pvr_unmap_sec_mem(&sec_buf);
    hi_tee_drv_nssmmu_unmap_cpu(&ree_buf);

    hi_info_func_exit();

    return HI_SUCCESS;

MAP_FAILED:
    hi_warn_print_u64(ree_buf);
    hi_warn_print_u64(tee_addr);
    hi_warn_print_u32(data_len);
    return HI_TEE_ERROR_PVR_NO_MEM;
}

/*
 * adjust ts data in order to send one whole frame(aligned by ts packet) to demux.
 * This API is defined for FF/FB play
 */
hi_s32 tee_drv_pvr_play_proc_ts_data(hi_mem_handle sec_addr_handle,
    hi_u32 head_offset, hi_u32 end_offset, hi_u32 head_add, hi_u32 end_add)
{
    hi_s32 ret;
    hi_u32 data_len;
    tee_pvr_play_tsdata_info data_info;
    hi_tee_smmu_buf sec_buf = {0};
    hi_tee_smmu_buf sec_smmu_buf;
    hi_u64 tee_addr;

    hi_info_func_enter();

    if (sec_addr_handle.mem_handle == 0) {
        hi_warn_print_info("Invalid input argument:null pointer!");
        hi_err_print_err_code(HI_TEE_ERROR_PVR_INVALID_PARAM);
        return HI_TEE_ERROR_PVR_INVALID_PARAM;
    }

    if ((end_offset > TEE_PVR_MAX_BUF_LENGTH) || (end_add > TEE_PVR_MAX_BUF_LENGTH)) {
        hi_warn_print_info("Invalid input argument:too long buffer size!");
        hi_err_print_err_code(HI_TEE_ERROR_PVR_INVALID_PARAM);
        return HI_TEE_ERROR_PVR_INVALID_PARAM;
    }

    hi_tee_drv_mem_get_secsmmu_by_handle_id(&sec_smmu_buf, sec_addr_handle.mem_handle);
    tee_addr = sec_smmu_buf.smmu_addr + sec_addr_handle.addr_offset;

    data_len = end_offset + end_add;
    /* 1. map the memory */
    pvr_map_sec_mem_to_cpu(sec_buf, tee_addr, data_len, ret);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(pvr_map_sec_mem_to_cpu, ret);
        hi_warn_print_u64(tee_addr);
        hi_err_print_err_code(HI_TEE_ERROR_PVR_NO_MEM);
        return HI_TEE_ERROR_PVR_NO_MEM;
    }

    /* 2. process the data following the specification of ts */
    data_info.end_offset = end_offset;
    data_info.end_add = end_add;
    data_info.head_offset = head_offset;
    data_info.head_add = head_add;
    ret = drv_pvr_play_proc_tsdata(&data_info, sec_buf.virt);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(drv_pvr_play_proc_tsdata, ret);
        pvr_unmap_sec_mem(&sec_buf);
        hi_err_print_err_code(ret);
        return ret;
    }

    /* 3. un-map the memory */
    pvr_unmap_sec_mem(&sec_buf);

    hi_info_func_exit();
    return HI_SUCCESS;
}

static hi_s32 tee_drv_pvr_ioctl(const unsigned int cmd, hi_void *buffer, hi_u32 len)
{
    hi_s32 ret = HI_FAILURE;

    hi_info_func_enter();

    hi_tee_pvr_drv_ioctl_buf *info = (hi_tee_pvr_drv_ioctl_buf *)buffer;

    switch (cmd) {
        case TEE_DRV_PVR_PLAYCOPYTOTEE: {
            ret = tee_drv_pvr_play_copy_from_ree(info->ch, info->ns_addr_handle, info->sec_addr_handle, info->data_len);
            break;
        }
        case TEE_DRV_PVR_PLAYPROCTSDATA: {
            ret = tee_drv_pvr_play_proc_ts_data(info->sec_addr_handle, info->head_offset, info->end_offset,
                info->head_add, info->end_add);
            break;
        }
        default: {
            hi_log_err("unsupport cmd:%x\n", cmd);
            break;
        }
    }
    pvr_unused(len);

    hi_info_func_exit();
    return ret;
}

hi_s32 tee_pvr_syscall(hi_s32 swi_id, TSK_REGS_S *regs, unsigned long long permissions)
{
    hi_s32 ret = HI_FAILURE;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_PVR, permissions, GENERAL_GROUP_PERMISSION)
            /*
             * register usage:
             * r0: cmd, r1: args
             * Note: must call ACCESS_CHECK Convert the virtual address of the api to the virtual address of drv.
             */
            hi_log_dbg("pvr_syscall regs->r0 0x%x, regs->r1 0x%x!\n", regs->r0, regs->r1);
            ACCESS_CHECK(regs->r1, sizeof(hi_tee_pvr_drv_ioctl_buf));
            ret = tee_drv_pvr_ioctl(regs->r0, (void *)regs->r1, sizeof(hi_tee_pvr_drv_ioctl_buf));
            if (ret != HI_SUCCESS) {
                hi_log_err("call pvr ioctl[cmd: 0x%x] fail: 0x%x!\n", regs->r0, ret);
                regs->r0 = ret;
            } else {
                regs->r0 = 0;
            }

            SYSCALL_END
        default:
            return -EINVAL;
    }

    return ret;
}

/* for pvr suspend and resume */
static hi_s32  tee_pvr_suspend(hi_void)
{
    return HI_SUCCESS;
}

static hi_s32 tee_pvr_resume(hi_void)
{
    return HI_SUCCESS;
}

hi_s32 pvr_drv_mod_init(hi_void)
{
    hi_info_func_enter();

    hi_tee_drv_hal_printf("load secure pvr success. build time:[%s, %s]\n", __DATE__,  __TIME__);

    hi_info_func_exit();
    return HI_SUCCESS;
}

hi_tee_drv_hal_driver_init_late(g_drv_pvr, 0, pvr_drv_mod_init, tee_pvr_syscall, tee_pvr_suspend, tee_pvr_resume);

