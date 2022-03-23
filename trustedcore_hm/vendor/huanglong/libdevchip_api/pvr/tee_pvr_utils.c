/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee pvr utils
 */

#define TA_DEBUG
#include "tee_pvr.h"
#include "hi_tee_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_module_id.h"
#include "tee_pvr_utils.h"

hi_s32 __tee_pvr_ioctl(unsigned long cmd, const hi_void *pri_args)
{
    unsigned int args[] = {
        (unsigned long)cmd,
        (uintptr_t)pri_args,
    };

    return hm_drv_call(HI_TEE_SYSCALL_PVR, args, ARRAY_SIZE(args));
}

/* copy ts data from ree to tee. This API is defined for playback */
hi_s32 tee_pvr_play_copy_from_ree(hi_u32 tsbuf, hi_mem_handle ns_addr_handle,
    hi_mem_handle sec_addr_handle, hi_u32 data_len)
{
    hi_s32 ret;
    hi_tee_pvr_drv_ioctl_buf buf_para = {0};

    hi_info_func_enter();

    hi_dbg_print_u32(tsbuf);
    hi_dbg_print_u64(ns_addr_handle.mem_handle);
    hi_dbg_print_u64(sec_addr_handle.mem_handle);
    hi_dbg_print_u64(ns_addr_handle.addr_offset);
    hi_dbg_print_u64(sec_addr_handle.addr_offset);
    hi_dbg_print_u32(data_len);

    /* this check is done in order to prevent large data is copyed to tee */
    if (data_len > TEE_PVR_MAX_BUF_LENGTH) {
        hi_warn_print_info("the data length is too long\n");
        hi_warn_print_u32(data_len);
        hi_warn_print_u32(TEE_PVR_MAX_BUF_LENGTH);
        hi_err_print_err_code(HI_TEE_ERROR_PVR_INVALID_PARAM);
        return HI_TEE_ERROR_PVR_INVALID_PARAM;
    }

    /* no ability of memory mapping, so the copy is done in kernel */
    buf_para.ns_addr_handle = ns_addr_handle;
    buf_para.sec_addr_handle = sec_addr_handle;
    buf_para.data_len = data_len;
    buf_para.ch = tsbuf;
    ret = __tee_pvr_ioctl(TEE_DRV_PVR_PLAYCOPYTOTEE, (hi_void *)&buf_para);
    if (ret != HI_SUCCESS) {
        hi_warn_print_info("copy ts data from ree failed\n");
        hi_err_print_err_code(ret);
        return ret;
    }

    hi_info_func_exit();
    return HI_SUCCESS;
}

/*
 * adjust ts data in order to send one whole frame(aligned by ts packet) to demux. This API is defined for FF/FB play
 * Input: the addr of tsbuffer, the length info for tsbuffer, head, end
 */
hi_s32 tee_pvr_play_proc_ts_data(hi_mem_handle sec_addr_handle,
    hi_u32 head_offset, hi_u32 end_offset, hi_u32 head_add, hi_u32 end_add)
{
    hi_s32 ret;
    hi_tee_pvr_drv_ioctl_buf buf_para = {0};

    hi_info_func_enter();

    hi_dbg_print_u64(sec_addr_handle.mem_handle);
    hi_dbg_print_u64(sec_addr_handle.addr_offset);
    hi_dbg_print_u32(head_offset);
    hi_dbg_print_u32(end_offset);
    hi_dbg_print_u32(head_add);
    hi_dbg_print_u32(end_add);

    buf_para.sec_addr_handle = sec_addr_handle;
    buf_para.head_offset = head_offset;
    buf_para.end_offset = end_offset;
    buf_para.head_add = head_add;
    buf_para.end_add = end_add;
    ret = __tee_pvr_ioctl(TEE_DRV_PVR_PLAYPROCTSDATA, (hi_void *)&buf_para);
    if (ret != HI_SUCCESS) {
        hi_warn_print_info("Process ts data failed\n");
        hi_err_print_err_code(ret);
        return ret;
    }

    hi_info_func_exit();
    return HI_SUCCESS;
}

