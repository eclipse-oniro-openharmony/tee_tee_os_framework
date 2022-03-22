/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: added for hm-teeos
 * Author: hanxuanwei
 * Create: 2018-05-21
 */

#include "sec_intf.h"

#include "sre_task.h"
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "mem_page_ops.h"
#include "sre_access_control.h"
#include "drv_module.h"
#include "venc_tee.h"

/* memroy description */
#include <procmgr_ext.h>  // for hm_getpid()
#include <tee_log.h>
#include <drv_pal.h>
#include <hmdrv_stub.h>
#include "drv_param_type.h"
#include "vfmw.h"

int HiVcodecSyscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
    UINT32 uwRet;

    if (params == NULL || params->args == 0) {
        return -1;
    }
    /* According to ARM AAPCS arguments from 5-> in a function call
     * are stored on the stack, which in this case is pointer by
     * user sp. Our own TrustedCore also push FP and LR on the stack
     * just before SWI, so skip them */
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_INIT, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK_A64(args[0], args[1]); // 0: Args, 1: ArgsLen
    ACCESS_READ_RIGHT_CHECK(args[0], args[1]); // 0: Args, 1: ArgsLen
    ACCESS_CHECK_A64(args[2], args[3]); // 2: phyaddrInfo, 3: infoLen
    ACCESS_READ_RIGHT_CHECK(args[2], args[3]); // 2: phyaddrInfo, 3: infoLen
    uwRet = (UINT32)SecVdecInit((unsigned int *)(uintptr_t)args[0], // 0: Args
         // 1: ArgsLen, 2: phyaddrInfo, 3: infoLen
        (unsigned int)args[1], (unsigned int *)(uintptr_t)args[2], (unsigned int)args[3]);
    args[0] = uwRet; // 0: Args
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_EXIT, permissions, VDEC_GROUP_PERMISSION)
    uwRet = (UINT32)SecVdecExit((unsigned int)args[0]); // 0: IsSecure
    args[0] = uwRet; // 0: IsSecure
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_CONTROL, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK_A64(args[2], args[3]); // 2: Args, 3: ArgLen
    ACCESS_WRITE_RIGHT_CHECK(args[2], args[3]); // 2: Args, 3: ArgLen
    ACCESS_CHECK_A64(args[4], args[5]); // 4: phyaddrInfo, 5: infoLen
    ACCESS_WRITE_RIGHT_CHECK(args[4], args[5]); // 4: phyaddrInfo, 5: infoLen
    // 0: Page_h, 1: intPage_l, 2: Count
    uwRet = (UINT32)SecVdecControl(args[0], args[1], (unsigned int *)(uintptr_t)args[2],
        args[3], (unsigned int *)(uintptr_t)args[4], args[5]); // 3: ArgLen, 4: phyaddrInfo, 5: infoLen
    args[0] = uwRet; // 0: ChanID
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_SUSPEND, permissions, VDEC_GROUP_PERMISSION)
    uwRet = (UINT32)SecVdecSuspend();
    args[0] = uwRet; // 0: param index
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_RESUME, permissions, VDEC_GROUP_PERMISSION)
    uwRet = (UINT32)SecVdecResume();
    args[0] = uwRet; // 0: param index
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_RUNPROCESS, permissions, VDEC_GROUP_PERMISSION)
    uwRet = (UINT32)SecVdecRunProcess((unsigned int)args[0], (unsigned int)args[1]); // 0: Args, 1: intArgLen
    args[0] = uwRet; // 0: Args
    SYSCALL_END

#ifdef VCODEC_ENG_VERSION
    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_READPROC, permissions, VDEC_GROUP_PERMISSION)
    // 0: Page_h, 1: intPage_l, 2: Count, 32: offset
    uwRet = (UINT32)SecVdecReadProc((((paddr_t)(args[0])) << 32) | (args[1]), (int)args[2]);
    args[0] = uwRet; // 0: Page_h
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_WRITEPROC, permissions, VDEC_GROUP_PERMISSION)
    uwRet = (UINT32)SecVdecWriteProc((unsigned int)args[0], (int)args[1]); // 0: Option 1, 1: Value
    args[0] = uwRet; // 0: Option
    SYSCALL_END
#endif

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_GETCHANIMAGE, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK_A64(args[1], sizeof(Image)); // 1: Image
    ACCESS_READ_RIGHT_CHECK(args[1], sizeof(Image)); // 1: Image
    ACCESS_WRITE_RIGHT_CHECK(args[1], sizeof(Image)); // 1: Image
    uwRet = (UINT32)SecVdecGetChanImage((int)args[0], (unsigned int *)(uintptr_t)args[1]); // 0: ChanID, 1: Image
    args[0] = uwRet; // 0: ChanID
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_RELEASECHANIMAGE, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK_A64(args[1], sizeof(Image)); // 1: Image_h
    ACCESS_READ_RIGHT_CHECK(args[1], sizeof(Image)); // 1: Image_h
    ACCESS_WRITE_RIGHT_CHECK(args[1], sizeof(Image)); // 1: Image_h
    uwRet = (UINT32)SecVdecReleaseChanImage((int)args[0], (unsigned int *)(uintptr_t)args[1]); // 0: ChanID, 1: Image_h
    args[0] = uwRet; // 0: ChanID
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_CONFIGINPUTBUFFER, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK_A64(args[1], sizeof(PHY_ADDR_INFO_S)); // 1: PhyAddr
    ACCESS_READ_RIGHT_CHECK(args[1], sizeof(UINT32)); // 1: PhyAddr
    // 0: ChanID, 1: PhyAddr
    uwRet = (UINT32)SecVdecConfigInputBuffer((int)args[0], (unsigned int *)(uintptr_t)args[1]);
    args[0] = uwRet; // 0: ChanID
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VENC_MEMREE2TEE, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK_NOCPY_A64(args[0], args[3]); // 0: reeAddr, 3: datalen
    ACCESS_READ_RIGHT_CHECK(args[0], args[3]); // 0: reeAddr, 3: datalen
    ACCESS_WRITE_RIGHT_CHECK(args[0], args[3]); // 0: reeAddr, 3: datalen
    uwRet = (int32_t)SEC_VENC_MemRee2Tee((uint32_t)args[0], (uint32_t)args[1], // 0: reeAddr, 1: sec_share_fd
        (uint32_t)args[2], (uint32_t)args[3]); // 2: offset, 3: datalen
    args[0] = uwRet; // 0: ret
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VENC_MEMTEE2REE, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK_NOCPY_A64(args[0], args[3]); // 0: reeAddr, 3: datalen
    ACCESS_READ_RIGHT_CHECK(args[0], args[3]); // 0: reeAddr, 3: datalen
    ACCESS_WRITE_RIGHT_CHECK(args[0], args[3]); // 0: reeAddr, 3: datalen
    uwRet = (int32_t)SEC_VENC_MemTee2Ree((uint32_t)args[0], (uint32_t)args[1], // 0: reeAddr, 1: sec_share_fd
        (uint32_t)args[2], (uint32_t)args[3]); // 2: offset, 3: datalen
    args[0] = uwRet; // 0: ret
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VENC_CFG_MASTER, permissions, VDEC_GROUP_PERMISSION)
    uwRet = (uint32_t)SEC_VENC_CFG_MASTER((enum SecVencState)args[0], (uint32_t)args[1]); // 0: sec venc state, 1: core_id
    args[0] = uwRet; // 0: ret
    SYSCALL_END

    default:
        return -1;
    }

    return 0;
}

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_BALTIMORE)
DECLARE_TC_DRV(
    hivcodec,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    HiVcodecSyscall,
    NULL,
    NULL
);
#endif
