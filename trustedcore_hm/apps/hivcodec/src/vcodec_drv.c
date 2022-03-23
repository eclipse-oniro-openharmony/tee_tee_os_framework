/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Author: h00424236
 * Create: 2019-05-08
 * Description: VDEC driver interface.
 */

#include <stdint.h>
#include <hmdrv.h>
#include <sre_syscalls_id_ext.h>
#include <timer_export.h>

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI6250)
#define VCTRL_ERR_HW_BUSY 10
#define HW_BUSY_TIMEOUT_COUNT 510

int __SEC_VDEC_Init(unsigned int *Args, unsigned int ArgsLen, unsigned int *phyaddrInfo, unsigned int infoLen)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)Args, /* Not support 64bit TA now */
        (uint64_t)ArgsLen,
        (uint64_t)(uintptr_t)phyaddrInfo, /* Not support 64bit TA now */
        (uint64_t)infoLen
    };

    return hm_drv_call(SW_SYSCALL_SEC_VDEC_INIT, args, ARRAY_SIZE(args));
}

int __SEC_VDEC_Exit(unsigned int IsSecure)
{
    uint64_t args[] = {
        (uint64_t)IsSecure
    };

    return hm_drv_call(SW_SYSCALL_SEC_VDEC_EXIT, args, ARRAY_SIZE(args));
}

int __SEC_VDEC_Suspend(void)
{
    uint64_t args[1] = {0};
    return hm_drv_call(SW_SYSCALL_SEC_VDEC_SUSPEND, args, ARRAY_SIZE(args));
}

int __SEC_VDEC_Resume(void)
{
    uint64_t args[1] = {0};
    return hm_drv_call(SW_SYSCALL_SEC_VDEC_RESUME, args, ARRAY_SIZE(args));
}

int __SEC_VDEC_RunProcess(unsigned int Args, unsigned intArgLen)
{
    uint64_t args[] = {
        (uint64_t)Args,
        (uint64_t)intArgLen
    };
    uint32_t waitTimeoutCnt = 0;
    int ret = 0;
    ret = hm_drv_call(SW_SYSCALL_SEC_VDEC_RUNPROCESS, args, ARRAY_SIZE(args));
    while ((ret == VCTRL_ERR_HW_BUSY) && (waitTimeoutCnt < HW_BUSY_TIMEOUT_COUNT)) {
        __SRE_SwMsleep(2);
        args[0] = ret;
        ret = hm_drv_call(SW_SYSCALL_SEC_VDEC_RUNPROCESS, args, ARRAY_SIZE(args));
        waitTimeoutCnt++;
    }
    return ret;
}

int __SEC_VENC_MEMREE2TEE(unsigned int reeAddr, unsigned int sec_share_fd, unsigned int offset, unsigned int datalen)
{
    uint64_t args[] = {
        (uint64_t)reeAddr,
        (uint64_t)sec_share_fd,
        (uint64_t)offset,
        (uint64_t)datalen
    };
    return hm_drv_call(SW_SYSCALL_SEC_VENC_MEMREE2TEE, args, ARRAY_SIZE(args));
}

int __SEC_VENC_MEMTEE2REE(unsigned int reeAddr, unsigned int sec_share_fd, unsigned int offset, unsigned int datalen)
{
    uint64_t args[] = {
        (uint64_t)reeAddr,
        (uint64_t)sec_share_fd,
        (uint64_t)offset,
        (uint64_t)datalen
    };
    return hm_drv_call(SW_SYSCALL_SEC_VENC_MEMTEE2REE, args, ARRAY_SIZE(args));
}

int __SEC_VENC_CFG_MASTER(unsigned int secVencState, unsigned int coreId)
{
    uint64_t args[] = {
        (uint64_t)secVencState,
        (uint64_t)coreId,
    };
    return hm_drv_call(SW_SYSCALL_SEC_VENC_CFG_MASTER, args, ARRAY_SIZE(args));
}

#ifdef VCODEC_ENG_VERSION
int __SEC_VDEC_ReadProc(unsigned int Page_h, unsigned intPage_l, int Count)
{
    uint64_t args[] = {
        (uint64_t)Page_h,
        (uint64_t)intPage_l,
        (uint64_t)Count
    };

    return hm_drv_call(SW_SYSCALL_SEC_VDEC_READPROC, args, ARRAY_SIZE(args));
}

int __SEC_VDEC_WriteProc(unsigned int Option, int Value)
{
    uint64_t args[] = {
        (uint64_t)Option,
        (uint64_t)Value
    };

    return hm_drv_call(SW_SYSCALL_SEC_VDEC_WRITEPROC, args, ARRAY_SIZE(args));
}
#endif

int __SEC_VDEC_GetChanImage(int ChanID, unsigned int *Image)
{
    uint64_t args[] = {
        (uint64_t)ChanID,
        (uint64_t)(uintptr_t)Image /* Not support 64bit TA now */
    };

    return hm_drv_call(SW_SYSCALL_SEC_VDEC_GETCHANIMAGE, args, ARRAY_SIZE(args));
}

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660)
int __SEC_VDEC_Control(int ChanID, unsigned int eCmdID, unsigned int *Args, unsigned int ArgLen)
{
    uint64_t args[] = {
        (uint64_t)ChanID,
        (uint64_t)eCmdID,
        (uint64_t)Args,
        (uint64_t)ArgLen
    };

    return hm_drv_call(SW_SYSCALL_SEC_VDEC_CONTROL, args, ARRAY_SIZE(args));
}

int __SEC_VDEC_ReleaseChanImage(int ChanID, unsigned int Image_h, unsigned int Image_l)
{
    uint64_t args[] = {
        (uint64_t)ChanID,
        (uint64_t)Image_h,
        (uint64_t)Image_l
    };

    return hm_drv_call(SW_SYSCALL_SEC_VDEC_RELEASECHANIMAGE, args, ARRAY_SIZE(args));
}

#else
int __SEC_VDEC_Control(int ChanID, unsigned int eCmdID, unsigned int *Args, unsigned int ArgLen,
                       unsigned int *phyaddrInfo, unsigned int infoLen)
{
    uint64_t args[] = {
        (uint64_t)ChanID,
        (uint64_t)eCmdID,
        (uint64_t)(uintptr_t)Args, /* Not support 64bit TA now */
        (uint64_t)ArgLen,
        (uint64_t)(uintptr_t)phyaddrInfo, /* Not support 64bit TA now */
        (uint64_t)infoLen
    };

    return hm_drv_call(SW_SYSCALL_SEC_VDEC_CONTROL, args, ARRAY_SIZE(args));
}

int __SEC_VDEC_ReleaseChanImage(int ChanID, unsigned int *Image)
{
    uint64_t args[] = {
        (uint64_t)ChanID,
        (uint64_t)(uintptr_t)Image /* Not support 64bit TA now */
    };

    return hm_drv_call(SW_SYSCALL_SEC_VDEC_RELEASECHANIMAGE, args, ARRAY_SIZE(args));
}

int __SEC_VDEC_ConfigInputBuffer(int ChanID, unsigned int *PhyAddr)
{
    uint64_t args[] = {
        (uint64_t)ChanID,
        (uint64_t)(uintptr_t)PhyAddr /* Not support 64bit TA now */
    };

    return hm_drv_call(SW_SYSCALL_SEC_VDEC_CONFIGINPUTBUFFER, args, ARRAY_SIZE(args));
}
#endif
#endif
