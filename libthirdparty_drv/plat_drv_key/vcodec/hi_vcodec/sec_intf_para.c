#include "sre_task.h"
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "sre_access_control.h"
#include "sec_intf_para.h"
#include <hmdrv_stub.h>
#include "drv_module.h"
#include "drv_param_type.h"
#include "venc_tee.h"
#include "drv_pal.h"

int hivdec_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
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
    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_DRV_INIT, permissions, VDEC_GROUP_PERMISSION)
    uwRet = (UINT32)tee_vdec_drv_init((unsigned int)args[1]);
    args[0] = uwRet; // 0: Args
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_DRV_EXIT, permissions, VDEC_GROUP_PERMISSION)
    uwRet = (UINT32)tee_vdec_drv_exit(1); // EXIT_NORMAL
    args[0] = uwRet; // 0: IsSecure
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_DRV_SCD_START, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK(args[0], args[1]);
    ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
    ACCESS_CHECK(args[2], args[3]);
    ACCESS_READ_RIGHT_CHECK(args[2], args[3]);
    uwRet = (UINT32)tee_vdec_drv_scd_start((unsigned int *)(uintptr_t)args[0],
        (unsigned int)args[1], (unsigned int *)(uintptr_t)args[2], (unsigned int)args[3]);
    args[0] = uwRet;
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_DRV_IOMMU_MAP, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK(args[0], args[1]);
    ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
    ACCESS_CHECK(args[2], args[3]);
    ACCESS_WRITE_RIGHT_CHECK(args[2], args[3]);
    uwRet = (UINT32)tee_vdec_drv_iommu_map((unsigned int *)(uintptr_t)args[0], (unsigned int *)(uintptr_t)args[2]);
    args[0] = uwRet;
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_DRV_IOMMU_UNMAP, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK(args[0], args[1]);
    ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
    uwRet = (UINT32)tee_vdec_drv_iommu_unmap((unsigned int *)(uintptr_t)args[0]);
    args[0] = uwRet;
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_DRV_GET_ACTIVE_REG, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK(args[0], args[1]);
    ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
    uwRet = (UINT32)tee_vdec_drv_get_active_reg((unsigned int *)(uintptr_t)args[0], (unsigned int)args[1]);
    args[0] = uwRet;
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_DRV_DEC_START, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK(args[0], args[1]);
    ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
    uwRet = (UINT32)tee_vdec_drv_dec_start((unsigned int *)(uintptr_t)args[0], (unsigned int)args[1]);
    args[0] = uwRet;
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_DRV_IRQ_QUERY, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK(args[0], args[1]);
    ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
    ACCESS_CHECK(args[2], args[3]);
    ACCESS_READ_RIGHT_CHECK(args[2], args[3]);
    uwRet = (UINT32)tee_vdec_drv_irq_query((unsigned int *)(uintptr_t)args[0],
        (unsigned int)args[1], (unsigned int *)(uintptr_t)args[2], (unsigned int)args[3]);
    args[0] = uwRet;
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_DRV_SET_DEV_REG, permissions, VDEC_GROUP_PERMISSION)
    uwRet = (UINT32)tee_vdec_drv_set_dev_reg((unsigned int)args[0]);
    args[0] = uwRet;
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_DRV_RESUME, permissions, VDEC_GROUP_PERMISSION)
    uwRet = (UINT32)tee_vdec_drv_resume();
    args[0] = uwRet;
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VDEC_DRV_SUSPEND, permissions, VDEC_GROUP_PERMISSION)
    uwRet = (UINT32)tee_vdec_drv_suspend();
    args[0] = uwRet;
    SYSCALL_END

    default:
        return -1;
    }
    return 0;
}

int hivenc_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
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
    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VENC_MEMREE2TEE, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK_NOCPY_A64(args[0], args[3]); // 0: reeAddr, 3: datalen
    ACCESS_READ_RIGHT_CHECK(args[0], args[3]); // 0: reeAddr, 3: datalen
    ACCESS_WRITE_RIGHT_CHECK(args[0], args[3]); // 0: reeAddr, 3: datalen
    // 0: reeAddr, 1: sec_share_fd
    uwRet = (int32_t)SEC_VENC_MemRee2Tee((uint32_t)args[0], (uint32_t)args[1],
        (uint32_t)args[2], (uint32_t)args[3]); // 2: offset, 3: datalen
    args[0] = uwRet; // 0: reeAddr
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VENC_MEMTEE2REE, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK_NOCPY_A64(args[0], args[3]); // 0: reeAddr, 3: datalen
    ACCESS_READ_RIGHT_CHECK(args[0], args[3]); // 0: reeAddr, 3: datalen
    ACCESS_WRITE_RIGHT_CHECK(args[0], args[3]); // 0: reeAddr, 3: datalen
    uwRet = (int32_t)SEC_VENC_MemTee2Ree((uint32_t)args[0], (uint32_t)args[1], // 0: reeAddr, 1: sec_share_fd
        (uint32_t)args[2], (uint32_t)args[3]); // 2: offset, 3: datalen
    args[0] = uwRet; // 0: reeAddr

    SYSCALL_END
    SYSCALL_PERMISSION(SW_SYSCALL_SEC_VENC_CFG_MASTER, permissions, VDEC_GROUP_PERMISSION)
    ACCESS_CHECK_NOCPY_A64(args[0], args[1]); // 0: baseAddr, 1: size
    ACCESS_READ_RIGHT_CHECK(args[0], args[1]); // 0: baseAddr, 1: size
    ACCESS_WRITE_RIGHT_CHECK(args[0], args[1]); // 0: baseAddr, 1: size
    uwRet = (uint32_t)SEC_VENC_CFG_MASTER((enum SecVencState)args[0], (uint32_t)args[1]); // 0: baseAddr, 1: size
    args[0] = uwRet; // 0: baseAddr
    SYSCALL_END

    default:
        return -1;
    }
    return 0;
}

int hivcodec_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
    if (hivdec_syscall(swi_id, params, permissions) != 0 &&
        hivenc_syscall(swi_id, params, permissions) != 0) {
        return -1;
    }

    return 0;
}

DECLARE_TC_DRV(
    hivcodec,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    hivcodec_syscall,
    NULL,
    NULL
);
