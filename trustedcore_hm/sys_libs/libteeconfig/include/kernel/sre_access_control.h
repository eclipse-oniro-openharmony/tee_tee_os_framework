/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: sre access control implementation
 * Create: 2018-05-06
 */
#ifndef __SRE_ACCESS_CONTROL_ID_H_
#define __SRE_ACCESS_CONTROL_ID_H_

#include <uidgid.h>
#include <stdint.h>

#ifdef SRE_AUDIT
extern void audit_syscall_perm_failure(int32_t swi_id, uint64_t permission, uid_t uid);
#endif

#define HANDLE_SYSCALL(swi_id) switch (swi_id)

#ifdef SRE_AUDIT
#define SYSCALL_PERMISSION(swi_id, current_permissions, permission) \
    case swi_id: {                                                  \
        uint64_t ullNeedPermission = permission;                      \
        if ((permission & current_permissions) == permission) {
#define SYSCALL_END                                                                                                  \
    break;                                                                                                           \
    }                                                                                                                \
    else                                                                                                             \
    {                                                                                                                \
        regs->r0 = OS_ERROR;                                                                                         \
        uart_printf_func(                                                                                            \
            "[ERROR!!!] permission denied to access swi_id 0x%x, please check sre_syscalls_id.h to get more info\n", \
            swi_id);                                                                                                 \
        audit_syscall_perm_failure(swi_id, ullNeedPermission, regs->r11);                                            \
        break;                                                                                                       \
    }                                                                                                                \
    }
#else
#define SYSCALL_PERMISSION(swi_id, current_permissions, permission) \
    case swi_id: {                                                  \
        if ((permission & current_permissions) == permission) {
#define SYSCALL_END                                                                                                  \
    break;                                                                                                           \
    }                                                                                                                \
    else                                                                                                             \
    {                                                                                                                \
        regs->r0 = OS_ERROR;                                                                                         \
        uart_printf_func(                                                                                            \
            "[ERROR!!!] permission denied to access swi_id 0x%x, please check sre_syscalls_id.h to get more info\n", \
            swi_id);                                                                                                 \
        break;                                                                                                       \
    }                                                                                                                \
    }
#endif

/* General TA group, all user space apps are allowed */
#define GENERAL_GROUP_PERMISSION 0x00000LL
/* Console initialization */
#define RESERVED1_GROUP_PERMISSION 0x00001LL
/* SMC call permissions */
#define SMC_GROUP_PERMISSION 0x00002LL
/* Memory mapping permissions */
#define RESERVED2_GROUP_PERMISSION 0x00004LL
/* Task manipulation permissions */
#define TASK_GROUP_PERMISSION 0x00008LL
/* Memory permissions */
#define RESERVED3_GROUP_PERMISSION 0x00010LL
/* Kernel variables permissions */
#define RESERVED4_GROUP_PERMISSION 0x00020LL
/* SWI permissions */
#define RESERVED5_GROUP_PERMISSION 0x00040LL
/* HWI permissions */
#define RESERVED6_GROUP_PERMISSION 0x00080LL
/* Real time clock(RTC) permissions */
#define RESERVED7_GROUP_PERMISSION 0x00100LL
/* Crypto cell management OPS permissions */
#define CC_OPS_GROUP_PERMISSION 0x00200LL
/* Crypto derive key operations */
#define CC_KEY_GROUP_PERMISSION 0x00400LL

/* CC power on or power down operation */
#define CC_POWEROPER_GROUP_PERMISSION 0x00800LL

/* Crypto cell crypto operations */
#define CC_CRYPTO_GROUP_PERMISSION GENERAL_GROUP_PERMISSION

/* Crypto cell RNG operations */
#define CC_RNG_GROUP_PERMISSION GENERAL_GROUP_PERMISSION

/* OEM KEY_operations */
#define OEM_KEY_GROUP_PERMISSION 0x02000LL

/* Crypto cell OEM unpack operations */
#define CC_OEM_KEY_GROUP_PERMISSION OEM_KEY_GROUP_PERMISSION

/* HDCP driver operations */
#define HDCP_GROUP_PERMISSION 0x04000LL

/* KM ROT operations */
#define RESERVED8_ROT_GROUP_PERMISSION 0x08000LL

/* TZASC operations */
#define TZASC_GROUP_PERMISSION 0x10000LL
/* Secboot operations */
#define SECBOOT_GROUP_PERMISSION 0x20000LL
/* IPI operations */
#define RESERVED9_GROUP_PERMISSION 0x40000LL

/* EFUSE operations */
#define EFUSE_GROUP_PERMISSION 0x80000LL

/* timer operations */
#define TIMER_GROUP_PERMISSION 0x100000LL
/* hwi msg operations */
#define HWIMSG_GROUP_PERMISSION 0x200000LL

/* ANTI ROOT */
#define ROOTSTATUS_GROUP_PERMISSION 0x1000000LL

/* SE communication operations */
#define SE_GROUP_PERMISSION 0x4000000LL

/* SE communication operations */
#define GENERIC_SE_GROUP_PERMISSION 0x8000000LL

/* fingerprint sensor operations */
#define FP_GROUP_PERMISSION 0x10000000LL
/* vsim operations */
#define VSIM_GROUP_PERMISSION 0x40000000LL

/* vdec operations */
#define VDEC_GROUP_PERMISSION 0x80000000LL

/* modem call operations */
#define MDMCALL_GROUP_PERMISSION 0x100000000LL

/* iris operations */
#define IRIS_GROUP_PERMISSION 0x200000000LL

/* Reserved operations */
/* All new syscalls use this permissions */
#define SECMEM_GROUP_PERMISSION 0x400000000LL

/* hdcp operation */
#define DPHDCP_GROUP_PERMISSION 0x800000000LL

/* cfc operation */
#define RESERVED11_GROUP_PERMISSION 0x1000000000LL

#define FR_GROUP_PERMISSION 0x2000000000LL

/* file encryption operation */
#define FILE_ENCRY_GROUP_PERMISSION 0x8000000000LL

#define DYNAMIC_ION_PERMISSION 0x10000000000LL

/* gatekeeper sys cal */
#define GATEKEEPER_GROUP_PERMISSION 0x20000000000LL

#define AI_GROUP_PERMISSION 0x40000000000LL

/* Reserved operations */
/* All new syscalls use this permissions */
#define RESERVED_GROUP_PERMISSION 0x80000000000LL

#define PERMSRV_GROUP_PERMISSION 0x100000000000LL

#define CRYPTO_ENHANCE_GROUP_PERMISSION 0x200000000000LL
/* MSP_TA_CHANNEL used in baltimore and future release */
#define MSP_CHAN_GROUP_PERMISSION HIEPS_GROUP_PERMISSION

/* ISP */
#define ISP_GROUP_PERMISSION 0x400000000000LL

/* IVP 1 << 54 */
#define IVP_GROUP_PERMISSION  0x40000000000000LL

/* NPU */
#define NPU_GROUP_PERMISSION    0x800000000000LL

/* SECFLASH */
#define SECFLASH_GROUP_PERMISSION    0x1000000000000LL

/* SE status operations */
#define SE_STATUS_GROUP_PERMISSION 0x2000000000000LL

/* Root of Trust */
#define ROT_GROUP_PERMISSION         0x4000000000000LL

/* MSPC */
#define MSPC_GROUP_PERMISSION      0x8000000000000LL

/* seplat used the same permission group as mspc. */
#define SEPLAT_GROUP_PERMISSION      MSPC_GROUP_PERMISSION

/* privacy protection */
#define PRIP_GROUP_PERMISSION      0x20000000000000LL

/* BIOMETRIC */
#define BIOMETRIC_GROUP_PERMISSION    0x8000000000000LL

/* 1<<53 */
#define MSPE_VIDEO_GROUP_PERMISSION 0x10000000000000LL

/* tpm */
#define TPM_GROUP_PERMISSION 0x80000000000000LL

#define DIM_GROUP_PERMISSION 0x100000000000000LL

/* get cert and key permission */
#define CERT_KEY_GROUP_PERMISSION 0x200000000000000LL

#define KEY_FACTOR_GROUP_PERMISSION 0x400000000000000LL

#ifdef TEE_SUPPORT_HSM
#define HSM_GROUP_PERMISSION 0x800000000000000LL

#define HSM_EFUSE_GROUP_PERMISSION 0x1000000000000000LL

#define FLASH_GROUP_PERMISSION 0x1000L
#endif

#define SECFLASH_GENERIC_PERMISSION 0x2000000000000000LL
#define SECFLASH_SPECIFIC_PERMISSION 0x4000000000000000LL
/* Access for all functions - ATTN this is reserved for global task
 * and other test tasks */
#define ALL_GROUP_PERMISSION ((uint64_t) - 1)
#define GT_PERMISSIONS (TASK_GROUP_PERMISSION | OEM_KEY_GROUP_PERMISSION | DYNAMIC_ION_PERMISSION)

#if defined(TESTSUITE_RTOSck_UT) || defined(TESTSUITE_RTOSck_PT) || \
    defined(TESTSUITE_RTOSck_IT) // set no mem access isolation when run testsuite
#endif
#endif
