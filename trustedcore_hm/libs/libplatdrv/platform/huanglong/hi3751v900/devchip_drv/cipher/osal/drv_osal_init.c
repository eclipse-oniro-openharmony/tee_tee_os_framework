/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: drivers of drv_osal_init
 * Author: cipher team
 * Create: 2019-06-18
 */
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "sre_access_control.h"
#include "hmdrv_stub.h"
#include "errno.h"
#include "drv_osal_lib.h"
#include "drv_cipher_kapi.h"
#include "drv_symc.h"
#include "cipher_drv_hash.h"
#include "hi_tee_ssm.h"
#include "drv_legacy_def.h"
#if defined(HI_CIPHER_TEST)
#include "test_main.h"
#endif

/************************* Internal Structure Definition *********************/
#define IOCTL_ARG_MAX_SIZE 0x100

TEE_Result crypto_ioctl(int cmd, void *argp);
hi_s32 crypto_entry(void);

/** @} */ /** <!-- ==== Structure Definition end ==== */

/******************************* API Code *****************************/
/** \addtogroup      link */
/** @{ */ /** <!-- [link] */

static int hi_cipher_suspend(void)
{
    drv_symc_suspend();

#ifdef CHIP_HASH_SUPPORT
    drv_hash_suspend();
#endif

    hi_log_info("Secure OS cipher suspend OK\n");

    return HI_SUCCESS;
}

static int hi_cipher_resume(void)
{
    hi_s32 ret;

    ret = drv_symc_resume();
    if (ret != HI_SUCCESS) {
        return ret;
    }

#ifdef CHIP_HASH_SUPPORT
    drv_hash_resume();
#endif

    /* call ssm module to set smmu tag id for spacc */
    ret = tee_drv_ssm_set_iommu_tag(LOGIC_MOD_ID_CIPHER);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(tee_drv_ssm_set_iommu_tag, ret);
        return ret;
    }

    hi_log_info("Secure OS cipher resume OK\n");

    return HI_SUCCESS;
}

static int hi_cipher_driver_ioctl(const unsigned int cmd, void *args)
{
    hi_u8 local[IOCTL_ARG_MAX_SIZE] = { 0 };
    hi_s32 ret;

    hi_log_check_param(IOCTL_ARG_MAX_SIZE <= CRYPTO_IOC_SIZE(cmd));

    if (0 != CRYPTO_IOC_SIZE(cmd)) {
        ret = crypto_copy_from_user(local, sizeof(local), args, CRYPTO_IOC_SIZE(cmd));
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(crypto_copy_from_user, ret);
            return ret;
        }
    }

    ret = crypto_ioctl(cmd, local);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    if (CRYPTO_IOC_DIR(cmd) & CRYPTO_IOC_R) {
        ret = crypto_copy_to_user(args, CRYPTO_IOC_SIZE(cmd), local, CRYPTO_IOC_SIZE(cmd));
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(crypto_copy_from_user, ret);
            return ret;
        }
    }

    return ret;
}

hi_s32 cipher_drv_mod_init(hi_void)
{
    hi_s32 ret;

    ret = crypto_entry();
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(crypto_entry, ret);
        return ret;
    }

    /* call ssm module to set smmu tag id for spacc */
    ret = tee_drv_ssm_set_iommu_tag(LOGIC_MOD_ID_CIPHER);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(tee_drv_ssm_set_iommu_tag, ret);
        return ret;
    }

    hi_log_info("Load Secure Cipher success. Build Time:[%s, %s]\n", __DATE__, __TIME__);

    return HI_SUCCESS;
}

static int cipher_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
    hi_void *argp = HI_NULL;
    hi_u32 addr;
    if (params == NULL || params->args == 0)
        return -1;
    uint64_t  *args = (uint64_t *)(uintptr_t)params->args;
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_CIPHER, permissions, GENERAL_GROUP_PERMISSION)
            /* register usage:
             * r0: cmd, r1: args
             *
             * Note: must call ACCESS_CHECK Convert the virtual address
             * of the api to the virtual address of drv.
             */
            hi_log_debug("cipher_syscall args[0]=0x%x, args[1]=0x%x\n", args[0], args[1]);
            argp = (hi_void *)args[1];
            args[0] = hi_cipher_driver_ioctl(args[0], (void *)args[1]);
            hi_log_debug("cipher_syscall return 0x%x\n", args[0]);
            SYSCALL_END
        default:
            return -EINVAL;
    }

    return 0;
}

hi_tee_drv_hal_driver_init(cipher, 0, cipher_drv_mod_init, cipher_syscall, hi_cipher_suspend, hi_cipher_resume);

/** @} */ /** <!-- ==== Structure Definition end ==== */
