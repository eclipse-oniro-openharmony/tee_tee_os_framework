/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: TA sevice for privacydata protection
 * Create: 2020-03-01
 */

#include "privacy_protection_common.h"
#include <sre_syscalls_id_ext.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <secure_gic_common.h>
#include <drv_pal.h>
#include <hmdrv_stub.h>
#include <drv_module.h>
#include <sre_errno.h>
#include <pthread.h>
#include <securec.h>
#include "drv_param_type.h"

#define SET_BUFS_AUTHORITY(x) do { \
    ACCESS_CHECK_A64(args[1], args[2]); \
    prip_params = (struct prip_drv_param *)(uintptr_t)args[1]; \
    for (buf_index = 0; buf_index < (x); buf_index++) { \
        if (prip_params->buf[buf_index].pdata) { \
            ACCESS_CHECK_A64(prip_params->buf[buf_index].pdata, prip_params->buf[buf_index].size); \
            ACCESS_WRITE_RIGHT_CHECK(prip_params->buf[buf_index].pdata, prip_params->buf[buf_index].size); \
        } \
    } \
} while (0)

static int32_t privacy_protection_init(void)
{
    tloge("PRIP: privacy protection init success!\n");
    return 0;
}

static int32_t privacy_protection_suspend(void)
{
    tloge("PRIP: suspend+\n");
    tloge("PRIP: suspend-\n");
    return 0;
}

static int32_t privacy_protection_resume(void)
{
    tloge("PRIP: resume+\n");
    tloge("PRIP: resume-\n");
    return 0;
}

int32_t privacy_protection_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t uw_ret;
    struct prip_drv_param *prip_params = NULL;
    uint32_t buf_index;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    /*
     * According to ARM AAPCS arguments from 5-> in a function call
     * are stored on the stack, which in this case is pointer by
     * user sp. Our own TrustedCore also push FP and LR on the stack
     * just before SWI, so skip them
     */
    HANDLE_SYSCALL(swi_id) {
    /* power on */
    SYSCALL_PERMISSION(SW_PRIP_POWERON, permissions, PRIP_GROUP_PERMISSION)
    uw_ret = mspe_poweron((uint32_t)args[0], (uint32_t)args[1], (uint32_t)args[2]);  /* 2: args param 2 */
    args[0] = uw_ret;
    SYSCALL_END

    /* power off */
    SYSCALL_PERMISSION(SW_PRIP_POWEROFF, permissions, PRIP_GROUP_PERMISSION)
    uw_ret = mspe_poweroff((uint32_t)args[0], (uint32_t)args[1], (uint32_t)args[2]);  /* 2: args param 2 */
    args[0] = uw_ret;
    SYSCALL_END

    /* gen trnd */
    SYSCALL_PERMISSION(SW_PRIP_RNG_GEN_TRND, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID1);
    uw_ret = mspe_rnd_gen_trnd((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* get sm2 key */
    SYSCALL_PERMISSION(SW_PRIP_SM2_GEN_KEY, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID3);
    uw_ret = mspe_sm2_gen_key((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* get sm2 encrypt */
    SYSCALL_PERMISSION(SW_PRIP_SM2_ENCRYPT, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID5);
    uw_ret = mspe_sm2_encrypt((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* get sm2 decrypt */
    SYSCALL_PERMISSION(SW_PRIP_SM2_DECRYPT, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID4);
    uw_ret = mspe_sm2_decrypt((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* get sm3 hash init */
    SYSCALL_PERMISSION(SW_PRIP_SM3_HASH_INIT, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID1);
    uw_ret = mspe_sm3_hash_init((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* get sm3 hash update */
    SYSCALL_PERMISSION(SW_PRIP_SM3_HASH_UPDATE, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID2);
    uw_ret = mspe_sm3_hash_update((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* get sm3 hash dofinal */
    SYSCALL_PERMISSION(SW_PRIP_SM3_HASH_DOFINAL, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID4);
    uw_ret = mspe_sm3_hash_dofinal((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* get sm3 hash single */
    SYSCALL_PERMISSION(SW_PRIP_SM3_HASH_SIGLE, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID3);
    uw_ret = mspe_sm3_hash_sigle((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* get sm4 set key */
    SYSCALL_PERMISSION(SW_PRIP_SM4_SET_KEY, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID2);
    uw_ret = mspe_sm4_set_key((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* get sm4 set iv */
    SYSCALL_PERMISSION(SW_PRIP_SM4_SET_IV, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID2);
    uw_ret = mspe_sm4_set_iv((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* get sm4 init */
    SYSCALL_PERMISSION(SW_PRIP_SM4_INIT, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID1);
    uw_ret = mspe_sm4_init((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* get sm4 update */
    SYSCALL_PERMISSION(SW_PRIP_SM4_UDATE, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID4);
    uw_ret = mspe_sm4_update((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* get sm4 dofinal */
    SYSCALL_PERMISSION(SW_PRIP_SM4_DOFINAL, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID4);
    uw_ret = mspe_sm4_dofinal((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* km derive key */
    SYSCALL_PERMISSION(SW_PRIP_KM_DERIVE_KDR, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID3);
    uw_ret = mspe_km_derive_kdr((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* sm9 sign */
    SYSCALL_PERMISSION(SW_PRIP_SM9_SIGN, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID6);
    uw_ret = mspe_sm9_sign((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* sm9 verify */
    SYSCALL_PERMISSION(SW_PRIP_SM9_VERIFY, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID5);
    uw_ret = mspe_sm9_verify((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* sm9 encrypt */
    SYSCALL_PERMISSION(SW_PRIP_SM9_ENCRYPT, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID7);
    uw_ret = mspe_sm9_encrypt((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* sm9 decrypt */
    SYSCALL_PERMISSION(SW_PRIP_SM9_DECRYPT, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID6);
    uw_ret = mspe_sm9_decrypt((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* sm9 wrap key */
    SYSCALL_PERMISSION(SW_PRIP_SM9_WRAP_KEY, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID6);
    uw_ret = mspe_sm9_wrap_key((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* sm9 unwrap key */
    SYSCALL_PERMISSION(SW_PRIP_SM9_UNWRAP_KEY, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID4);
    uw_ret = mspe_sm9_unwrap_key((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    /* sm9 pre data */
    SYSCALL_PERMISSION(SW_PRIP_SM9_PRE_DATA, permissions, PRIP_GROUP_PERMISSION)
    SET_BUFS_AUTHORITY(ID3);
    uw_ret = mspe_sm9_pre_data((uint32_t)args[0], (struct prip_drv_param *)(uintptr_t)args[1]);
    args[0] = uw_ret;
    SYSCALL_END

    default :
        return -1;
    }
    return 0;
}

/* declare privacy protection module */
DECLARE_TC_DRV(
    privacy_protection_driver,       /* name      */
    0,                               /* reserved1 */
    0,                               /* reserved2 */
    0,                               /* reserved3 */
    TC_DRV_MODULE_INIT,              /* priority  */
    privacy_protection_init,         /* init      */
    NULL,                            /* handle    */
    privacy_protection_syscall,      /* syscall   */
    privacy_protection_suspend,      /* suspend   */
    privacy_protection_resume        /* resume    */
);

