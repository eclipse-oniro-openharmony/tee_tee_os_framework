/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: cc driver syscall
 * Create: 2019-12
 */
#include <errno.h>
#include <crypto_syscal_types.h>
#include "sre_syscalls_ext.h"
#include "sre_syscalls_id.h"
#include "sre_access_control.h"
#include "param_check.h"
#include "drv_module.h"
#include "cc_driver_stub.h"

/* cc */
#include "dx_cclib.h"
#include "dx_util.h"
#include "crys_rnd.h"
#include "dx_cc_defs.h"
#include "cc_crypto_ctx.h"
#include <sep_ctx.h>

#include "crys_ecpki_types.h"
#include "crys_ecpki_build.h"
#include "crys_ecpki_ecdsa.h"
#include "crys_ecpki_dh.h"
#include "crys_ecpki_kg.h"
#include "cc_power.h"
#ifdef CC_ENGINE_ENABLE
#include "cc_ctr_drbg.h"
#endif

int cc_driver_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t ret;
    if (params == NULL || params->args == 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_CC_SECS_POWER_ON, permissions, CC_POWEROPER_GROUP_PERMISSION)
        ret = cc_power_on();
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_SECS_POWER_DOWN, permissions, CC_POWEROPER_GROUP_PERMISSION)
        ret = cc_power_down();
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_DX_UTIL_CMACDERIVEKEY, permissions, CC_KEY_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], sizeof(DX_UTIL_AES_CmacResult_t));
        ACCESS_WRITE_RIGHT_CHECK(args[3], sizeof(DX_UTIL_AES_CmacResult_t));
        ret = DX_UTIL_CmacDeriveKey((DX_UTIL_KeyType_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                                    (DxUint32_t)args[2], (DxUint8_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RND_GENERATEVECTOR, permissions, CC_RNG_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[0]);
        ACCESS_WRITE_RIGHT_CHECK(args[1], args[0]);
        ret = CRYS_RND_GenerateVector((DxUint16_t)args[0], (DxUint8_t *)(uintptr_t)args[1]);
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_ECPKI_BUILD_PUBLKEY, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[3], sizeof(CRYS_ECPKI_UserPublKey_t));
        ret = CRYS_ECPKI_BuildPublKey((CRYS_ECPKI_DomainID_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                                      (DxUint32_t)args[2], (CRYS_ECPKI_UserPublKey_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_ECPKI_BUILD_PRIVKEY, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_CHECK_A64(args[3], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[3], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ret = CRYS_ECPKI_BuildPrivKey((CRYS_ECPKI_DomainID_t)args[0], (DxUint8_t *)(uintptr_t)args[1],
                                      (DxUint32_t)args[2], (CRYS_ECPKI_UserPrivKey_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_ECPKI_EXPORTPUBLKEY, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_CHECK_A64(args[3], sizeof(DxUint32_t));
        ACCESS_WRITE_RIGHT_CHECK(args[3], sizeof(DxUint32_t));
        if (args[3]) {
            if (*((DxUint32_t *)(uintptr_t)args[3]) == 0) {
                printf("WARNING: CCMgr map size = 0, force set size to 1\n");
                ACCESS_CHECK_A64(args[2], sizeof(DxUint8_t));
                ACCESS_WRITE_RIGHT_CHECK(args[2], sizeof(DxUint8_t));
            } else {
                ACCESS_CHECK_A64(args[2], *((DxUint32_t *)(uintptr_t)args[3]));
                ACCESS_WRITE_RIGHT_CHECK(args[2], *((DxUint32_t *)(uintptr_t)args[3]));
            }
        }
        ret = CRYS_ECPKI_ExportPublKey((CRYS_ECPKI_UserPublKey_t *)(uintptr_t)args[0],
                                       (CRYS_ECPKI_PointCompression_t)args[1],
                                       (DxUint8_t *)(uintptr_t)args[2], (DxUint32_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_ECDH_SVDP_DH, permissions, CC_CRYPTO_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_CHECK_A64(args[1], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ACCESS_READ_RIGHT_CHECK(args[1], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ACCESS_CHECK_A64(args[3], sizeof(DxUint32_t));
        ACCESS_WRITE_RIGHT_CHECK(args[3], sizeof(DxUint32_t));
        if (args[3]) {
            ACCESS_CHECK_A64(args[2], *(DxUint32_t *)(uintptr_t)args[3]);
            ACCESS_WRITE_RIGHT_CHECK(args[2], *((DxUint32_t *)(uintptr_t)args[3]));
        }
        ACCESS_CHECK_A64(args[4], sizeof(CRYS_ECDH_TempData_t));
        ACCESS_READ_RIGHT_CHECK(args[4], sizeof(CRYS_ECDH_TempData_t));
        ret = CRYS_ECDH_SVDP_DH((CRYS_ECPKI_UserPublKey_t *)(uintptr_t)args[0],
                                (CRYS_ECPKI_UserPrivKey_t *)(uintptr_t)args[1],
                                (DxUint8_t *)(uintptr_t)args[2], (DxUint32_t *)(uintptr_t)args[3],
                                (CRYS_ECDH_TempData_t *)(uintptr_t)args[4]);
        args[0] = ret;
        SYSCALL_END_DMA;

        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_ECPKI_GENKEY_PAIR, permissions, CC_CRYPTO_GROUP_PERMISSION)
            ACCESS_CHECK_A64(args[1], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[1], sizeof(CRYS_ECPKI_UserPrivKey_t));
        ACCESS_CHECK_A64(args[2], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_WRITE_RIGHT_CHECK(args[2], sizeof(CRYS_ECPKI_UserPublKey_t));
        ACCESS_CHECK_A64(args[3], sizeof(CRYS_ECPKI_KG_TempData_t));
        ACCESS_READ_RIGHT_CHECK(args[3], sizeof(CRYS_ECPKI_KG_TempData_t));
        ret = CRYS_ECPKI_GenKeyPair((CRYS_ECPKI_DomainID_t)args[0], (CRYS_ECPKI_UserPrivKey_t *)(uintptr_t)args[1],
            (CRYS_ECPKI_UserPublKey_t *)(uintptr_t)args[2],
            (CRYS_ECPKI_KG_TempData_t *)(uintptr_t)args[3]);
        args[0] = ret;
        SYSCALL_END_DMA;

    default:
        return -1;
    }

    return 0;
}

DECLARE_TC_DRV(
    cc_syscall_init,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    cc_driver_syscall,
    NULL,
    NULL
);
