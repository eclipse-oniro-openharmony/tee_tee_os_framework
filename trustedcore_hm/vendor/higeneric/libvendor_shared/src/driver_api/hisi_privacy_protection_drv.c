/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: privacy data protection api syscall interface, call tee drvier api
 * Create: 2020-03-10
 */

#include "hisi_privacy_protection_drv.h"
#include "hmdrv.h"
#include "mem_page_ops.h"
#include <sre_syscalls_id_ext.h>

uint32_t __mspe_poweron(uint32_t cmd, uint32_t id, uint32_t profile)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)id,
                        (uint64_t)profile,
    };

    return hm_drv_call(SW_PRIP_POWERON, args, ARRAY_SIZE(args));
}

uint32_t __mspe_poweroff(uint32_t cmd, uint32_t id, uint32_t profile)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)id,
                        (uint64_t)profile,
    };

    return hm_drv_call(SW_PRIP_POWEROFF, args, ARRAY_SIZE(args));
}

uint32_t __mspe_rnd_gen_trnd(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_RNG_GEN_TRND, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm2_gen_key(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM2_GEN_KEY, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm2_encrypt(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM2_ENCRYPT, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm2_decrypt(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM2_DECRYPT, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm3_hash_init(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM3_HASH_INIT, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm3_hash_update(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM3_HASH_UPDATE, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm3_hash_dofinal(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM3_HASH_DOFINAL, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm3_hash_sigle(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM3_HASH_SIGLE, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm4_set_key(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM4_SET_KEY, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm4_set_iv(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM4_SET_IV, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm4_init(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM4_INIT, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm4_update(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM4_UDATE, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm4_dofinal(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM4_DOFINAL, args, ARRAY_SIZE(args));
}

uint32_t __mspe_km_derive_kdr(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_KM_DERIVE_KDR, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm9_sign(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM9_SIGN, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm9_verify(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM9_VERIFY, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm9_wrap_key(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM9_WRAP_KEY, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm9_unwrap_key(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM9_UNWRAP_KEY, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm9_encrypt(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM9_ENCRYPT, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm9_decrypt(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM9_DECRYPT, args, ARRAY_SIZE(args));
}

uint32_t __mspe_sm9_pre_data(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen)
{
    uint64_t args[] = { (uint64_t)cmd,
                        (uint64_t)(uintptr_t)sendbuf,
                        (uint64_t)sendlen,
    };

    return hm_drv_call(SW_PRIP_SM9_PRE_DATA, args, ARRAY_SIZE(args));
}
