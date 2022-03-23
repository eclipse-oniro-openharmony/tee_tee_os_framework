/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: driver to get taload key.
 * Author: BSP group
 * Create: 2020-01-17
 */

#include "tee_drv_taload.h"

#include "tee_drv_taload_ioctl.h"
#include "tee_drv_os_hal.h"
#include "drv_legacy_def.h"
#include "hi_tee_errcode.h"

static hi_s32 taload_get_tee_ext_pub_key(taload_rsa_key *rsa_key)
{
    tee_ca_key *ca_key = HI_NULL_PTR;
    void *virt_addr = HI_NULL_PTR;
    hi_s32 ret;

    virt_addr = hi_tee_drv_hal_remap(TEE_CA_KEY_ADDRESS, TEE_CA_KEY_SIZE, TEE_SECURE_DDR, TEE_NON_CACHE);
    if (virt_addr == HI_NULL_PTR) {
        hi_error_taload("hi_tee_drv_hal_remap failed\n");
        return HI_TEE_ERR_MEM;
    }
    ca_key = (tee_ca_key *)virt_addr;
    ret = memcpy_s(rsa_key->rsa_key_e, TALOAD_RSA_PUBLIC_KEY_E_LEN, ca_key->ext_pub_key_e, TALOAD_RSA_PUBLIC_KEY_E_LEN);
    if (ret != HI_SUCCESS) {
        hi_tee_drv_hal_unmap(virt_addr, TEE_CA_KEY_SIZE);
        hi_error_taload("memcpy_s failed\n");
        return HI_TEE_ERR_MEM;
    }

    ret = memcpy_s(rsa_key->rsa_key_n, TALOAD_RSA_PUBLIC_KEY_N_LEN, ca_key->ext_pub_key_n, TALOAD_RSA_PUBLIC_KEY_N_LEN);
    if (ret != HI_SUCCESS) {
        hi_error_taload("memcpy_s failed\n");
        hi_tee_drv_hal_unmap(virt_addr, TEE_CA_KEY_SIZE);
        return HI_TEE_ERR_MEM;
    }
    hi_tee_drv_hal_unmap(virt_addr, TEE_CA_KEY_SIZE);

    return ret;
}

static hi_s32 taload_get_tee_root_pub_key(taload_rsa_key *rsa_key)
{
    tee_key *key = HI_NULL_PTR;
    hi_s32 ret;
    void *virt_addr = HI_NULL_PTR;

    virt_addr = hi_tee_drv_hal_remap(TEE_KEY_ADDRESS, TEE_KEY_SIZE, TEE_SECURE_DDR, TEE_NON_CACHE);
    if (virt_addr == HI_NULL_PTR) {
        hi_error_taload("hi_tee_drv_hal_remap in failed\n");
        return HI_TEE_ERR_MEM;
    }

    key = (tee_key *)virt_addr;
    ret = memcpy_s(rsa_key->rsa_key_e, TALOAD_RSA_PUBLIC_KEY_E_LEN, key->hisi_tee_root_pub_key_e,
        TALOAD_RSA_PUBLIC_KEY_E_LEN);
    if (ret != HI_SUCCESS) {
        hi_tee_drv_hal_unmap(virt_addr, TEE_KEY_SIZE);
        hi_error_taload("memcpy_s failed\n");
        return HI_TEE_ERR_MEM;
    }

    ret = memcpy_s(rsa_key->rsa_key_n, TALOAD_RSA_PUBLIC_KEY_N_LEN, key->hisi_tee_root_pub_key_n,
        TALOAD_RSA_PUBLIC_KEY_N_LEN);
    if (ret != HI_SUCCESS) {
        hi_tee_drv_hal_unmap(virt_addr, TEE_KEY_SIZE);
        hi_error_taload("memcpy_s failed\n");
        return HI_TEE_ERR_MEM;
    }
    hi_tee_drv_hal_unmap(virt_addr, TEE_KEY_SIZE);

    return HI_SUCCESS;
}

static hi_s32 taload_get_tarootcert_double_sign(hi_u32 *value)
{
    tee_ca_key *ca_key = HI_NULL_PTR;
    void *virt_addr = HI_NULL_PTR;

    virt_addr = hi_tee_drv_hal_remap(TEE_CA_KEY_ADDRESS, TEE_CA_KEY_SIZE, TEE_SECURE_DDR, TEE_NON_CACHE);
    if (virt_addr != HI_NULL_PTR) {
        hi_error_taload("hi_tee_drv_hal_remap failed\n");
        return HI_FAILURE;
    }
    ca_key = (tee_ca_key *)virt_addr;
    *value = ca_key->ta_rootcert_double_sign_en;

    hi_tee_drv_hal_unmap(virt_addr, TEE_CA_KEY_SIZE);

    return HI_SUCCESS;
}

static hi_s32 tee_drv_taload_ioctl(const unsigned int cmd, hi_void *args)
{
    hi_s32 ret = HI_FAILURE;

    switch (cmd) {
        case TALOAD_IOCTL_GET_ROOT_PUB_KEY: {
            taload_rsa_key *key = (taload_rsa_key *)args;
            ret = taload_get_tee_root_pub_key(key);
            if (ret != HI_SUCCESS) {
                hi_error_taload("taload_get_tee_ext_pub_key failed!\n");
            }
            break;
        }
        case TALOAD_IOCTL_GET_EXT_PUB_KEY: {
            taload_rsa_key *key = (taload_rsa_key *)args;
            ret = taload_get_tee_ext_pub_key(key);
            if (ret != HI_SUCCESS) {
                hi_error_taload("taload_get_tee_ext_pub_key failed!\n");
            }
            break;
        }
        case TALOAD_IOCTL_GET_TAROOTCERT_DOUBLEL_SIGN: {
            hi_u32 *value = (hi_u32 *)args;
            ret = taload_get_tarootcert_double_sign(value);
            if (ret != HI_SUCCESS) {
                hi_error_taload("taload_get_tee_ext_pub_key failed!\n");
            }
            break;
        }
        default: {
            hi_error_taload("Unknown ioctl cmd in taload!\n");
            break;
        }
    }

    return ret;
}

static hi_s32 taload_syscall(hi_s32 swi_id, struct drv_param *params, unsigned long long permissions)
{
    hi_u32 ret;
    if (params == NULL || params->args == 0)
        return -1;
    uint64_t  *args = (uint64_t *)(uintptr_t)params->args;
    ret = HI_FAILURE;
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_TALOAD, permissions, GENERAL_GROUP_PERMISSION)
            ACCESS_CHECK(args[1], args[2])
            ret = tee_drv_taload_ioctl(args[0], (hi_void *)args[1]);
            if (ret != HI_SUCCESS) {
                hi_error_taload("call log ioctl fail: 0x%x!\n", ret);
                args[0] = HI_FAILURE;  /* return failure for api */
            } else {
                args[0] = HI_SUCCESS;  /* return success for api */
            }
            SYSCALL_END
         default:
            return -EINVAL;
    }
    return 0;
}

hi_tee_drv_hal_driver_init_late(drv_taload, 0, HI_NULL, taload_syscall, HI_NULL, HI_NULL);
