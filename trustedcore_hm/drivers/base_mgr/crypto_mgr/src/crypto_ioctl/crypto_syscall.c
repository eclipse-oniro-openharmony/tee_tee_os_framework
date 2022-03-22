/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: implement crypto hal syscall
 * Create: 2022-01-13
 */
#include "crypto_syscall_common.h"
#include <securec.h>
#include "tee_driver_module.h"
#include <sys/hmapi_ext.h>
#include <sys/hm_priorities.h>
#include <inttypes.h>
#include <procmgr_ext.h>
#include <sys/fileio.h>
#include <sys/usrsyscall_ext.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sre_log.h>
#include "drv_random.h"
#include "ccmgr_hm.h"
#include "crypto_syscall.h"
#include "crypto_syscall_ec.h"
#include "crypto_syscall_hash.h"
#include "crypto_syscall_hmac.h"
#include "crypto_syscall_rsa.h"
#include "crypto_syscall_random.h"
#include "crypto_syscall_ae.h"
#include "crypto_syscall_cipher.h"
#include "crypto_syscall_oemkey.h"
#include "crypto_syscall_derive_key.h"

struct crypto_drv_ops_t *g_drv_entry = NULL;
#define DRV_NAME   "/tafs/libhardware_crypto_drv.so"

static int32_t load_drv_hardware(void)
{
    void *drv_so_handle = dlopen(DRV_NAME, RTLD_LAZY | RTLD_GLOBAL);
    if (drv_so_handle == NULL) {
        hm_error("load failed %s\n", dlerror());
        return CRYPTO_OVERFLOW;
    }

    g_drv_entry = (struct crypto_drv_ops_t *)dlsym(drv_so_handle, "g_crypto_drv_ops");
    if (g_drv_entry == NULL) {
        hm_error("cannot get tee drv entry\n");
        return CRYPTO_OVERFLOW;
    }

    if (g_drv_entry->init != NULL)
        g_drv_entry->init();

    register_crypto_rand_driver(hw_generate_random_ops, g_drv_entry);
    return CRYPTO_SUCCESS;
}

#define SWI_ID_INDEX(swi_id) ((swi_id) - IOCTRL_CRYPTO_BASE)
typedef int32_t (*crypto_syscall_func)(const struct drv_data *drv,
    unsigned long args, uint32_t args_len, const struct crypto_drv_ops_t *ops);
static crypto_syscall_func g_crypto_func_list[] = {
    [SWI_ID_INDEX(IOCTRL_CRYPTO_GET_CTX_SIZE)]         = get_ctx_size_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_CTX_COPY)]             = ctx_copy_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_HASH_INIT)]            = hash_init_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_HASH_UPDATE)]          = hash_update_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_HASH_DOFINAL)]         = hash_dofinal_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_HASH)]                 = hash_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_HMAC_INIT)]            = hmac_init_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_HMAC_UPDATE)]          = hmac_update_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_HMAC_DOFINAL)]         = hmac_dofinal_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_HMAC)]                 = hmac_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_CIPHER_INIT)]          = cipher_init_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_CIPHER_UPDATE)]        = cipher_update_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_CIPHER_DOFINAL)]       = cipher_dofinal_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_CIPHER)]               = cipher_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_AE_INIT)]              = ae_init_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_AE_UPDATE_AAD)]        = ae_update_aad_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_AE_UPDATE)]            = ae_update_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_AE_ENC_FINAL)]         = ae_enc_final_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_AE_DEC_FINAL)]         = ae_dec_final_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_RSA_GENERATE_KEYPAIR)] = rsa_generate_keypair_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_RSA_ENCRYPT)]          = rsa_encrypt_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_RSA_DECRYPT)]          = rsa_decrypt_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_RSA_SIGN_DIGEST)]      = rsa_sign_digest_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_RSA_VERIFY_DIGEST)]    = rsa_verify_digest_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_ECC_GENERATE_KEYPAIR)] = ecc_generate_keypair_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_ECC_ENCRYPT)]          = ecc_encrypt_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_ECC_DECRYPT)]          = ecc_decrypt_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_ECC_SIGN_DIGEST)]      = ecc_sign_digest_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_ECC_VERIFY_DIGEST)]    = ecc_verify_digest_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_ECDH_DERIVE_KEY)]      = ecdh_derive_key_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_DH_GENERATE_KEY)]      = dh_generate_key_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_DH_DERIVE_KEY)]        = dh_derive_key_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_GENERATE_RANDOM)]      = generate_random_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_GET_ENTROPY)]          = get_entropy_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_DERIVE_ROOT_KEY)]      = derive_root_key_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_PBKDF2)]               = pbkdf2_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_GET_DRV_ABILITY)]      = get_driver_ability_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_CHECK_ALG_SUPPORT)]    = check_alg_support_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_GET_OEMKEY)]           = get_oemkey_call,
    [SWI_ID_INDEX(IOCTRL_CRYPTO_MAX)]                  = NULL
};

int32_t crypto_ioctl_func(const struct drv_data *drv, uint32_t cmd,
    unsigned long args, uint32_t args_len)
{
    if (drv == NULL)
        return CRYPTO_BAD_PARAMETERS;

    if (g_drv_entry == NULL) {
        int32_t ret = load_drv_hardware();
        if (ret != CRYPTO_SUCCESS) {
            tloge("drv hardware open fail");
            return ret;
        }
    }

    bool check = (cmd <= IOCTRL_CRYPTO_BASE || cmd >= IOCTRL_CRYPTO_MAX ||
        g_crypto_func_list[SWI_ID_INDEX(cmd)] == NULL);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    return g_crypto_func_list[SWI_ID_INDEX(cmd)](drv, args, args_len, g_drv_entry);
}

