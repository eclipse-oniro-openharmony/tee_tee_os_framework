/* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: define array of syscall id for ascend.
 * Create: 2020-06-25
 */
#include <sre_syscalls_id_ext.h>
#include <sre_syscalls_id.h>
#include "platdrv_hash.h"

static uint32_t g_drv_module_size;

static uint16_t g_task_exit_driver_id[] = {
    SW_SYSCALL_SYS_OSTSKEXIT,
};

static uint16_t g_hwi_register_driver_id[] = {
    SW_SYSCALL_HWI_IPCREGISTER,
    SW_SYSCALL_HWI_IPCDEREGISTER,
};

static uint16_t g_sec_hiss_driver_id[] = {
    SW_SYSCALL_SEC_PRO_KEY,
};

static uint16_t g_crypto_driver_id[] = {
    SW_SYSCALL_CRYPTO_GET_CTX_SIZE,
    SW_SYSCALL_CRYPTO_CTX_COPY,
    SW_SYSCALL_CRYPTO_HASH_INIT,
    SW_SYSCALL_CRYPTO_HASH_UPDATE,
    SW_SYSCALL_CRYPTO_HASH_DOFINAL,
    SW_SYSCALL_CRYPTO_HASH,
    SW_SYSCALL_CRYPTO_HMAC_INIT,
    SW_SYSCALL_CRYPTO_HMAC_UPDATE,
    SW_SYSCALL_CRYPTO_HMAC_DOFINAL,
    SW_SYSCALL_CRYPTO_HMAC,
    SW_SYSCALL_CRYPTO_CIPHER_INIT,
    SW_SYSCALL_CRYPTO_CIPHER_UPDATE,
    SW_SYSCALL_CRYPTO_CIPHER_DOFINAL,
    SW_SYSCALL_CRYPTO_CIPHER,
    SW_SYSCALL_CRYPTO_AE_INIT,
    SW_SYSCALL_CRYPTO_AE_UPDATE_AAD,
    SW_SYSCALL_CRYPTO_AE_UPDATE,
    SW_SYSCALL_CRYPTO_AE_ENC_FINAL,
    SW_SYSCALL_CRYPTO_AE_DEC_FINAL,
    SW_SYSCALL_CRYPTO_RSA_GENERATE_KEYPAIR,
    SW_SYSCALL_CRYPTO_RSA_ENCRYPT,
    SW_SYSCALL_CRYPTO_RSA_DECRYPT,
    SW_SYSCALL_CRYPTO_RSA_SIGN_DIGEST,
    SW_SYSCALL_CRYPTO_RSA_VERIFY_DIGEST,
    SW_SYSCALL_CRYPTO_ECC_GENERATE_KEYPAIR,
    SW_SYSCALL_CRYPTO_ECC_ENCRYPT,
    SW_SYSCALL_CRYPTO_ECC_DECRYPT,
    SW_SYSCALL_CRYPTO_ECC_SIGN_DIGEST,
    SW_SYSCALL_CRYPTO_ECC_VERIFY_DIGEST,
    SW_SYSCALL_CRYPTO_ECDH_DERIVE_KEY,
    SW_SYSCALL_CRYPTO_DH_GENERATE_KEY,
    SW_SYSCALL_CRYPTO_DH_DERIVE_KEY,
    SW_SYSCALL_CRYPTO_GENERATE_RANDOM,
    SW_SYSCALL_CRYPTO_DERIVE_ROOT_KEY,
    SW_SYSCALL_CRYPTO_PBKDF2,
    SW_SYSCALL_CRYPTO_GET_DRV_ABILITY,
};

static uint16_t g_firmup_driver_id[] = {
    SYSCALL_SECURE_FLASH_ERASE,
    SYSCALL_SECURE_FLASH_READ,
    SYSCALL_SECURE_FLASH_WRITE,
    SYSCALL_SECURE_IMG_VERIFY,
    SYSCALL_SECURE_IMG_UPDATE,
    SYSCALL_SECURE_UPDATE_FINISH,
    SYSCALL_SECURE_VERSION_GET,
    SYSCALL_SECURE_COUNT_GET,
    SYSCALL_SECURE_INFO_GET,
    SYSCALL_SECURE_UFS_CNT_READ,
    SYSCALL_SECURE_UFS_CNT_WRITE,
    SYSCALL_SECURE_VERIFY_STATUS_UPDATE,
    SYSCALL_SECURE_IMG_SYNC,
    SYSCALL_UPGRADE_SRAM_READ,
    SYSCALL_UPGRADE_FLASH_READ,
    SYSCALL_UPGRADE_FLASH_WRITE,
    SYSCALL_UPGRADE_RESET_CNT_READ,
    SYSCALL_UPGRADE_RESET_CNT_WRITE,
    SYSCALL_SECURE_ROOTKEY_GET,
    SYSCALL_SECURE_CMDLINE_GET,
    SYSCALL_REFLASH_HILINK,
    SYSCALL_SECURE_PART_READ,
    SYSCALL_SECURE_GET_BLFLAG,
    SYSCALL_SECURE_SET_BLFLAG,
    SYSCALL_SECURE_HBOOT_TRANS,
    SYSCALL_SECURE_UPDATE_STATUS,
    SYSCALL_SECURE_RECOVERY_CNT_WRITE
};

static uint16_t g_scmi_driver_id[] = {
    SYSCALL_SCMI_CHANNEL_OPEN,
    SYSCALL_SCMI_CHANNEL_CLOSE,
    SYSCALL_SCMI_CHANNEL_SEND_DATA,
    SYSCALL_SCMI_CHANNEL_TASK_AND_GET_DATA,
    SYSCALL_SCMI_CHANNEL_PADDR2VADDR,
};

static uint16_t g_trng_hiss_driver_id[] = {
    SW_SYSCALL_TRNG_GENERATE_RANDOM,
};


static uint16_t g_efuse_driver_id[] = {
    SYSCALL_HSM_EFUSE_WRITE,
    SYSCALL_HSM_EFUSE_BURN,
    SYSCALL_HSM_EFUSE_CHECK,
    SYSCALL_HSM_EFUSE_NV_CNT_BURN,
    SYSCALL_HSM_EFUSE_NV_CNT_CHECK,
    SYSCALL_HSM_EFUSE_NS_FORIBID_CHECK,
};

static uint16_t g_sfc_driver_id[] = {
    SYSCALL_SFC_FLASH_READ,
    SYSCALL_SFC_FLASH_WRITE,
    SYSCALL_SFC_FLASH_ERASE,
    SYSCALL_SFC_FLASH_PA2TAVA,
};

uint16_t g_sharedmem_addr_id[] = {
    SW_SYSCALL_GET_TEESHAREDMEM,
};

static uint16_t g_pg_info_get_driver_id[] = {
    SYSCALL_HSM_PG_GET,
};

void drv_module_init(void)
{
    struct module_info *init_info = get_g_module_info();

    register_drv_module(sec_hiss_driver)
    register_drv_module(task_exit_driver)
    register_drv_module(hwi_register_driver)
    register_drv_module(crypto_driver)
    register_drv_module(firmup_driver)
    register_drv_module(scmi_driver)
    register_drv_module(trng_hiss_driver)
    register_drv_module(efuse_driver)
    register_drv_module(sharedmem_addr)
    register_drv_module(sfc_driver)
    register_drv_module(pg_info_get_driver)
}

uint32_t get_drv_module_size(void)
{
    return g_drv_module_size;
}
