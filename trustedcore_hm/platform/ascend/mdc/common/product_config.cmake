set(CONFIG_TIMER_EVENT true)
set(CONFIG_KMS true)
set(CONFIG_CRYPTO_SUPPORT_EC25519 true)
set(CONFIG_CRYPTO_SUPPORT_X509 true)
set(CONFIG_CRYPTO_ECC_WRAPPER true)
set(CONFIG_CRYPTO_AES_WRAPPER true)

list(APPEND PRODUCT_RELEASE_64 hsm.elf hsm_bbox.elf firmware_upgrade.elf rpmb_key.elf hsm_efuse.elf hsm_flash.elf cmscbb)

list(APPEND PRODUCT_APPS_64 hsm.elf hsm_bbox.elf firmware_upgrade.elf rpmb_key.elf hsm_efuse.elf hsm_flash.elf)
