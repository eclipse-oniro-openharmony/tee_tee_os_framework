set(CONFIG_TA_32BIT  true)
set(CONFIG_TIMER_EVENT true)
set(CONFIG_TA_SIGN_KEY_CBG true)

list(APPEND PRODUCT_RELEASE_64 mspcore rot weaver art biometric sec_flash_client vltmm chinadrm)
list(APPEND PRODUCT_RELEASE_32 mspcore rot weaver art biometric sec_flash_client vltmm chinadrm)

if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_32 dx_cc7)
endif()

if ("${CONFIG_SUPPORT_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 storage.elf attestation_ta.elf kds.elf secboot.elf)
else()
    list(APPEND PRODUCT_RELEASE_64 storage.elf attestation_ta.elf kds.elf secboot.elf)
    list(APPEND PRODUCT_RELEASE_32 storage.elf attestation_ta.elf kds.elf secboot.elf)
endif()

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "baltimore" OR "${TARGET_BOARD_PLATFORM}" STREQUAL "denver" OR "${TARGET_BOARD_PLATFORM}" STREQUAL "laguna")
    if (NOT "${WITH_MODEM}" STREQUAL "false")
        list(APPEND PRODUCT_RELEASE_32 sec_modem)
    endif()
endif()

list(APPEND BOOTFS_FILES_IN_PREBUILD taloader.elf)

set(CONFIG_CRYPTO_SUPPORT_EC25519 true)
set(CONFIG_CRYPTO_SUPPORT_X509 true)
set(CONFIG_CRYPTO_ECC_WRAPPER true)
set(CONFIG_CRYPTO_AES_WRAPPER true)

if ("${CONFIG_DRV_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_APPS_32 storage.elf attestation_ta.elf kds.elf secboot.elf)
endif()

if ("${CONFIG_DRV_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_APPS_64 storage.elf attestation_ta.elf kds.elf secboot.elf)
endif()
