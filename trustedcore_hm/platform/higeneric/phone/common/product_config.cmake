set(CONFIG_TA_32BIT true)
set(CONFIG_TIMER_EVENT true)
set(CONFIG_TA_SIGN_KEY_CBG true)
set(CONFIG_DRIVER_DYN_MOD true)
set(CONFIG_SIGN_KEY_RELEASE_DEBUG_ISOLATION true)

if ("${CONFIG_SUPPORT_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 mspcore rot weaver art biometric sec_flash_client vltmm chinadrm)
else()
    list(APPEND PRODUCT_RELEASE_64 mspcore rot weaver art biometric sec_flash_client vltmm chinadrm)
    list(APPEND PRODUCT_RELEASE_32 mspcore_a32 rot_a32 weaver_a32 art_a32 biometric_a32 sec_flash_client_a32 vltmm_a32 chinadrm_a32)
endif()

if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_32 dx_cc7)
endif()

if ("${CONFIG_SUPPORT_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 storage.elf attestation_ta.elf kds.elf secboot.elf)
else()
    list(APPEND PRODUCT_RELEASE_32 storage.elf attestation_ta.elf kds.elf secboot.elf)
endif()

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "baltimore" OR "${TARGET_BOARD_PLATFORM}" STREQUAL "denver" OR "${TARGET_BOARD_PLATFORM}" STREQUAL "laguna")
    if (NOT "${WITH_MODEM}" STREQUAL "false")
        list(APPEND PRODUCT_RELEASE_32 sec_modem)
    endif()
endif()

list(APPEND BOOTFS_FILES_IN_PREBUILD taloader.elf)

set(CONFIG_CRYPTO_SUPPORT_DES true)
set(CONFIG_CRYPTO_SUPPORT_EC25519 true)
set(CONFIG_CRYPTO_SUPPORT_X509 true)
set(CONFIG_CRYPTO_ECC_WRAPPER true)
set(CONFIG_CRYPTO_AES_WRAPPER true)

if ("${CONFIG_DRV_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        attestation_ta.elf
        storage.elf
    )
endif()
if ("${CONFIG_DRV_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_APPS_32
        attestation_ta.elf
        storage.elf
        secboot.elf
        kds.elf
    )
endif()

include(${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/modules/modules.cmake)
