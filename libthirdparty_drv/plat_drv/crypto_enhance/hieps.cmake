if ("${TARGET_BUILD_VARIANT}" STREQUAL "eng")
    set(HIEPS_C_DEFINITIONS
        FEATURE_DFT_ENABLE
        FEATURE_AUTOTEST
        FEATURE_CDRM_TEST
        FEATURE_HIEPS_AUTOTEST
        FEATURE_PLATFORM_NAME=\"${TARGET_BOARD_PLATFORM}\"
        FEATURE_CHIP_TYPE=\"${chip_type}\"
    )
endif()

set(HIEPS_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/common/sec_utils.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/common/common_sce.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/api_agent/api_cipher.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/api_agent/api_mac.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/api_agent/api_hash.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/api_agent/api_hmac.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/api_agent/api_km.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/api_agent/api_rsa.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/api_agent/api_sm2.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/cdrmr/cdrmr_cipher.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/cdrmr/cdrmr_hash.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/cdrmr/cdrmr_hmac.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/cdrmr/cdrmr_sm2.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/adapter/adapt_rsa.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/adapter/adapt_cipher.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/adapter/adapt_hash.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/adapter/adapt_hmac.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/adapter/adapt_km.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/driver/cdrm/hieps_cdrm_cmd.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/driver/power/hieps_power.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/driver/power/hieps_pm.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/driver/timer/hieps_timer.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/driver/exception/hieps_exception.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/driver/agent/src/hieps_memory.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/driver/agent/src/hieps_run_func.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/driver/watchdog/hieps_watchdog.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/driver/ipc/hieps_ipc.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/common/hieps_common.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/common/hieps_smc.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/host/src/pal_libc.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/host/src/pal_timer.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/host/src/pal_log.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/host/src/pal_memory.c
)

if ("${TARGET_BUILD_VARIANT}" STREQUAL "eng")
    add_custom_command(OUTPUT ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/autotest/config/hat_pack.c
        COMMAND python ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/autotest/hat_pack.py "gen_code" "${TARGET_BOARD_PLATFORM}"
        DEPENDS ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/autotest/config/hat_pack.cfg
    )

    list(APPEND HIEPS_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/autotest/framework/hat_entry.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/autotest/framework/hat_framework.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/autotest/config/hat_pack.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/cdrmr/cdrmr_dft.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/api_agent/api_symm_dft.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/adapter/adapt_dft.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/common/msptest_interface.c
    )
endif()

list(SORT HIEPS_C_SOURCES COMPARE STRING CASE SENSITIVE ORDER ASCENDING)

if("${chip_type}" MATCHES "es|es2|cs2")
   set(HIEPS_AP_PLATFORM_DIR "${TARGET_BOARD_PLATFORM}_${chip_type}")
else()
   set(HIEPS_AP_PLATFORM_DIR "${TARGET_BOARD_PLATFORM}")
endif()
set(HIEPS_AP_PLATFORM_DIR ${PROJECT_SOURCE_DIR}/../../../../../vendor/hisi/ap/platform/${HIEPS_AP_PLATFORM_DIR})

set(HIEPS_INCLUDE_PATH
    ${HIEPS_AP_PLATFORM_DIR}
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/host/include/pal
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/host/include/adapter
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include/cdrmr
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/driver/agent/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include/api
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include/hal/hieps
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include/hal
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include/common/hieps
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include/common
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/api_agent/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/cdrmr/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/adapter/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/ccdriver_lib/include
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/secmem/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/secmem
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/inner_sdk/legacy
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/sdk/teeapi/common
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/sdk/gpapi/common
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/inner_sdk/legacy/uapi
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/inner_sdk/hmapi
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/inner_sdk/teeapi/common
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/host/uapi
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/kernel/uapi
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/ddk/legacy
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/ddk/hmapi
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers
    ${PROJECT_SOURCE_DIR}/thirdparty/huawei/libhwsecurec/include/libhwsecurec
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include/TEE_ext
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include/kernel
    ${PROJECT_SOURCE_DIR}/sys_libs/libhmdrv_stub/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libtimer_a32/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libtimer/inc
)

if ("${TARGET_BUILD_VARIANT}" STREQUAL "eng")
    list(APPEND HIEPS_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/autotest
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/autotest/framework
    )
endif()
