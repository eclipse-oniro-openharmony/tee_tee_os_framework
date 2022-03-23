set(MSPE_C_DEFINITIONS
    FEATURE_OS_SUPPORTED
    FEATURE_SECENG_IP_DYNAMIC_CTRL
    FEATURE_SECENG_IP_GTCLK_ENABLE
    FEATURE_PAL_HEAP_SUPPORTED
    FEATURE_ECC_SM2_SUPPORT
    FEATURE_ECC_HAL_SUPPORT
    FEATURE_ECC_SUPPORT
    FEATURE_SCE_SUPPORT_AUTH_CRYPTO
    FEATURE_RTL_CRYPTO_ENABLE
    FEATURE_SCE_WORKSPACE_ENABLE
    FEATURE_RSA_GENKEY_PQ
    FEATURE_TRNG_HSV2_ENABLE
    FEATURE_SM9_ENABLE
)

if ("${TARGET_BUILD_VARIANT}" STREQUAL "eng")
    list(APPEND MSPE_C_DEFINITIONS
        FEATURE_DFT_ENABLE
        FEATURE_TRNG_ALARM_ENABLE
        FEATURE_HAT_HAVA_SUPPORTED
    )
endif()

set(MSPE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/adapter/adapter_cipher.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/adapter/adapter_platform.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/adapter/adapter_rng.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/adapter/adapter_ecc.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/adapter/adapter_common.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/adapter/adapter_hmac.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/adapter/adapter_hash.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/adapter/adapter_rsa.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/libcustom/cdrm/hisee_video_ops.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/libcustom/cdrm/hisee_video.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/libcustom/cdrm/hisee_video_syscall_handle.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/custom/priprotect/hisee_priprotect_km.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/custom/hiai/hisee_hiai_km.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/driver/power/chip/baltimore/hieps_power.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/driver/power/chip/baltimore/mspe_power_plat.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/driver/power/chip/baltimore/hieps_powerctrl_plat.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/driver/smmu/hieps_smmu.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/driver/timer/hieps_timer.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/common/hieps_common.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/common/hieps_smc.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/host/osl/teeos/osl_os_plat.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/host/pal/pal_smmu_plat.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/host/pal/pal_exception_plat.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/host/pal/pal_cpu_plat.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/host/pal/pal_interrupt_plat.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/host/pal/pal_mem_plat.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/host/pal/pal_log_plat.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/host/pal/pal_nv_cfg_plat.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/host/pal/pal_timer_plat.c
)

if ("${TARGET_BUILD_VARIANT}" STREQUAL "eng")
    list(APPEND MSPE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/host/pal/pal_plat_dft.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/autotest/custom/hisee_hiai_dft.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/autotest/custom/cdrm/hisee_video_dft.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/common/msptest_interface.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/autotest/custom/cdrm/hisee_video_cmaion_mgr.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/autotest/custom/cdrm/hisee_video_perf.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/autotest/hat_mem_plat.c
    )
endif()

list(SORT MSPE_C_SOURCES COMPARE STRING CASE SENSITIVE ORDER ASCENDING)

if("${chip_type}" STREQUAL "es")
    set(MSPE_BIN_PATH "${TARGET_BOARD_PLATFORM}_es")
else()
    set(MSPE_BIN_PATH "${TARGET_BOARD_PLATFORM}_cs")
endif()
set(MSPE_BIN_PATH ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/libseceng/${MSPE_BIN_PATH})

if("${chip_type}" MATCHES "es|es2|cs2")
   set(MSPE_AP_PLATFORM_DIR "${TARGET_BOARD_PLATFORM}_${chip_type}")
else()
   set(MSPE_AP_PLATFORM_DIR "${TARGET_BOARD_PLATFORM}")
endif()
set(MSPE_AP_PLATFORM_DIR ${PROJECT_SOURCE_DIR}/../../../../../vendor/hisi/ap/platform/${MSPE_AP_PLATFORM_DIR})


set(MSPE_INCLUDE_PATH
    ${MSPE_AP_PLATFORM_DIR}/mspe/teeos
    ${MSPE_AP_PLATFORM_DIR}/mspe
    ${MSPE_AP_PLATFORM_DIR}
    ${PROJECT_SOURCE_DIR}/../../../../../vendor/hisi/bsp/libc_sec/securec_v2/include
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include/
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${MSPE_BIN_PATH}/libseceng/utils/include
    ${MSPE_BIN_PATH}/libseceng/standard/include
    ${MSPE_BIN_PATH}/libseceng/basic/bignum/include
    ${MSPE_BIN_PATH}/libseceng/basic/rng/include
    ${MSPE_BIN_PATH}/libseceng/api/sce/include
    ${MSPE_BIN_PATH}/libseceng/api/pke/ecc/include
    ${MSPE_BIN_PATH}/libseceng/mspe/hal/include
    ${MSPE_BIN_PATH}/include/host/pal
    ${MSPE_BIN_PATH}/include/host/osl
    ${MSPE_BIN_PATH}/include/mspe
    ${MSPE_BIN_PATH}/include/common
    ${MSPE_BIN_PATH}/include/api
    ${MSPE_BIN_PATH}/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/adapter
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/adapter/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/include/host/pal
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/include/host/osl/teeos
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/include/host
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/custom/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/libcustom/cdrm
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/custom/priprotect
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/custom/hiai
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/driver/power/chip/${TARGET_BOARD_PLATFORM}
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/driver/power
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/driver/smmu
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/main
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/driver/timer
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/common
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/driver/agent/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/main
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/host/osl
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/host/pal
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/crypto
    ${PROJECT_SOURCE_DIR}/libs/libchinadrm/include
    ${PROJECT_SOURCE_DIR}/thirdparty/huawei/libhwsecurec/include/libhwsecurec
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include/TEE_ext
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include/kernel
    ${PROJECT_SOURCE_DIR}/sys_libs/libhmdrv_stub/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libtimer_a32/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libtimer/inc
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/secmem/include
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
)

if ("${TARGET_BUILD_VARIANT}" STREQUAL "eng")
    list(APPEND MSPE_INCLUDE_PATH
        ${MSPE_BIN_PATH}/autotest/include
        ${MSPE_BIN_PATH}/autotest
        ${MSPE_BIN_PATH}/libseceng/mspe/test/include
        ${MSPE_BIN_PATH}/libseceng/mspe/test/include/common
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/autotest/custom/cdrm
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/autotest
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_engine/autotest/include
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_core/test
    )
endif()
