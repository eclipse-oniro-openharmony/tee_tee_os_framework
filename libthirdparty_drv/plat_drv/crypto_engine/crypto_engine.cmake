set(MSPE_PLATDRV_DIR ${HISEE_HOST_TEEOS_MSPE_DIR})

include(${MSPE_PLATDRV_DIR}/build/cmake/dir_variables.cmake)
include(${MSPE_PLATDRV_DIR}/build/cmake/mspe_module.cmake)

set(runtime_platform "teeos")
set(mspe_target "mspe_teeos_libseceng")

# generate seceng static library
# return "libseceng_path", store static library
mspe_gen_libseceng(libseceng_path
    BOARD_PLATFORM   "${TARGET_BOARD_PLATFORM}"
    TARGETS          "${mspe_target}"
    BUILD_OUT        "${CMAKE_BINARY_DIR}/crypto_engine"
    CHIP_TYPE        "${chip_type}"
    BUILD_VARIANT    "${TARGET_BUILD_VARIANT}"
    RUNTIME_PLATFORM "${runtime_platform}"
)
# generate seceng macro config header file
# return "macro_config_path", store macro config header file
mspe_get_config_path(macro_config_path
    BOARD_PLATFORM   "${TARGET_BOARD_PLATFORM}"
    CHIP_TYPE        "${chip_type}"
    BUILD_VARIANT    "${TARGET_BUILD_VARIANT}"
    RUNTIME_PLATFORM "${runtime_platform}"
)
message(STATUS "MSPE ${runtime_platform} libseceng_path: ${libseceng_path}")
message(STATUS "MSPE ${runtime_platform} macro_config_path: ${macro_config_path}")

set(MSPE_C_COMPILE_OPTIONS
    "-include ${macro_config_path}" # "SHELL:-include ${macro_config_path}"
)

set(MSPE_C_SOURCES
    ${MSPE_PLATDRV_DIR}/adapter/adapter_cipher.c
    ${MSPE_PLATDRV_DIR}/adapter/adapter_common.c
    ${MSPE_PLATDRV_DIR}/adapter/adapter_ecc.c
    ${MSPE_PLATDRV_DIR}/adapter/adapter_hash.c
    ${MSPE_PLATDRV_DIR}/adapter/adapter_hmac.c
    ${MSPE_PLATDRV_DIR}/adapter/adapter_rng.c
    ${MSPE_PLATDRV_DIR}/adapter/adapter_rsa.c
    ${MSPE_PLATDRV_DIR}/adapter/adapter_platform.c
    ${MSPE_PLATDRV_DIR}/common/hieps_common.c
    ${MSPE_PLATDRV_DIR}/common/hieps_smc.c
    ${MSPE_PLATDRV_DIR}/custom/hiai/hisee_hiai_km.c
    ${MSPE_PLATDRV_DIR}/custom/priprotect/hisee_priprotect_km.c
    ${MSPE_PLATDRV_DIR}/custom/cdrm/hisee_video.c
    ${MSPE_PLATDRV_DIR}/custom/cdrm/hisee_video_ops.c
    ${MSPE_PLATDRV_DIR}/custom/cdrm/hisee_video_syscall_handle.c
    ${MSPE_PLATDRV_DIR}/driver/timer/hieps_timer.c
    ${MSPE_PLATDRV_DIR}/driver/crypto_init/mspe_crypto_init.c
    ${MSPE_PLATDRV_DIR}/driver/crypto_selftest/mspe_crypto_selftest.c
    ${MSPE_PLATDRV_DIR}/host/osl/teeos/osl_os_plat.c
    ${MSPE_PLATDRV_DIR}/host/pal/pal_exception_plat.c
    ${MSPE_PLATDRV_DIR}/host/pal/pal_interrupt_plat.c
    ${MSPE_PLATDRV_DIR}/host/pal/pal_log_plat.c
    ${MSPE_PLATDRV_DIR}/host/pal/pal_mem_plat.c
    ${MSPE_PLATDRV_DIR}/host/pal/pal_nv_cfg_plat.c
    ${MSPE_PLATDRV_DIR}/host/pal/pal_timer_plat.c
    ${MSPE_PLATDRV_DIR}/host/pal/pal_cpu_plat.c
)

if(CONFIG_HISI_MSPE_SMMUV2)
    list(APPEND MSPE_C_SOURCES
        ${MSPE_PLATDRV_DIR}/custom/cdrm/hisee_video_smmuv2.c
        ${MSPE_PLATDRV_DIR}/driver/smmu/mspe_smmu_v2.c
        ${MSPE_PLATDRV_DIR}/host/pal/pal_smmuv2_plat.c
    )
endif()

if(CONFIG_HISI_MSPE_SMMUV3)
    list(APPEND MSPE_C_SOURCES
        ${MSPE_PLATDRV_DIR}/custom/cdrm/hisee_video_smmuv3.c
        ${MSPE_PLATDRV_DIR}/driver/smmu/mspe_smmu_v3.c
        ${MSPE_PLATDRV_DIR}/host/pal/pal_smmuv3_plat.c
    )
endif()

if (CONFIG_HISI_MSPE_POWER_SCHEME)
    list(APPEND MSPE_C_SOURCES
        ${MSPE_PLATDRV_DIR}/driver/power/mspe_power.c
        ${MSPE_PLATDRV_DIR}/driver/power/mspe_power_compatible.c
        ${MSPE_PLATDRV_DIR}/driver/power/mspe_power_ctrl.c
        ${MSPE_PLATDRV_DIR}/driver/power/mspe_power_dvfs.c
        ${MSPE_PLATDRV_DIR}/driver/power/mspe_power_msg_route.c
        ${MSPE_PLATDRV_DIR}/driver/power/mspe_power_mspe.c
        ${MSPE_PLATDRV_DIR}/driver/power/mspe_power_state_mgr.c
        ${MSPE_PLATDRV_DIR}/driver/power_hook/mspe_power_hook.c
        ${MSPE_PLATDRV_DIR}/factory/mspe_factory.c
    )
else()
    # baltimore power use this
    list(APPEND MSPE_C_SOURCES
        ${MSPE_PLATDRV_DIR}/driver/power/chip/${TARGET_BOARD_PLATFORM}/hieps_power.c
        ${MSPE_PLATDRV_DIR}/driver/power/chip/${TARGET_BOARD_PLATFORM}/hieps_powerctrl_plat.c
        ${MSPE_PLATDRV_DIR}/driver/power/chip/${TARGET_BOARD_PLATFORM}/mspe_power_plat.c
    )
endif()

if(CONFIG_HISI_MSPE_IN_MEDIA2)
    list(APPEND MSPE_C_SOURCES
        ${MSPE_PLATDRV_DIR}/driver/power/mspe_clk_volt/media2/mspe_power_clk_volt_plat.c
        ${MSPE_PLATDRV_DIR}/driver/power/mspe_clk_volt/media2/mspe_power_mspe_plat.c
    )
endif()

if (NOT "${TARGET_BUILD_VARIANT}" STREQUAL "user")
    list(APPEND MSPE_C_SOURCES
        ${MSPE_PLATDRV_DIR}/autotest/custom/cdrm/hisee_video_cmaion_mgr.c
        ${MSPE_PLATDRV_DIR}/autotest/custom/cdrm/hisee_video_perf.c
        ${MSPE_PLATDRV_DIR}/autotest/custom/cdrm/hisee_video_dft.c
        ${MSPE_PLATDRV_DIR}/autotest/custom/hisee_hiai_dft.c
        ${MSPE_PLATDRV_DIR}/autotest/hat_mem_plat.c
        ${MSPE_PLATDRV_DIR}/common/mspe_test.c
        ${MSPE_PLATDRV_DIR}/host/pal/pal_plat_dft.c
    )
endif()

list(SORT MSPE_C_SOURCES COMPARE STRING CASE SENSITIVE ORDER ASCENDING)

if("${chip_type}" MATCHES "es|es2|cs2")
   set(MSPE_AP_PLATFORM_DIR "${TARGET_BOARD_PLATFORM}_${chip_type}")
else()
   set(MSPE_AP_PLATFORM_DIR "${TARGET_BOARD_PLATFORM}")
endif()
set(MSPE_AP_PLATFORM_DIR ${HISEE_AP_PLATFORM_DIR}/${MSPE_AP_PLATFORM_DIR})

set(MSPE_INCLUDE_PATH
    ${MSPE_AP_PLATFORM_DIR}/mspe/teeos
    ${MSPE_AP_PLATFORM_DIR}/mspe
    ${MSPE_AP_PLATFORM_DIR}
    ${HISEE_SECENG_INCLUDE_DIR}/libseceng/utils/include
    ${HISEE_SECENG_INCLUDE_DIR}/libseceng/standard/include
    ${HISEE_SECENG_INCLUDE_DIR}/libseceng/basic/bignum/include
    ${HISEE_SECENG_INCLUDE_DIR}/libseceng/basic/rng/include
    ${HISEE_SECENG_INCLUDE_DIR}/libseceng/api/sce/include
    ${HISEE_SECENG_INCLUDE_DIR}/libseceng/api/pke/ecc/include
    ${HISEE_SECENG_INCLUDE_DIR}/libseceng/mspe/hal/include
    ${HISEE_SECENG_INCLUDE_DIR}/include/host/pal
    ${HISEE_SECENG_INCLUDE_DIR}/include/host/osl
    ${HISEE_SECENG_INCLUDE_DIR}/include/mspe
    ${HISEE_SECENG_INCLUDE_DIR}/include/common
    ${HISEE_SECENG_INCLUDE_DIR}/include/api
    ${HISEE_SECENG_INCLUDE_DIR}/include
    ${MSPE_PLATDRV_DIR}/adapter
    ${MSPE_PLATDRV_DIR}/adapter/include
    ${MSPE_PLATDRV_DIR}/include/host/pal
    ${MSPE_PLATDRV_DIR}/include/host/osl/teeos
    ${MSPE_PLATDRV_DIR}/include
    ${MSPE_PLATDRV_DIR}/include/host
    ${MSPE_PLATDRV_DIR}/custom/include
    ${MSPE_PLATDRV_DIR}/libcustom/cdrm
    ${MSPE_PLATDRV_DIR}/custom/priprotect
    ${MSPE_PLATDRV_DIR}/custom/hiai
    ${MSPE_PLATDRV_DIR}/driver/power/chip/${TARGET_BOARD_PLATFORM}
    ${MSPE_PLATDRV_DIR}/driver/power
    ${MSPE_PLATDRV_DIR}/driver/smmu
    ${MSPE_PLATDRV_DIR}/include
    ${MSPE_PLATDRV_DIR}/main
    ${MSPE_PLATDRV_DIR}/driver/timer
    ${MSPE_PLATDRV_DIR}/common
    ${MSPE_PLATDRV_DIR}/driver/agent/include
    ${MSPE_PLATDRV_DIR}/main
    ${MSPE_PLATDRV_DIR}/host/osl
    ${MSPE_PLATDRV_DIR}/host/pal
    ${PROJECT_SOURCE_DIR}/../../../../../vendor/hisi/bsp/libc_sec/securec_v2/include
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include/
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/crypto
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/secmem/include
    ${PROJECT_SOURCE_DIR}/libs/libchinadrm/include
    ${PROJECT_SOURCE_DIR}/thirdparty/huawei/libhwsecurec/include/libhwsecurec
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include/TEE_ext
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include/kernel
    ${PROJECT_SOURCE_DIR}/sys_libs/libhmdrv_stub/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libtimer_a32/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libtimer/inc
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

if (NOT "${TARGET_BUILD_VARIANT}" STREQUAL "user")
    list(APPEND MSPE_INCLUDE_PATH
        ${HISEE_SECENG_INCLUDE_DIR}/autotest/include
        ${HISEE_SECENG_INCLUDE_DIR}/autotest
        ${HISEE_SECENG_INCLUDE_DIR}/libseceng/mspe/test/include
        ${HISEE_SECENG_INCLUDE_DIR}/libseceng/mspe/test/include/common
        ${MSPE_PLATDRV_DIR}/autotest/custom/cdrm
        ${MSPE_PLATDRV_DIR}/autotest
        ${MSPE_PLATDRV_DIR}/autotest/include
    )
endif()
