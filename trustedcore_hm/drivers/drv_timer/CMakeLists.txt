set(ENTRY_POINT main)
include(apps_drv_flags)
include(apps_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

if (EXISTS ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/timer/cmake)
    include(${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/timer/cmake/timer_config.cmake)
endif()
include(${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/modules/timer_common.cmake)

if ("${ARCH}" STREQUAL "arm")
    set(USE_GNU_CXX y)
endif()

list(APPEND TEE_INCLUDE_PATH
    ${PREBUILD_DIR}/headers/ddk
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${PROJECT_SOURCE_DIR}/drivers/common
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/crypto
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/src
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libdrv_frame/include
    ${PREBUILD_HEADER}/sys/stackprotect
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/timer/include
)

if ("${chip_type}" STREQUAL "es")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/../../../../hisi/ap/platform/${TARGET_BOARD_PLATFORM}_es
    )
else()
    if ("${chip_type}" STREQUAL "cs2")
        list(APPEND TEE_INCLUDE_PATH
            ${PROJECT_SOURCE_DIR}/../../../../hisi/ap/platform/${TARGET_BOARD_PLATFORM}_cs2
        )
    else()
        list(APPEND TEE_INCLUDE_PATH
            ${PROJECT_SOURCE_DIR}/../../../../hisi/ap/platform/${TARGET_BOARD_PLATFORM}
        )
    endif()
endif()

if ("${CONFIG_SOFT_RTC_TICK}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        SOFT_RTC_TICK
        SOFT_RTC_IRQ_DISABLE
    )
endif()

if ("${CONFIG_SOFT_RTC_TICK}" STREQUAL "false")
    list(APPEND TEE_C_DEFINITIONS
        SOFT_RTC_IRQ_DISABLE
    )
endif()

if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        DX_ENABLE=1
    )
endif()

if ("${CONFIG_TIMER_S3_ADJUST_FREQ}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TIMER_S3_ADJUST_FREQ
    )
endif()

if ("${CONFIG_RESUME_FREE_TIMER}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        RESUME_FREE_TIMER_FEATURE
    )
endif()

if ("${CONFIG_TIMER_PERMISSION_DISABLE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TIMER_PERMISSION_DISABLE
    )
endif()

if ("${CONFIG_TIMER_FREERUNNING_FIQ_DISABLE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TIMER_FREE_RUNNING_FIQ_DISABLE
    )
endif()

list(APPEND TEE_C_SOURCES
    src/main.c
    src/timer_init.c
    src/timer_irq.c
    src/timer_pm.c
    src/timer_sys.c
    src/timer_desc.c
    src/timer_interrupt.c
    ${PROJECT_SOURCE_DIR}/drivers/common/drv_call_check.c
    ${PROJECT_SOURCE_DIR}/drivers/common/drv_pm_check.c
)

if ("${CONFIG_TIMER_EVENT}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        src/timer_event.c
    )
    list(APPEND TEE_C_DEFINITIONS
        TIMER_EVENT_SUPPORT
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND DRV_TIMER_LIBRARIES
        c_shared
        io
        teeos
        teemem
        hwi
        ac
        ccmgr
        crypto_hal
        teeconfig
        hmdrv
        hmdrv_stub
        ac_policy
    )
    list(APPEND DRV_TIMER_LDFLAGS
        -Wl,-z,text
        -Wl,-z,noexecstack
        -Wl,--dynamic-linker=libc_shared.so
    )
else()
    list(APPEND DRV_TIMER_LIBRARIES
        c_shared_a32
        io_a32
        teeos_a32
        teemem_a32
        hwi_a32
        ac_a32
        ccmgr
        crypto_hal
        teeconfig
        hmdrv_a32
        hmdrv_stub
        ac_policy
    )
    list(APPEND DRV_TIMER_LDFLAGS
        -Wl,-z,text
        -Wl,-z,noexecstack
        -Wl,--dynamic-linker=libc_shared_a32.so
    )
endif()

if ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "openssl")
    list(APPEND DRV_TIMER_LIBRARIES
        openssl
    )
endif()

if(NOT "${CMAKE_TOOLCHAIN_BASEVER}" STREQUAL "8.0.1")
    list(APPEND DRV_TIMER_LDFLAGS
        -Wl,-z,separate-loadable-segments
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND DRV_TIMER_LDFLAGS
        -Wl,-T${CMAKE_CURRENT_SOURCE_DIR}/linker64.ld
    )
else()
    if ("${CONFIG_ENABLE_XOM32}" STREQUAL "y")
        list(APPEND DRV_TIMER_LDFLAGS
            -Wl,-T${CMAKE_CURRENT_SOURCE_DIR}/linker.xom.ld
        )
    else()
        list(APPEND DRV_TIMER_LDFLAGS
            -Wl,-T${CMAKE_CURRENT_SOURCE_DIR}/linker.ld
        )
    endif()
endif()

list(REMOVE_ITEM TEE_C_FLAGS -Os)
list(APPEND TEE_C_FLAGS -O0)

list(FIND PRODUCT_APPS "drv_timer.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(drv_timer.elf
    SOURCES
    ${TEE_C_SOURCES}

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    ${TEE_C_FLAGS}

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    LD_FLAGS
    ${DRV_LDFLAGS}
    ${DRV_TIMER_LDFLAGS}
    ${COMMON_LDFLAGS}

    LINKGROUP
    ${DRV_TIMER_LIBRARIES}
    ${COMMON_LIBGCC_COMPS}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)

