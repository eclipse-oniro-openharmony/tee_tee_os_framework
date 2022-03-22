include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -DCC_DRIVER
    -Wall
    -DSECFLASH_PARTITION_HIGH_HALF_ENABLE
    -Wno-unused-parameter
)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon/src/
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/libc_32/hm
    ${PREBUILD_DIR}/headers/ddk/hmapi
    ${PREBUILD_DIR}/headers/ddk/legacy
    ${PROJECT_SOURCE_DIR}/platform/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/secmem/include
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
    ${PROJECT_SOURCE_DIR}/vendor/higeneric/libvendor_shared/src/driver_api/
)

list(APPEND TEE_C_SOURCES
    src/bitmap.c
    src/vltmm_service.c
)

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "baltimore")
    if ("${chip_type}" STREQUAL "es")
        list(APPEND TEE_INCLUDE_PATH
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/include/platform/baltimore_es
        )
    else()
        list(APPEND TEE_INCLUDE_PATH
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/include/platform/baltimore
        )
    endif()
endif()

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND VLTMM_SERVICE_LDFLAGS
        -Wl,--entry=tee_task_entry
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND ANTIROOT_LIBRARIES
        teeagentcommon
        agent_base
    )
else()
    list(APPEND ANTIROOT_LIBRARIES
        teeagentcommon
        agent_base_a32
    )
endif()

list(FIND PRODUCT_APPS "vltmm_service.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(vltmm_service.elf
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
    ${TA_LDFLAGS}
    ${VLTMM_SERVICE_LDFLAGS}

    LINKGROUP
    ${ANTIROOT_LIBRARIES}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
