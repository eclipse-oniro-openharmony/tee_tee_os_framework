set(SVC_PARTITIAL_LINK y)
include(apps_drv_flags)
include(apps_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_C_FLAGS
    -Wall
    -Wextra
    -Werror
    -Wno-unused-parameter
    -Wno-implicit-fallthrough
    -Wno-main
    -DCONFIG_MISC_DRIVER=1
    -DTA_LOG_LEVEL=2
)

if ("${CONFIG_ENABLE_XOM32}" STREQUAL "y" AND "${ARCH}" STREQUAL "arm")
    list(APPEND TEE_MISC_DRIVER_LDFLAGS
        -Wl,-T${XOM_LDS}
    )
endif()

if ("${CONFIG_ENABLE_XOM}" STREQUAL "y" AND "${ARCH}" STREQUAL "aarch64")
    list(APPEND TEE_MISC_DRIVER_LDFLAGS
        -Wl,--execute-only
    )
endif()

if(NOT "${CMAKE_TOOLCHAIN_BASEVER}" STREQUAL "8.0.1")
    list(APPEND TEE_MISC_DRIVER_LDFLAGS
        -Wl,-z,separate-loadable-segments
    )
endif()

list(REMOVE_ITEM TEE_C_FLAGS -fvisibility=hidden)
list(REMOVE_ITEM TEE_C_FLAGS -flto)
list(REMOVE_ITEM TEE_C_FLAGS -fsplit-lto-unit)

list(APPEND TEE_INCLUDE_PATH
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-local-release/headers/ddk/hmapi
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-local-release/headers/sys/hmapi
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-local-release/headers/ddk/legacy
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${PROJECT_SOURCE_DIR}/drivers/tee_drv_server/src
    ${PROJECT_SOURCE_DIR}/drivers/base_mgr/tee_misc_driver/src
    ${PROJECT_SOURCE_DIR}/drivers/base_mgr/crypto_mgr/src/crypto_ioctl
    ${PROJECT_SOURCE_DIR}/sys_libs/libdrv_frame/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libdynconfmgr/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libspawn_common/include
    ${PROJECT_SOURCE_DIR}/drivers/common
)

# Source files required to build the target
set(TEE_C_SOURCES
    ${TEE_C_SOURCES}
    src/tee_misc_driver.c
    src/drv_sharedmem.c
    src/tee_oemkey_driver.c
)

list(FIND PRODUCT_APPS "tee_misc_driver.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(tee_misc_driver.elf
    C_SOURCES
    ${TEE_C_SOURCES}

    COMPILE_TOOL
    clang

    C_COMPILER_FLAGS
    ${TEE_C_FLAGS}

    C_PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    CPP_PRIVATE_INCLUDES
    ${TEE_CPP_INCLUDE_PATH}

    C_COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    CPP_COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    LD_FLAGS
    ${DRV_LDFLAGS}
    ${TEE_MISC_DRIVER_LDFLAGS}

    LINKGROUP
    ${CPP_LIBRARIES}
    ${TEE_MISC_DRIVER_LIBRARIES}
    -lgcc

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
