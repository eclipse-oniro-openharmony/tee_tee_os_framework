include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_C_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/chip_info.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/drv_call.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/extra_syms.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hdcp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/inse.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/secboot.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/driver_api/fp_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/driver_api/fr_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/driver_api/hisi_secboot_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/driver_api/secmem_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/driver_api/vdecry_drv.c
    ${PROJECT_SOURCE_DIR}/vendor/common/src/chip_info.c
    ${PROJECT_SOURCE_DIR}/vendor/common/src/tee_crypto_kds_api.c
)

if ("${CONFIG_SE_SERVICE_32BIT}" STREQUAL "true" OR "${CONFIG_SE_SERVICE_64BIT}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/se_status.c
    )
endif()

file(GLOB DRIVER_API_UNI src/driver_api_uni/*.c)

list(APPEND TEE_C_SOURCES
    ${DRIVER_API_UNI}
)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
    ${PROJECT_SOURCE_DIR}/vendor/common/include
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${PROJECT_SOURCE_DIR}/vendor/${PLATFORM_NAME}/libvendor_shared/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libtimer/include
)

if ("${TARGET_BUILD_VARIANT}" STREQUAL "user")
    list(APPEND TEE_C_DEFINITIONS
        DEF_BUILDUSERMODE
    )
endif()

list(APPEND VENDOR_SHARED_LINKER_FLAGS
    -Wl,-shared
    -Wl,-X
    -Wl,-EL
    -Wl,-z,text
    -Wl,-z,now
    -Wl,-z,relro
    -Wl,-z,noexecstack
    -Wl,--gc-sections
    -L${PREBUILD_LIBS}/${ARCH}
    -nostdlib
    -Wl,-z,max-page-size=4096
    ${CMAKE_CURRENT_SOURCE_DIR}/extern.txt
)

list(FIND PRODUCT_APPS "vendor_shared" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_library(vendor_shared SHARED
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

    LINKER_FLAGS
    ${CHOOSE_LLD}
    ${VENDOR_SHARED_LINKER_FLAGS}
    ${COMMON_LDFLAGS}

    LINKGROUP
    ${VENDOR_SHARED_LIBRARIES}
    ${COMMON_LIBGCC_COMPS}

    LIBS_INSTALL_PATH
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
if ("${ARCH}" STREQUAL "arm")
    set_target_properties(vendor_shared PROPERTIES OUTPUT_NAME "vendor_shared_a32")
endif()
