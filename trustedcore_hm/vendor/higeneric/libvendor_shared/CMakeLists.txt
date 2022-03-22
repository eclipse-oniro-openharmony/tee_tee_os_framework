include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_C_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/chip_info.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/extra_syms.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/hdcp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/hisi_mspc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/inse.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/secboot.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/secflash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/file_encry_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/fp_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/fr_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/hisi_hieps_task.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/hisi_privacy_protection_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/hisi_secboot_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/npu_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/secmem_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/vdecry_drv.c
    ${PROJECT_SOURCE_DIR}/vendor/common/src/chip_info.c
    ${PROJECT_SOURCE_DIR}/vendor/common/src/tee_crypto_kds_api.c
    ${PROJECT_SOURCE_DIR}/libs/libsec_flash_client/src/sec_flash_api.c
)

if ("${CONFIG_SE_SERVICE_32BIT}" STREQUAL "true" OR "${CONFIG_SE_SERVICE_64BIT}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/se_status.c
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
    ${PROJECT_SOURCE_DIR}/vendor/common/include
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${PROJECT_SOURCE_DIR}/libs/libsec_flash_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/src
    ${PROJECT_SOURCE_DIR}/libs/libvltmm_a32/include
)

if ("${TARGET_BUILD_VARIANT}" STREQUAL "user")
    list(APPEND TEE_C_FLAGS
        -DDEF_BUILDUSERMODE
    )
endif()

if ("${CONFIG_HISI_MSPC_IPC_TEST}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_HISI_MSPC_IPC_TEST
    )
endif()

list(APPEND VENDOR_SHARED_LIBRARIES
    mspcore
    rot
    art
    biometric
    sec_flash_client
    chinadrm
)

if ("${CONFIG_WEAVER}" STREQUAL "true")
    list(APPEND VENDOR_SHARED_LIBRARIES
        weaver
    )
endif()

if ("${CONFIG_VLTMM_SRV}" STREQUAL "true")
    list(APPEND VENDOR_SHARED_LIBRARIES
        vltmm
    )
endif()

list(APPEND VENDOR_SHARED_LINKER_FLAGS
    -Wl,--shared
    -Wl,-X
    -Wl,-EL
    -Wl,-z,text
    -Wl,-z,now
    -Wl,-z,relro
    -Wl,-z,noexecstack
    -Wl,--gc-sections
    -Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/export.txt
    -Wl,-L${PREBUILD_LIBS}/${ARCH}
    -nostdlib
    -Wl,-z,max-page-size=4096
    ${CMAKE_CURRENT_BINARY_DIR}/extern.txt
)

if ("${ARCH}" STREQUAL "arm" AND "${CONFIG_ENABLE_XOM32}" STREQUAL "y")
    list(APPEND VENDOR_SHARED_LINKER_FLAGS
        -Wl,-T${XOM_LIB_LDS}
    )
endif()

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

set(TEE_PRECOMPILE_FLAGS ${TEE_C_FLAGS})
list(REMOVE_ITEM TEE_PRECOMPILE_FLAGS "-march=armv8-a")
foreach(d ${TEE_C_DEFINITIONS})
    list(APPEND TEE_PRECOMPILE_FLAGS -D${d})
endforeach()

add_custom_target(kirin_vendor_shared_export)
add_custom_target(kirin_vendor_shared_extern)
add_custom_command(
    TARGET kirin_vendor_shared_export
    COMMAND ${CMAKE_C_COMPILER} ${TEE_PRECOMPILE_FLAGS} -x assembler-with-cpp -E --no-line-commands ${CMAKE_CURRENT_SOURCE_DIR}/export.txt -o ${CMAKE_CURRENT_BINARY_DIR}/export.txt
)
add_custom_command(
    TARGET kirin_vendor_shared_extern
    COMMAND ${CMAKE_C_COMPILER} ${TEE_PRECOMPILE_FLAGS} -x assembler-with-cpp -E --no-line-commands ${CMAKE_CURRENT_SOURCE_DIR}/extern.txt -o ${CMAKE_CURRENT_BINARY_DIR}/extern.txt
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
    ${LIB_VENDOR_FLAGS}

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
if ("${BUILD_TOOL}" STREQUAL "clang")
    add_dependencies(vendor_shared kirin_vendor_shared_extern kirin_vendor_shared_export)
endif()
