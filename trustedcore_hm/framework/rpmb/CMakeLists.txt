set(SVC_PARTITIAL_LINK y)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${PROJECT_SOURCE_DIR}/vendor/ascend/libvendor_shared/src/libhsm_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libcrypto_hal/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/crypto
    ${PROJECT_SOURCE_DIR}/drivers/include
)

if ("${CFG_TEE_RPMB_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/include
    )
    list(APPEND TEE_C_FLAGS
        -DCFG_TEE_RPMB_SUPPORT
    )
endif()

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND RPMB_LDFLAGS
        -Wl,--entry=tee_task_entry
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND RPMB_LIBRARIES
        rpmbagent
        zlib
        sec_fs
    )
else()
    list(APPEND RPMB_LIBRARIES
        rpmbagent_a32
        zlib_a32
        sec_fs_a32
    )
endif()

if ("${CONFIG_ADD_STRIP}" STREQUAL "y")
    list(APPEND RPMB_LDFLAGS
        -s
    )
endif()

if ("${CONFIG_HSM}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DTEE_SUPPORT_HSM
    )
endif()

if ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "boringssl")
    list(APPEND TEE_C_FLAGS
        -DBORINGSSL_ENABLE
    )
endif()

if ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "boringssl")
    list(APPEND TEE_INCLUDE_PATH
        ${PREBUILD_DIR}/headers/boringssl
    )
endif()

if ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "openssl")
    list(APPEND TEE_INCLUDE_PATH
        ${PREBUILD_DIR}/headers/openssl
    )
endif()

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

list(FIND PRODUCT_APPS "rpmb.elf" index)
if (${index} GREATER -1)
    if ("${CONFIG_RPMB_64BIT}" STREQUAL "true" AND "${ARCH}" STREQUAL "aarch64")
        set(IF_INSTALL DO_INSTALL)
    endif()
    if ("${CONFIG_RPMB_64BIT}" STREQUAL "false" AND "${ARCH}" STREQUAL "arm")
        set(IF_INSTALL DO_INSTALL)
    endif()
endif()

tee_add_executable(rpmb.elf
    SOURCES
    src/rpmb_key_stat.c
    src/tee_rpmb_oper_config.c

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
    ${RPMB_LDFLAGS}
    ${COMMON_LDFLAGS}

    LINKGROUP
    ${RPMB_LIBRARIES}
    ${COMMON_LIBGCC_COMPS}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
