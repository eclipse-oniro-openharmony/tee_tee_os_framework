include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PLATFORM_DIR}/common/include
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${PROJECT_SOURCE_DIR}/drivers/base_mgr/tee_misc_driver/src
)

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND PERMISSION_SERVICE_LDFLAGS
        -Wl,--entry=tee_task_entry
    )
endif()

if ("${CONFIG_HUK_PLAT_COMPATIBLE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TEE_HUK_PLAT_COMPATIBLE
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND PERMISSION_SERVICE_LIBRARIES
        permsrv elf_verify elf_verify_key whitebox dynconfmgr dynconfbuilder base_shared
    )
else()
    list(APPEND PERMISSION_SERVICE_LIBRARIES
        permsrv_a32 elf_verify_a32 elf_verify_key whitebox_a32 dynconfmgr dynconfbuilder base_shared
    )
endif()

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

list(FIND PRODUCT_APPS "permission_service.elf" index)
if (${index} GREATER -1)
    if ("${CONFIG_PERMSRV_64BIT}" STREQUAL "true" AND "${ARCH}" STREQUAL "aarch64")
        set(IF_INSTALL DO_INSTALL)
    endif()
    if ("${CONFIG_PERMSRV_64BIT}" STREQUAL "false" AND "${ARCH}" STREQUAL "arm")
        set(IF_INSTALL DO_INSTALL)
    endif()
endif()

if ("${CONFIG_CMS_CAHASH_AUTH}" STREQUAL "y")
    list(APPEND PERMISSION_SERVICE_LIBRARIES
        cmscbb tee_cmscbb
    )
    list(APPEND TEE_C_SOURCES
         src/auth/tee_auth_sign_cms.c
     )
    list(APPEND TEE_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/src/auth/tee_auth_sign_cms.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../sys_libs/libtee_cmscbb/include
    )
else()
    list(APPEND TEE_C_SOURCES
        src/auth/tee_auth_sign_rsa.c
    )
    list(APPEND TEE_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/src/auth/tee_auth_sign_rsa.h
    )
endif()

tee_add_executable(permission_service.elf
    SOURCES
    src/root_cert_info.c
    src/ta_permission_config.c
    src/ca_hashfile_config.c
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
    ${PERMISSION_SERVICE_LDFLAGS}

    LIBRARIES
    ${PERMISSION_SERVICE_LIBRARIES}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
