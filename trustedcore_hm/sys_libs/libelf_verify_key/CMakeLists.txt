add_custom_target(libelf_verify_key_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

if ("${CONFIG_SIGN_KEY_RELEASE_DEBUG_ISOLATION}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DSUPPORT_SIGN_KEY_RELEASE_DEBUG_ISOLATION
    )
endif()

if ("${chip_type}" STREQUAL "CS2")
    list(APPEND TEE_C_FLAGS
        -DWITH_CHIP_CS2
    )
else()
    list(APPEND TEE_C_FLAGS
        -DWITH_CHIP_CS
    )
endif()

if ("${CONFIG_DYN_TA_FORMAT}" STREQUAL "1")
    list(APPEND TEE_C_FLAGS
        -DDYN_TA_SUPPORT_V1
        -DDYN_TA_SUPPORT_V2
        -DDYN_TA_SUPPORT_V3
    )
elseif ("${CONFIG_DYN_TA_FORMAT}" STREQUAL "2")
    list(APPEND TEE_C_FLAGS
        -DDYN_TA_SUPPORT_V2
        -DDYN_TA_SUPPORT_V3
    )
elseif ("${CONFIG_DYN_TA_FORMAT}" STREQUAL "3")
    list(APPEND TEE_C_FLAGS
        -DDYN_TA_SUPPORT_V3
    )
else()
    message(FATAL_ERROR "dynamic TA format not supported, please check CONFIG_DYN_TA_FORMAT")
endif()

if ("${ENABLE_TA_LOAD_WHITE_BOX_KEY}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_WHITE_BOX_KEY
    )
endif()

list(APPEND TEE_C_SOURCES
    src/ta_load_config.c
    src/ta_load_key.c
    src/check_ta_version.c
    src/wb_tool_256_root_key.c
)

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/gtask/include
)

if ("${CONFIG_GENERIC_LOAD_KEY}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        src/higeneric/ta_key_data.c
        src/higeneric/wb_tool_128_root_key.c
        src/higeneric/ta_verify_key.c
    )
    list(APPEND TEE_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/src/higeneric
    )
    if (NOT "${ENABLE_TA_LOAD_WHITE_BOX_KEY}" STREQUAL "true")
        if (NOT "${CONFIG_DYN_TA_FORMAT}" STREQUAL "1")
            list(REMOVE_ITEM TEE_C_SOURCES
                src/higeneric/wb_tool_128_root_key.c
            )
        endif()
        list(REMOVE_ITEM TEE_C_SOURCES
            src/wb_tool_256_root_key.c
        )
    endif()
endif()

if ("${CONFIG_PUBKEY_SHAREMEM}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        src/common/ta_key_data.c
        src/common/ta_verify_key.c
    )
    list(APPEND TEE_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/src/common
    )
    list(APPEND TEE_C_FLAGS
        -DCONFIG_PUBKEY_SHAREMEM
    )
endif()

if ("${CONFIG_KUNPENG_LOAD_KEY}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        src/kunpeng/ta_key_data.c
        src/kunpeng/ta_verify_key.c
    )
    list(APPEND TEE_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kunpeng
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kunpeng/ecies_keys
    )
endif()

if ("${CONFIG_ASCEND_LOAD_KEY}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        src/ascend/ta_key_data.c
        src/ascend/ta_verify_key.c
    )
    list(APPEND TEE_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ascend
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ascend/ecies_keys
    )
    if ("${product_type}" STREQUAL "mdc")
        list(APPEND TEE_C_FLAGS
            -DCONFIG_TA_DECRYPT_ECIES_MDC
        )
    elseif ("${product_type}" STREQUAL "mini")
        list(APPEND TEE_C_FLAGS
            -DCONFIG_TA_DECRYPT_ECIES_MINI
        )
    endif()
endif()

if ("${CONFIG_HUANGLONG_LOAD_KEY_3072}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/src/huanglong/ecies_keys
    )
endif()

if ("${CONFIG_OH_LOAD_KEY}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        src/openharmony/ta_verify_key.c
        src/common/ta_key_data.c
    )
endif()

if ("${product_type}" STREQUAL "cdc")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_TA_SIGN_CDC
    )
elseif ("${product_type}" STREQUAL "mdc")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_TA_SIGN_MDC
    )
elseif ("${product_type}" STREQUAL "mini")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_TA_SIGN_MINI
    )
elseif ("${CONFIG_TA_SIGN_KEY_CBG}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_TA_SIGN_CBG
    )
elseif ("${CONFIG_TA_LOCAL_SIGN}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DTA_LOCAL_SIGN
    )
elseif ("${CONFIG_HUANGLONG_LOAD_KEY_3072}" STREQUAL "y")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_TA_SIGN_HUANGLONG
    )
endif()

list(APPEND TEE_C_FLAGS
    -fstack-protector-all
)

if ("${CONFIG_PLAT_HUANGLONG}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/platform/huanglong/ta_load/tee_ta_load.c
    )
endif()

list(APPEND TEE_C_FLAGS ${TRUSTEDCORE_PLATFORM_FLAGS})
list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

list(REMOVE_ITEM TEE_C_FLAGS "-flto")
list(REMOVE_ITEM TEE_C_FLAGS "-fsplit-lto-unit")

tee_add_library(elf_verify_key STATIC
    SOURCES
    ${TEE_C_SOURCES}
    src/ta_load_key.c

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    ${TEE_C_FLAGS}

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    NO_INSTALL
)
