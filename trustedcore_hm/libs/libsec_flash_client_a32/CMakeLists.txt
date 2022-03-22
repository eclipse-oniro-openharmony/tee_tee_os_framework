add_custom_target(libsec_flash_client_a32_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS -fno-builtin)
list(APPEND TEE_C_FLAGS -DRESERVE_TA_PERM)
list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/src
    ${PROJECT_SOURCE_DIR}/vendor/higeneric/libvendor_shared/src
)

if(${TARGET_BOARD_PLATFORM} STREQUAL "kirin990")
    list(APPEND TEE_C_DEFINITIONS CONFIG_HISI_SECFLASH)
elseif (TARGET_BOARD_PLATFORM} STREQUAL "baltimore")
    list(APPEND TEE_C_DEFINITIONS HISI_MSP_SECFLASH)
endif()

list(APPEND TEE_C_FLAGS ${TRUSTEDCORE_PLATFORM_FLAGS})

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

tee_add_library(sec_flash_client_a32 STATIC
    SOURCES
    src/sec_flash_api.c
    src/sec_flash_ext_api.c

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
