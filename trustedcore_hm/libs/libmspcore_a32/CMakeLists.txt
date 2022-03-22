add_custom_target(libmspcore_a32_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS -fno-builtin)
list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/hisee
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/src
    ${PROJECT_SOURCE_DIR}/libs/libsec_flash_client_a32/src
    ${PROJECT_SOURCE_DIR}/libs/libart_a32/include
    ${PROJECT_SOURCE_DIR}/vendor/higeneric/libvendor_shared/src
)

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "baltimore")
    list(APPEND TEE_C_FLAGS -DCONFIG_HISI_MSPC)
endif()

if ("${CONFIG_HISI_MSPC_IPC_TEST}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS -DCONFIG_HISI_MSPC_IPC_TEST)
endif()

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

tee_add_library(mspcore_a32 STATIC
    SOURCES
    src/mspc_ext_api.c
    src/mspc_ipc_test_api.c
    src/msp_service_status.c
    src/msp_tee_se_ext_api.c

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
