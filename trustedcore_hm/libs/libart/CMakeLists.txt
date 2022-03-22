add_custom_target(libart_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS -fno-builtin)
list(APPEND TEE_C_DEFINITIONS CC_DRIVER=1 RESERVE_TA_PERM)
list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libart/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/src
)

if(${TARGET_BOARD_PLATFORM} STREQUAL "baltimore")
    list(APPEND TEE_C_DEFINITIONS CONFIG_GENERIC_ART)
endif()

list(APPEND TEE_C_FLAGS ${TRUSTEDCORE_PLATFORM_FLAGS})

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

tee_add_library(art STATIC
    SOURCES
    src/art_api.c

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
