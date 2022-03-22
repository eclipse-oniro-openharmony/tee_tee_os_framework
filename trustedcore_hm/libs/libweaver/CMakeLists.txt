add_custom_target(libweaver_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -fno-builtin
    -Wall
    -Wextra
)
list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/libs/libsec_flash_client/src
    ${PROJECT_SOURCE_DIR}/libs/libmspcore/include
)

if(${TARGET_BOARD_PLATFORM} STREQUAL "baltimore")
    list(APPEND TEE_C_DEFINITIONS SUPPORT_MSP_WEAVER)
endif()

list(APPEND TEE_C_FLAGS ${TRUSTEDCORE_PLATFORM_FLAGS})

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

add_definitions(-DTA_SLOG_LEVEL=2)

tee_add_library(weaver STATIC
    SOURCES
    src/weaver_api.c

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
