add_custom_target(librot_a32_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -fno-builtin
    -DCC_DRIVER=1
)
list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/src
    ${PROJECT_SOURCE_DIR}/libs/libmspcore_a32/include
)

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "baltimore")
    list(APPEND TEE_C_FLAGS -DCONFIG_GENERIC_ROT)
endif()

list(APPEND TEE_C_FLAGS ${TRUSTEDCORE_PLATFORM_FLAGS})

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

tee_add_library(rot_a32 STATIC
    SOURCES
    src/rot_api.c
    src/rot_tlv.c
    src/rot_apdu.c

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
