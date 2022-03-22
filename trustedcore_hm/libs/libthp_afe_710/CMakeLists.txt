add_custom_target(libthp_afe_710_headers
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/../libthp_common/include/thp_afe.h ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -fno-builtin
    -Wall
    -Wextra
    -mfloat-abi=softfp
    -mfpu=neon
)

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/../libthp_common/include
)

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

tee_add_library(thp_afe_710 STATIC
    SOURCES
    src/thp_afe_platform.c
    ../libthp_common/src/thp_afe.c
    ../libthp_common/src/thp_afe_debug.c
    ../libthp_common/src/thp_afe_driver.c
    ../libthp_common/src/thp_afe_wrapper.c

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
