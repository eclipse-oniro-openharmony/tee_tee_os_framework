add_custom_target(libchinadrm_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS -Wno-unused-parameter -Wno-pointer-to-int-cast -fno-builtin)
list(APPEND TEE_INCLUDE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include)

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

tee_add_library(chinadrm STATIC
    SOURCES
    src/chinadrm_manager.c

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
