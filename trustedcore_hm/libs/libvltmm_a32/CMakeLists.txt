add_custom_target(libvltmm_a32_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -Wno-unused-parameter
    -fno-builtin
)
list(APPEND TEE_C_DEFINITIONS CC_DRIVER=1)
list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/libs/libart/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/src
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-local-release/headers/libc_32/hm
)

if(${TARGET_BOARD_PLATFORM} STREQUAL "baltimore")
    if ("${chip_type}" STREQUAL "es")
        list(APPEND TEE_INCLUDE_PATH
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/include/platform/baltimore_es
        )
    else()
        list(APPEND TEE_INCLUDE_PATH
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/include/platform/baltimore
        )
    endif()
    list(APPEND TEE_C_DEFINITIONS TEE_SUPPORT_VLTMM_SRV)
endif()

list(APPEND TEE_C_FLAGS ${TRUSTEDCORE_PLATFORM_FLAGS})

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

tee_add_library(vltmm_a32 STATIC
    SOURCES
    src/bitmap.c
    src/genalloc.c
    src/vltmm_client_api.c

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
