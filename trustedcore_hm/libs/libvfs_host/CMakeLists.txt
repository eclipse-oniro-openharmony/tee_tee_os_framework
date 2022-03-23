set(TARGET_IS_HOST y)
include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND HOST_C_FLAGS
    -Wall
    -Wextra
    -Werror
    -DHM_BUILD_TARGET_HOST
)

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PREBUILD_HEADER}/libc/hm
    ${PREBUILD_HEADER}
)

if ("${CONFIG_HW_SECUREC_MIN_MEM}" STREQUAL "y")
    list(APPEND HOST_C_FLAGS
        -DSECUREC_WARP_OUTPUT=1
        -DSECUREC_WITH_PERFORMANCE_ADDONS=0
    )
endif()

tee_add_library(vfs_host STATIC
    SOURCES
    src/vfs.c
    src/tee_bitmap.c

    COMPILE_TOOL
    host

    COMPILER_FLAGS
    ${HOST_C_FLAGS}

    PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    NO_INSTALL
)
