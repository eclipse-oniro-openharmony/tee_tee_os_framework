set(TARGET_IS_HOST y)
include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND HOST_C_FLAGS
    -Wall
    -Wextra
    -std=gnu99
    -DHM_BUILD_TARGET_HOST
)

if ("${CONFIG_HW_SECUREC_MIN_MEM}" STREQUAL "y")
    list(APPEND HOST_C_FLAGS
        -DSECUREC_WARP_OUTPUT=1
        -DSECUREC_WITH_PERFORMANCE_ADDONS=0
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/libs/libvfs_host/include
    ${PREBUILD_HEADER}/libc/arch
    ${PREBUILD_HEADER}/libc/hm
)

tee_add_library(ramfs_host STATIC
    SOURCES
    src/tafs.c
    src/ramfs.c
    src/lock_ops.c

    COMPILE_TOOL
    host

    COMPILER_FLAGS
    ${HOST_C_FLAGS}

    PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    NO_INSTALL
)
