add_custom_target(libdrv_frame_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_var_and_config)

list(APPEND TEE_C_FLAGS
    -fno-builtin
)
list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libtimer/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libccmgr/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${PROJECT_SOURCE_DIR}/drivers/common
    ${PROJECT_SOURCE_DIR}/platform/common/tee_config
    ${PREBUILD_DIR}/headers/sys/hmapi
)
list(APPEND TEE_C_SOURCES
    src/libdrv_frame.c
    src/drv_thread.c
    src/drv_param_ops.c
)

tee_add_library(drv_frame STATIC
    SOURCES
    ${TEE_C_SOURCES}

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
