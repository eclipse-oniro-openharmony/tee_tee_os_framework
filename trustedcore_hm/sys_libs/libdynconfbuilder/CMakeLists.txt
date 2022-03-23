add_custom_target(libdynconfbuilder_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

if ("${CONFIG_DYN_CONF}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TEE_SUPPORT_DYN_CONF
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/sys_libs/libdynconfmgr/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libdynconfbuilder/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/drivers/tee_drv_server/src
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libspawn_common/include
)

tee_add_library(dynconfbuilder STATIC
    SOURCES
    src/drv_dyn_conf_builder.c
    src/drvcall_dyn_conf_builder.c
    src/ta_config_builder.c

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
