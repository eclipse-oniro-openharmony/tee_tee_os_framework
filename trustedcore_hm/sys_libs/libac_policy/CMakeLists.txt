add_custom_target(libac_policy_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_C_FLAGS
    -fno-builtin
)
if ("${CONFIG_HSM}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS TEE_SUPPORT_HSM)
endif()

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/hm_policy
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include/TEE_ext
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${PLATFORM_DIR}/common/hm_policy
)

tee_add_library(ac_policy STATIC
    SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/uuid.c
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/hm_policy/policy.c

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
