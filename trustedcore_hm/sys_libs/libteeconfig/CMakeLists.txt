add_custom_target(libteeconfig_headers
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/crypto_syscal_types.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hwi_drv_call.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/root_status_ops.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/sre_syscalls_id.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/tee_sharemem.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/TEE_ext/sre_syscalls_ext.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/TEE_ext/sre_syscalls_id_ext.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/TEE_ext/tee_bit_ops.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/kernel/sre_access_control.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/kernel/sre_rwroot.h ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_C_FLAGS
    -fno-builtin
    -DTARGET_PRODUCT_VAL=\"${TARGET_BOARD_PLATFORM}\"
)

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "baltimore")
    list(APPEND TEE_C_DEFINITIONS
        CONFIG_GENERIC_ROT
        CONFIG_GENERIC_ART
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include/TEE_ext
    ${CMAKE_CURRENT_SOURCE_DIR}/include/kernel
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${PROJECT_SOURCE_DIR}/drivers/base_mgr/tee_misc_driver/src
    ${PLATFORM_DIR}/common/include
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
)

if ("${CONFIG_TEE_MISC_DRIVER_64BIT}" STREQUAL "true" OR "${CONFIG_TEE_MISC_DRIVER_64BIT}" STREQUAL "false")
    list(APPEND TEE TEE_C_DEFINITIONS
        CONFIG_TEE_MISC_DRIVER
    )
endif()

if ("${CONFIG_SUPPORT_GET_DIEID}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        CONFIG_SUPPORT_GET_DIEID
    )
endif()

if ("${CONFIG_DYN_CONF}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TEE_SUPPORT_DYN_CONF
    )
endif()

if ("${CONFIG_HISI_MSPC_IPC_TEST}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        CONFIG_HISI_MSPC_IPC_TEST
    )
endif()

list(APPEND TEE_C_FLAGS
    ${TRUSTEDCORE_PLATFORM_FLAGS}
)

if("${CONFIG_TEST_CA_CHECK}" STREQUAL "y")
    set(TEST_CA_CHECK_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tee_test_config/tee_test_calist.c
    )
endif()

tee_add_library(teeconfig STATIC
    SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/drv_hal/antiroot.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/drv_hal/drvcalls.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/drv_hal/tee_drv_client.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tee_config/tee_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tee_config/tee_config_hal.c
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config/product_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tee_config/product_config_hal.c
    ${TEST_CA_CHECK_SRC}

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
