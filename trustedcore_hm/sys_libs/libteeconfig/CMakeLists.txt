add_custom_target(libteeconfig_headers
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/crypto_syscal_types.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/dynion_types.h ${HDR_L_DIR}
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
        HISI_MSP_SECFLASH
        CONFIG_GENERIC_ART
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include/TEE_ext
    ${CMAKE_CURRENT_SOURCE_DIR}/include/kernel
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/include/platform/${TARGET_BOARD_PLATFORM}
)

if ("${CONFIG_TEE_MISC_DRIVER_64BIT}" STREQUAL "true" OR "${CONFIG_TEE_MISC_DRIVER_64BIT}" STREQUAL "false")
    list(APPEND TEE TEE_C_DEFINITIONS
        CONFIG_TEE_MISC_DRIVER
    )
endif()

if ("${CONFIG_HSM}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TEE_SUPPORT_HSM
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

tee_add_library(teeconfig STATIC
    SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/antiroot.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/drvcalls.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mem_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tee_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tee_drv_client.c
    ${PLATFORM_DIR}/common/tee_config/teeos_config.c
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config/product_config.c

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
