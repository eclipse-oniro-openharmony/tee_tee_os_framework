include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_C_FLAGS
    -Wall
    -Wextra
    -Werror
    -DKEYMASTER_ITRATION_TIMES=${GATEKEEPER_ITRATION_TIMES}
    -DDERIVE_ROOT_INTERNAL_ITRATIONS=${DERIVE_ROOT_INTERNAL_ITRATIONS}
    -DCFG_TEE_KEYMASTER_ENHANCED_KEY
)

list(APPEND TEE_C_SOURCES
    task_keymaster/km_auth.c
    task_keymaster/km_cmd_auth.c
    task_keymaster/km_cmd_handle.c
    task_keymaster/km_cmd_handle_provision.c
    task_keymaster/km_cmd_params_check.c
    task_keymaster/km_key_node.c
    task_keymaster/km_main.c
    task_keymaster/km_rollback_resistance.c
    task_keymaster/km_tag_operation.c
    task_keymaster/km_keyblob/km_3des_weak_keys.c
    task_keymaster/km_keyblob/km_key_adaptor.c
    task_keymaster/km_keyblob/km_keyblob.c
    task_keymaster/km_keyblob/km_keyblob_check.c
    task_keymaster/km_keyblob/km_keyblob_crypto.c
    task_keymaster/km_keyblob/km_keyblob_dx2gp.c
    task_keymaster/km_keyblob/km_keyblob_export.c
    task_keymaster/km_keyblob/km_keyblob_generate.c
    task_keymaster/km_keyblob/km_keyblob_import.c
    task_keymaster/km_keyblob/km_keyblob_upgrade.c
    task_keymaster/km_keyblob/km_key_params.c
    task_keymaster/km_keyblob/km_key_gp.c
    task_keymaster/km_keyblob/km_key_gp_sw_convert.c
    task_keymaster/whitebox/wb_aes_decrypt.c
    task_keymaster/whitebox/wb_aes_util.c
    task_keymaster/km_attest/km_attest.c
    task_keymaster/km_attest/km_attest_check.c
    task_keymaster/km_attest/km_attest_default_certs.c
    task_keymaster/km_attest/km_attest_factory.c
    task_keymaster/km_attest/km_attest_id.c
    task_keymaster/km_attest/km_attest_provision.c
    task_keymaster/km_attest/km_attest_file_ops.c
    task_keymaster/km_crypto/km_crypto_3des.c
    task_keymaster/km_crypto/km_crypto_adaptor.c
    task_keymaster/km_crypto/km_crypto_aes.c
    task_keymaster/km_crypto/km_crypto.c
    task_keymaster/km_crypto/km_crypto_check.c
    task_keymaster/km_crypto/km_crypto_ecdsa.c
    task_keymaster/km_crypto/km_crypto_hmac.c
    task_keymaster/km_crypto/km_crypto_rsa.c
    task_keymaster/km_crypto/km_crypto_sw_engine.c
    task_keymaster/km_crypto/gp_sw_adaptor.c
    task_keymaster/km_crypto/km_gp_adaptor.c
    task_keymaster/km_crypto/km_sw_adaptor.c
    task_keymaster/km_sys/km_common.c
    task_keymaster/km_sys/km_env.c
    task_keymaster/km_sys/km_file_ops.c
    task_keymaster/km_key_enhanced.c
    task_keymaster/km_key_enhanced.h
)
list(APPEND TEE_INCLUDE_PATH
    ${PREBUILD_DIR}/headers/boringssl
    ${PROJECT_SOURCE_DIR}/sys_apps/keymaster/task_keymaster/whitebox
    ${PROJECT_SOURCE_DIR}/sys_apps/keymaster/task_keymaster/include
    ${PROJECT_SOURCE_DIR}/sys_apps/keymaster/task_keymaster
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
)
list(APPEND TEE_C_DEFINITIONS
    API_LEVEL=3
)

if ("${ARCH}" STREQUAL "aarch64" AND "${CONFIG_MTK_BOOT_INFO}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DMTK_BOOT_INFO
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TEE_INCLUDE_PATH
        ${DDK_INCLUDE_PATH_COMMON}
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/sys_libs/libccmgr/include
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
)

if ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "boringssl")
    list(APPEND TEE_INCLUDE_PATH
        ${PREBUILD_HEADER}/boringssl
    )
    list(APPEND TEE_C_FLAGS
        -DBORINGSSL_ENABLE
    )
else()
    list(APPEND TEE_INCLUDE_PATH
        ${PREBUILD_HEADER}/openssl
    )
    list(APPEND TEE_C_FLAGS
        -DOPENSSL_ENABLE
    )
endif()

if ("${ARCH}" STREQUAL "arm" AND "${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/sys_libs/libta_magic_a32/src/ta_magic.c
    )
endif()

list(FIND PRODUCT_APPS "keymaster.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(keymaster.elf
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

    LD_FLAGS
    ${TA_LDFLAGS}
    ${COMMON_LDFLAGS}

    LINKGROUP
    ${COMMON_LIBGCC_COMPS}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
