include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -DAPI_LEVEL=3
)

list(APPEND TEE_INCLUDE_PATH
    ${PLATFORM_DIR}/common/tee_config
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/crypto
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${PREBUILD_DIR}/headers/openssl
)

list(APPEND TEE_C_SOURCES
    src/crypto_operation.c
    src/gp_api_adapt_big_data.c
    src/gp_api_adapt_small_data.c
    src/gp_api_adapt_util.c
    src/gp_keyblob_operation.c
    src/invoke.c
    src/invoke_check.c
    src/invoke_function.c
    src/kms_key_node.c
    src/kms_tag_api.c
    src/kms_asn1_api.c
    src/volatile_key.c
    src/kms_key_storage.c
    src/kms_file_ops.c
    src/kdf.c
    src/kms_params_check.c
    src/permission_check.c
)

list(FIND PRODUCT_APPS "kms.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(kms.elf
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

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
