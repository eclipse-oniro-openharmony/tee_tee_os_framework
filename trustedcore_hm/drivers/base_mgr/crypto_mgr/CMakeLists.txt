include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_INCLUDE_PATH
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${DDK_INCLUDE_PATH_COMMON}
    ${PROJECT_SOURCE_DIR}/drivers/tee_drv_server/src
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${PROJECT_SOURCE_DIR}/drivers/common
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/src
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/crypto
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
    ${PROJECT_SOURCE_DIR}/platform/ascend/mdc/hi1951/platdrv/include
    ${PROJECT_SOURCE_DIR}/platform/higeneric/phone/common/include
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libdrv_frame/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libdrv_shared/src
    ${PROJECT_SOURCE_DIR}/drivers/base_mgr/crypto_mgr/src/crypto_ioctl/

)

list(APPEND TEE_C_SOURCES
    src/crypto_ioctl/crypto_syscall.c
    src/crypto_ioctl/crypto_syscall_ae.c
    src/crypto_ioctl/crypto_syscall_cipher.c
    src/crypto_ioctl/crypto_syscall_common.c
    src/crypto_ioctl/crypto_syscall_derive_key.c
    src/crypto_ioctl/crypto_syscall_ec.c
    src/crypto_ioctl/crypto_syscall_hash.c
    src/crypto_ioctl/crypto_syscall_hmac.c
    src/crypto_ioctl/crypto_syscall_oemkey.c
    src/crypto_ioctl/crypto_syscall_random.c
    src/crypto_ioctl/crypto_syscall_rsa.c
    src/crypto_mgr.c
)

tee_add_executable(crypto_mgr.elf
    SOURCES
    ${TEE_C_SOURCES}

    COMPILE_TOOL
    clang

    COMPILER_FLAGS

    COMPILER_DEFINITIONS

    PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    LD_FLAGS
    ${DRV_LDFLAGS}
    ${COMMON_LDFLAGS}

    INSTALL_DIR
)
