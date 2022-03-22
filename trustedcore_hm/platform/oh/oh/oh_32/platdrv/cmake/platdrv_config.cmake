list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ipc/sec/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/plat_cap
)
list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ipc/sec/cipher_syscall.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ipc/sec/src/cryp_trng.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ipc/sec/src/drv_trng.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ipc/sec/src/drv_klad.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ipc/sec/src/hal_otp.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ipc/sec/src/cipher_adapt.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/plat_cap/plat_cap_hal.c
)
