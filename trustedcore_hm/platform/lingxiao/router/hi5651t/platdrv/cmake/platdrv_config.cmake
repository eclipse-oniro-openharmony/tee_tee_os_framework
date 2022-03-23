list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/lingxiao/sec/include
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/lingxiao/sec/src/hi_sec_drv.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/lingxiao/sec/src/hi_trng.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/lingxiao/sec/src/hi_kdf.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/lingxiao/sec/src/hi_sec_common.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/lingxiao/sec/src/sec_adapt.c
)
