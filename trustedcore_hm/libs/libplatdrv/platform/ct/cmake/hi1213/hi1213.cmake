list(APPEND TEE_C_FLAGS
    -Wall
    -Wextra
    )
list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ct/trng
)
list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ct/trng/trng_api.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ct/trng/trng_hal.c
)
