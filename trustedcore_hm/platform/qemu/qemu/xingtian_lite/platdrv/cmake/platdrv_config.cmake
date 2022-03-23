list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/plat_cap
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/qemu/trngdriver_lib
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
)
if ("${CONFIG_TRNG_ENABLE}" STREQUAL "true")
list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/qemu/trngdriver_lib/trng_api.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/qemu/qemu_hal.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/qemu/plat_info.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/plat_cap/plat_cap_hal.c
)
list(APPEND TEE_C_FLAGS
    -DTRNG_ENABLE
)
endif()
list(APPEND TEE_C_FLAGS
    -Wall
    -Wextra
)
