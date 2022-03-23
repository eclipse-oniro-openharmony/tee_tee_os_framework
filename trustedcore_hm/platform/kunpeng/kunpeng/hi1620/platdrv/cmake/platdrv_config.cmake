list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/plat_cap
    ${PREBUILD_HEADER}/sys/mmgr
    ${PREBUILD_HEADER}/sys/mmgr_sysmgr
)

if ("${CONFIG_TRNG_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TRNG_ENABLE
    )
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kunpeng/trngdriver_lib
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kunpeng/acc_lib/include
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kunpeng/sec_hal.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kunpeng/acc_lib/src/sec_api.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kunpeng/acc_lib/src/hi_sec_dlv.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kunpeng/acc_lib/src/acc_common.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kunpeng/acc_lib/src/acc_common_sess.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kunpeng/acc_lib/src/acc_common_drv.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kunpeng/acc_lib/src/acc_common_qm.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kunpeng/acc_lib/src/hi_sec_atest_api.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kunpeng/acc_lib/src/acc_common_isr.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kunpeng/trngdriver_lib/trng_api.c
    )
endif()
list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kunpeng/secboot/secureboot.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kunpeng/secboot/getcert.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/plat_cap/plat_cap_hal.c
)

list(APPEND TEE_C_FLAGS
    -Wall
    -Wextra
)
