include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND DEVCHIP_LIBRARIES
    devchip_api
)

list(APPEND TEE_C_FLAGS
    -DTEE_PARAM_TYPE_NSSMMU_HAND_INPUT=0x9
    -DTEE_PARAM_TYPE_SECSMMU_HAND_INPUT=0xa
    -DTEE_PARAM_TYPE_PHYS_HAND_INPUT=0xb
)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/devchip_apps/keyslot
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/include
)

list(APPEND TEE_C_SOURCES
    hisi_keyslot_task.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/common/log/hi_tee_log.c
)

list(FIND PRODUCT_APPS "task_hisi_keyslot.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(task_hisi_keyslot.elf
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

    LINKGROUP
    ${DEVCHIP_LIBRARIES}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
