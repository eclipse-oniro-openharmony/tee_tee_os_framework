include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/secureboot/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/vendor/common/include
)

list(APPEND TEE_C_SOURCES
    src/task_secboot/secboot_task.c
    src/task_secboot/secboot_verify.c
    src/task_secboot/secboot_cuid.c
    src/task_secboot/secboot_load_modem_teeos.c
    src/task_secboot/secboot_modem_call.c
)

if ("${with_rfdsp}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_RFIC_LOAD
    )
endif()

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/sys_libs/libta_magic_a32/src/ta_magic.c
    )
endif()

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "kirin980" OR "${TARGET_BOARD_PLATFORM}" STREQUAL "orlando")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_HISI_NVIM_SEC
        -DCONFIG_COLD_PATCH
    )
endif()

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "kirin990")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_HISI_NVIM_SEC
        -DCONFIG_COLD_PATCH
        -DCONFIG_MODEM_ASLR
	-DCONFIG_LOAD_MODEM_TEEOS
    )
endif()

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "kirin980")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_MODEM_ASLR
    )
endif()

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "kirin710")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_COLD_PATCH
    )
endif()

list(FIND PRODUCT_APPS "secboot.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(secboot.elf
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
