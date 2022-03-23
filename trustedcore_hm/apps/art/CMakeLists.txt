include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -DSUPPORT_DYN_ART
    -DCC_DRIVER=1
    -Wall
)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon/src
    ${PROJECT_SOURCE_DIR}/libs/libart/include
    ${PROJECT_SOURCE_DIR}/libs/libmspcore/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/eSE/hisee
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
)

list(APPEND TEE_C_SOURCES
    src/art_msg.c
    src/art_comm.c
    src/msp_tee_se_ext_api_tlv.c
    src/msp_tee_tlv.c
    src/samgr_common.c
    src/samgr_msg.c
)

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND ART_LDFLAGS
        -Wl,--entry=tee_task_entry
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND ART_LIBRARIES
        teeagentcommon
    )
else()
    list(APPEND ART_LIBRARIES
        teeagentcommon
    )
endif()

list(FIND PRODUCT_APPS "art.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(art.elf
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
    ${ART_LDFLAGS}

    LINKGROUP
    ${ART_LIBRARIES}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
