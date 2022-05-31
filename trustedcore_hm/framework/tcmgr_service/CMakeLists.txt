include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
)

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND TCMGR_SERVICE_LDFLAGS
        -Wl,--entry=tee_task_entry
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TCMGR_SERVICE_LIBRARIES
        tcmgrsrv
    )
else()
    list(APPEND TCMGR_SERVICE_LIBRARIES
        tcmgrsrv_a32
    )
endif()

list(FIND PRODUCT_APPS "tcmgr_service.elf" index)

tee_add_executable(tcmgr_service.elf
    SOURCES
    src/tcmgr_service_config.c

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
    ${TCMGR_SERVICE_LDFLAGS}

    LIBRARIES
    ${TCMGR_SERVICE_LIBRARIES}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
