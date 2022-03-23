include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

if ("${TEE_SUPPORT_FILE_ENCRY_V3}" STREQUAL "true")
    list(APPEND TEE_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/src/task_file_encry_v3
        ${PROJECT_SOURCE_DIR}/libs/libmspcore_a32/include
        ${PROJECT_SOURCE_DIR}/libs/libsec_flash_client_a32/src
        ${PROJECT_SOURCE_DIR}/libs/libmspcore/include
    )
else()
    list(APPEND TEE_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/src/task_file_encry
    )
endif()

if ("${TEE_SUPPORT_FILE_ENCRY_V3}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        src/task_file_encry_v3/sec_fbe3_derive_key.c
        src/task_file_encry_v3/sec_fbe3_drv.c
        src/task_file_encry_v3/sec_fbe3_interface.c
        src/task_file_encry_v3/sec_fbe3_rpmb.c
        src/task_file_encry_v3/sec_fbe3_ta.c
    )
    if ("${CONFIG_HISI_MSPC}" STREQUAL "true")
        list(APPEND TEE_C_SOURCES
            src/task_file_encry_v3/msp_fbe.c
        )
        list(APPEND TEE_C_FLAGS
            -DFILE_ENCRY_MSP_ENABLE
        )
    endif()
else()
    if ("${TEE_SUPPORT_FILE_ENCRY_V2}" STREQUAL "true")
        file(GLOB FILE_ENCRY_V2_SOURCES src/task_file_encry_v2/*.c)
        list(APPEND TEE_C_SOURCES
            ${FILE_ENCRY_V2_SOURCES}
        )
    else()
        list(APPEND TEE_C_SOURCES
            src/task_file_encry/sec_file_encry_tee.c
        )
    endif()
endif()

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/sys_libs/libta_magic_a32/src/ta_magic.c
    )
endif()

if ("${TEE_SUPPORT_FILE_ENCRY_V2}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        ARM_PAE=1
    )
endif()

list(FIND PRODUCT_APPS "file_encry.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(file_encry.elf
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
