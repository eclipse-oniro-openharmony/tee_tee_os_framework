include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/src/task_ukey
    ${CMAKE_CURRENT_SOURCE_DIR}/src/task_ukey/common/libs/inc
    ${CMAKE_CURRENT_SOURCE_DIR}/src/task_ukey/common/rpmb_sfs_util/inc
)

list(APPEND TEE_C_SOURCES
    src/task_ukey/ukey_ta_data.c
    src/task_sem/task_sem.c
    src/task_ukey/common/libs/src/TA_Parcel.c
    src/task_ukey/common/libs/src/TA_String.c
    src/task_ukey/common/libs/src/TA_BasicLibs.c
    src/task_ukey/common/libs/src/TA_TLV_Parser.c
    src/task_ukey/common/rpmb_sfs_util/src/TA_FileOperator.c
    src/task_ukey/common/rpmb_sfs_util/src/TA_SFSFileOperator.c
    src/task_ukey/common/rpmb_sfs_util/src/TA_RPMBFileOperator.c
)

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/sys_libs/libta_magic_a32/src/ta_magic.c
    )
endif()

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

list(FIND PRODUCT_APPS "sem.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(sem.elf
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
