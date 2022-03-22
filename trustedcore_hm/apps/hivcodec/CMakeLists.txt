include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -Wall -Wextra -Wdate-time
    -fno-common
    -DTEE_SUPPORT_RPMB_DEVICE
    -DTEE_SUPPORT_HIVCODEC
)

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "hi3660")
    list(APPEND TEE_C_FLAGS
        -DTEE_SUPPORT_TZMP2
    )
endif()

list(APPEND HIVCODEC_LDFLAGS
    -Wl,-Bsymbolic
    -Wl,--no-undefined
)

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/src/task_antiroot
    ${CMAKE_CURRENT_SOURCE_DIR}/src/task_antiroot/eima
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
)

list(APPEND TEE_C_SOURCES
    src/vcodec_drv.c
)
if (NOT "${TARGET_BOARD_PLATFORM}" STREQUAL "baltimore")
    list(APPEND TEE_C_SOURCES
        src/task_hi_vcodec/hi_vcodec_task_hivna.c
    )
endif()

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/sys_libs/libta_magic_a32/src/ta_magic.c
    )
endif()

list(FIND PRODUCT_APPS "hivcodec.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(hivcodec.elf
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
