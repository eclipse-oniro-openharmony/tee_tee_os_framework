include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${DDK_INCLUDE_PATH_COMMON}
    ${PROJECT_SOURCE_DIR}/libs/libthp_common/include
)

list(APPEND TEE_C_SOURCES
    src/tui_misc.c
)

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TUI_LIBRARIES
        tui_internal
    )
else()
    list(APPEND TUI_LIBRARIES
        tui_internal_a32
    )
endif()

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND TUI_SERVICE_LDFLAGS
        -Wl,--entry=tee_task_entry
    )
endif()

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "baltimore")
    if ("${ARCH}" STREQUAL "aarch64")
        list(APPEND TUI_LIBRARIES
            thp_afe_baltimore
            tsa
        )
        list(APPEND TUI_LINKER_FLAGS
            -L${PROJECT_SOURCE_DIR}/libs/libthp_afe_baltimore/libs
        )
    else()
        list(APPEND TUI_LIBRARIES
            thp_afe_baltimore_a32
            tsa_a32
        )
        list(APPEND TUI_LINKER_FLAGS
            -L${PROJECT_SOURCE_DIR}/libs/libthp_afe_baltimore_a32/libs
        )
    endif()
endif()

list(APPEND TUI_LDFLAGS
    -lgcc
)

list(FIND PRODUCT_APPS "tui.elf" index)
if (${index} GREATER -1)
    if ("${CONFIG_TUI_64BIT}" STREQUAL "true" AND "${ARCH}" STREQUAL "aarch64")
        set(IF_INSTALL DO_INSTALL)
    endif()
    if ("${CONFIG_TUI_64BIT}" STREQUAL "false" AND "${ARCH}" STREQUAL "arm")
        set(IF_INSTALL DO_INSTALL)
    endif()
    if ("${CONFIG_TUI_32BIT}" STREQUAL "true" AND "${ARCH}" STREQUAL "arm")
        set(IF_INSTALL DO_INSTALL)
    endif()
endif()

if ("${ARCH}" STREQUAL "arm" AND "${CONFIG_ENABLE_XOM32}" STREQUAL "y")
    set(TUI_XOM_BLFLAGS -mllvm -tee-xom32=false)
endif()

tee_add_executable(tui.elf
    SOURCES
    ${TEE_C_SOURCES}

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    ${TEE_C_FLAGS}
    ${TUI_XOM_BLFLAGS}

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    LD_FLAGS
    ${TA_LDFLAGS}
    ${TUI_SERVICE_LDFLAGS}
    ${TUI_LDFLAGS}

    LINKGROUP
    ${TUI_LIBRARIES}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
