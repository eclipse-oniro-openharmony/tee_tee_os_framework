include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

set(SCRAMBLE_ME ${CONFIG_SCRAMBLE_SYMS})

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${DDK_INCLUDE_PATH_COMMON}
)

list(APPEND TEE_C_SOURCES
    src/tui_misc.c
)
if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TUI_LIBRARIES
        tui_internal
    )
else ()
    list(APPEND TUI_LIBRARIES
        tui_internal_a32
    )
endif()

if ("${ARCH}" STREQUAL "arm")
    if ("${TARGET_BOARD_PLATFORM}" STREQUAL "kirin980")
        list(APPEND TUI_LIBRARIES
            thp_afe
            thp_afe_hal_hima_nova
            thp_afe_hal_hima_syns
            thp_afe_hal_goodix
            thp_afe_hal_solomon
            tsa
            thp_afe_hal_himax
            thp_afe_hal_yale_focal
            thp_afe_hal_yale_nova
            thp_afe_hal_yale_snps
            thp_afe_hal_b141_goodix
        )
        list(APPEND TUI_LINKER_FLAGS
            -L${PROJECT_SOURCE_DIR}/libs/libthp_afe/libs
        )
    endif()

    if ("${TARGET_BOARD_PLATFORM}" STREQUAL "kirin970")
        list(APPEND TUI_LIBRARIES
            thp_afe_970
            afehal_jdi_new
            thp_afe_hal_emily_snps
            thp_afe_hal_nova
            tsa
        )
        list(APPEND TUI_LINKER_FLAGS
            -L${PROJECT_SOURCE_DIR}/libs/libthp_afe_970/libs
        )
    endif()

    if ("${TARGET_BOARD_PLATFORM}" STREQUAL "kirin710")
        list(APPEND TUI_LIBRARIES
            thp_afe_710
            thp_afe_hal_hp_nova
            thp_afe_hal_hp_td4320
            thp_afe_hal_hp_td4330
            tsa
        )
        list(APPEND TUI_LINKER_FLAGS
            -L${PROJECT_SOURCE_DIR}/libs/libthp_afe_710/libs
        )
    endif()

    if ("${TARGET_BOARD_PLATFORM}" STREQUAL "hi3660")
        list(APPEND TUI_LIBRARIES
            thp_afe_3660_6250
        )
    endif()

    if ("${TARGET_BOARD_PLATFORM}" STREQUAL "hi6250")
        list(APPEND TUI_LIBRARIES
            thp_afe_3660_6250
        )
    endif()

    if ("${TARGET_BOARD_PLATFORM}" STREQUAL "orlando")
        list(APPEND TUI_LIBRARIES
            thp_afe_orlando
            thp_afe_hal_saipan_snps
            thp_afe_hal_saipan_nova
            thp_afe_hal_saipan_focal
            tsa
            thp_afe_hal_b141_goodix
            thp_afe_hal_yale_snps
            thp_afe_hal_yale_nova
        )
        list(APPEND TUI_LINKER_FLAGS
            -L${PROJECT_SOURCE_DIR}/libs/libthp_afe_orlando/libs
        )
    endif()

    if ("${TARGET_BOARD_PLATFORM}" STREQUAL "kirin990")
        list(APPEND TUI_LIBRARIES
            thp_afe_990
            thp_afe_hal_waltz_snps
            thp_afe_hal_waltz_nova
            thp_afe_hal_oxford_snps
            thp_afe_hal_oxford_nova
            thp_afe_hal_edin_snps
            thp_afe_hal_edin_goodix
            tsa
        )
        list(APPEND TUI_LINKER_FLAGS
            -L${PROJECT_SOURCE_DIR}/libs/libthp_afe_990/libs
        )
    endif()

    if ("${TARGET_BOARD_PLATFORM}" STREQUAL "denver")
        list(APPEND TUI_LIBRARIES
            thp_afe_denver
            thp_afe_hal_goodix
            thp_afe_hal_snps
            thp_afe_hal_cindy_nova
            thp_afe_hal_cindy_syna
            tsa
        )
        list(APPEND TUI_LINKER_FLAGS
            -L${PROJECT_SOURCE_DIR}/libs/libthp_afe_denver/libs
        )
    endif()

    if ("${TARGET_BOARD_PLATFORM}" STREQUAL "baltimore")
        list(APPEND TUI_LIBRARIES
            thp_afe_baltimore
            thp_afe_hal_goodix
            tsa
            thp_afe_hal_dp167_goodix
        )
        list(APPEND TUI_LINKER_FLAGS
            -L${PROJECT_SOURCE_DIR}/libs/libthp_afe_baltimore_a32/libs
        )
    endif()

    if ("${TARGET_BOARD_PLATFORM}" STREQUAL "mt6885")
        list(APPEND TUI_LINKER_FLAGS
            -L${PROJECT_SOURCE_DIR}/libs/libthp_afe_mtk6885/libs
        )
    endif()
endif()

list(APPEND TUI_LINKER_FLAGS
    -r
    -d
    -T${PROJECT_SOURCE_DIR}/cmake/ta_link.ld
    -L${PREBUILD_ARCH_PLAT_LIBS}
)

list(FIND PRODUCT_APPS "tui.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

if ("${ARCH}" STREQUAL "arm" AND "${CONFIG_ENABLE_XOM32}" STREQUAL "y")
    set(TUI_XOM_BLFLAGS -mllvm -tee-xom32=false)
endif()

list(REMOVE_ITEM TEE_C_FLAGS "-flto")
list(REMOVE_ITEM TEE_C_FLAGS "-fsplit-lto-unit")
list(REMOVE_ITEM TUI_XOM_BLFLAGS "-flto")
list(REMOVE_ITEM TUI_XOM_BLFLAGS "-fsplit-lto-unit")

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
    ${TUI_LINKER_FLAGS}

    LINKGROUP
    ${TUI_LIBRARIES}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
