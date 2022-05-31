include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND LIBTUI_INTERNAL_SHARED_LDFLAGS
        --shared
        -X
        -EL
        -z text
        -z now
        -m aarch64elf
        -z relro
        -z noexecstack
        -z max-page-size=4096
        --gc-sections
        --version-script=${CMAKE_CURRENT_SOURCE_DIR}/export.txt
        -nostdlib
        ${CMAKE_CURRENT_SOURCE_DIR}/extern.txt
    )
else()
    list(APPEND LIBTUI_INTERNAL_SHARED_LDFLAGS
        --shared
        -X
        -EL
        -z text
        -z now
        -m armelf_linux_eabi
        -z relro
        -z noexecstack
        --gc-sections
        --version-script=${CMAKE_CURRENT_SOURCE_DIR}/export.txt
        -nostdlib
    )
endif()

if(NOT "${CMAKE_TOOLCHAIN_BASEVER}" STREQUAL "8.0.1")
    list(APPEND LIBTUI_INTERNAL_SHARED_LDFLAGS
        -z separate-loadable-segments
    )
endif()

if ("${ARCH}" STREQUAL "arm" AND "${CONFIG_ENABLE_XOM32}" STREQUAL "y")
    list(APPEND LIBTUI_INTERNAL_SHARED_LDFLAGS
        -T${XOM_LIB_LDS}
)
endif()

list(REMOVE_ITEM LIBTUI_INTERNAL_SHARED_LDFLAGS "-flto")
list(REMOVE_ITEM LIBTUI_INTERNAL_SHARED_LDFLAGS "-fsplit-lto-unit")

if ("${ARCH}" STREQUAL "aarch64")
    set(TUI_INTERNAL_INSTALL_NAME libtui_internal_shared.so)
else()
    set(TUI_INTERNAL_INSTALL_NAME libtui_internal_shared_a32.so)
endif()

if("${ARCH}" STREQUAL "arm")
set(LINK_COMPILET_RT -lclang_rt.builtins-arm)
else()
set(LINK_COMPILET_RT -lclang_rt.builtins-aarch64)
endif()

if ("${BUILD_TOOL}" STREQUAL "clang")
add_custom_target(tui_internal_shared
    COMMAND ${CMAKE_LINKER} ${LIBTUI_INTERNAL_SHARED_LDFLAGS} -o ${CMAKE_CURRENT_BINARY_DIR}/libtui_internal_shared.so ${CMAKE_CURRENT_SOURCE_DIR}/extern.txt ${RUNTIMELIB_LINK_PATH} -L${PREBUILD_LIBS}/${ARCH} --start-group -lpng -lzlib -lfreetype ${LINK_COMPILET_RT} --end-group
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/libtui_internal_shared.so ${BOOTFS_STAGE_DIR}/${TUI_INTERNAL_INSTALL_NAME}
    VERBATIM)
endif()
