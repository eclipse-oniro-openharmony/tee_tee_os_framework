include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TARUNNER_LIBRARIES
        ta_mt
        c_shared
    )
else()
    list(APPEND TARUNNER_LIBRARIES
        ta_mt_a32
        c_shared_a32
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/sys_libs/libspawn_common/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libdrv_shared/src
    ${PROJECT_SOURCE_DIR}/drivers/include
)

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TARUNNER_LDFLAGS
        -Wl,-z,text
        -Wl,-z,noexecstack
        -Wl,--dynamic-linker=libc_shared.so
        -Wl,--entry=main
    )
else()
    list(APPEND TARUNNER_LDFLAGS
        -Wl,-z,text
        -Wl,-z,noexecstack
        -Wl,--dynamic-linker=libc_shared_a32.so
        -Wl,--entry=main
    )
endif()

if(NOT "${CMAKE_TOOLCHAIN_BASEVER}" STREQUAL "8.0.1")
    list(APPEND TARUNNER_LDFLAGS
        -Wl,-z,separate-loadable-segments
    )
endif()

if ("${TRUSTEDCORE_CHIP_CHOOSE}" STREQUAL "WITH_CHIP_HI1951"
        OR "${TRUSTEDCORE_CHIP_CHOOSE}" STREQUAL "WITH_CHIP_HI1981"
        OR "${TRUSTEDCORE_CHIP_CHOOSE}" STREQUAL "WITH_CHIP_HI1911"
        )
    list(APPEND TARUNNER_LDFLAGS
        -Wl,--export-dynamic
    )
endif()

list(FIND PRODUCT_APPS "tarunner.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(tarunner.elf
    SOURCES
    src/main.c
    src/get_spawn_env.c

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    ${TEE_C_FLAGS}

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    LD_FLAGS
    ${DRV_LDFLAGS}
    ${TARUNNER_LDFLAGS}
    ${COMMON_LDFLAGS}

    LINKGROUP
    ${TARUNNER_LIBRARIES}
    ${COMMON_LIBGCC_COMPS}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
if ("${ARCH}" STREQUAL "arm")
    set_target_properties(tarunner.elf PROPERTIES OUTPUT_NAME "tarunner_a32.elf")
endif()
