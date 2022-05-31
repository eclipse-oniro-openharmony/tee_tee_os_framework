if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND HMFILEMGR_LIBRARIES
        hongmeng
        ramfs
        debug
        syscalls
        pathmgr
        ac
        security
        hmlog
        ac_policy
        ipc
        -lhmfilemgr
        hwsecurec
        ${COMMON_LIBGCC_COMPS}
    )
    list(APPEND HMFILEMGR_LIBRARIES
        c
        vfs
        mmgr
    )
else()
    list(APPEND HMFILEMGR_LIBRARIES
        hongmeng_a32
        ramfs_a32
        debug_a32
        syscalls_a32
        pathmgr_a32
        ac_a32
        security_a32
        hmlog_a32
        ac_policy
        ipc_a32
        -lhmfilemgr
        hwsecurec
        ${COMMON_LIBGCC_COMPS}
    )
    list(APPEND HMFILEMGR_LIBRARIES
        c_a32
        vfs_a32
        mmgr_a32
    )
endif()

list(APPEND HMFILEMGR_C_FLAGS
    -Wall
    -Wextra
    -Werror
    -std=gnu11
    -Oz
    -fno-builtin
    -fPIC
    -Wdate-time
    -Werror
    -Wfloat-equal
    -Wshadow
    -fno-common
    -fno-strict-aliasing
    -pipe
    -fstack-protector-strong
    -mtune=cortex-a53
    -march=armv8-a
    -ffunction-sections
    -fdata-sections
    -fno-omit-frame-pointer
    -include${PREBUILD_HEADER}/autoconf.h
    -DBOOTFS_IMG=${BOOTFS_OUT}/bootfs.img
)

if(NOT "${CMAKE_TOOLCHAIN_BASEVER}" STREQUAL "8.0.1")
    list(APPEND HMFILEMGR_LD_FLAGS
        -Wl,-z,separate-loadable-segments
    )
endif()

list(APPEND HMFILEMGR_LD_FLAGS
    -Wl,--undefined=__vsyscall_ptr
    -Wl,-T${PREBUILD_TOOLS}/common/boot-app-${ARCH}.lds
    -L${LIB_DIR}
    -Wl,--gc-sections
    -L${PREBUILD_ARCH_PLAT_LIBS}
    -Wl,--undefined=_hm_start
    -Wl,--entry=_hm_start
    -Wl,-z,max-page-size=0x1000
    -nostdlib
    -Wl,--build-id=none
    -Wl,-z,noexecstack
    -Wl,-z,relro
    -Wl,-z,now
)

if ("${CONFIG_SYSSERV_ASLR}" STREQUAL "y")
    list(APPEND HMFILEMGR_LD_FLAGS
        -Wl,-pie
    )
endif()

list(APPEND HMFILEMGR_LD_FLAGS
    -s
)

if ("${BUILD_TOOL}" STREQUAL "clang")
list(FIND PRODUCT_APPS "hmfilemgr.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(hmfilemgr
    SOURCES
    src/get_ramfs_data.c

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    ${HMFILEMGR_C_FLAGS}

    LD_FLAGS
    ${HMFILEMGR_LD_FLAGS}
    ${COMMON_LDFLAGS}

    LINKGROUP
    ${HMFILEMGR_LIBRARIES}

    INSTALL_DIR
    ${OUTPUTDIR}

    ${IF_INSTALL}
)
endif()
