if("${ARCH}" STREQUAL "aarch64")
    set(GCC_TOOLCHAIN_PATH ${GCC64_TOOLCHAIN_PATH})
else()
    set(GCC_TOOLCHAIN_PATH ${GCC32_TOOLCHAIN_PATH})
endif()

set(XOM_LIB_LDS ${PROJECT_SOURCE_DIR}/../hm-apps/trustedcore_hm/cmake/linker.lib.xom.ld)
set(XOM_LDS ${PROJECT_SOURCE_DIR}/../hm-apps/trustedcore_hm/cmake/linker.xom.ld)

foreach(common_i ${DEFS})
    if(COMMON_DEFS)
        set(COMMON_DEFS "-D${common_i}")
    else()
        set(COMMON_DEFS "${COMMON_DEFS} -D${common_i}")
    endif()
endforeach()

set(COMMON_CFLAGS
    ${COMMON_CFLAGS}
    ${NK_CCFLAGS}
    ${COMMON_DEFS}
)

set(COMMON_LDFLAGS
    ${COMMON_LDFLAGS}
    ${NK_LDFLAGS}
)
set(COMMON_CFLAGS
    ${COMMON_CFLAGS}
    --gcc-toolchain=${GCC_TOOLCHAIN_PATH}
)

set(COMMON_ASFLAGS
    ${COMMON_ASFLAGS}
    --gcc-toolchain=${GCC_TOOLCHAIN_PATH}
)

set(COMMON_INCLUDES
    ${COMMON_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/syslib/libhmlog/include
    ${CMAKE_CURRENT_SOURCE_DIR}/ext_apps/hm-apps/trustedcore_hm/thirdparty/huawei/libhwsecurec/include/libhwsecurec
    ${CMAKE_CURRENT_SOURCE_DIR}/ext_apps/hm-apps/trustedcore_hm/thirdparty/huawei/libhwsecurec/include
)

if ("${CONFIG_KASAN}" STREQUAL "y")
    if (NOT "${NO_KASAN}" STREQUAL "y")
        set(COMMON_NK_CFLAGS
            ${COMMON_NK_CFLAGS}
            -fsanitize=kernel-address
            -fasan-shadow-offset=${CONFIG_APP_MMGR_LAYOUT_PROCESS_SIZE_64}
            --param=asan-stack=1
            --param=asan-globals=1
        )
        set(COMMON_A32_CFLAGS
            ${COMMON_A32_CFLAGS}
            -fsanitize=kernel-address
            -fasan-shadow-offset=${CONFIG_APP_MMGR_LAYOUT_PROCESS_SIZE_32}
            --param=asan-stack=1
            --param=asan-globals=1
        )
    endif()
endif()

if (NOT "${CONFIG_USER_CFLAGS}" STREQUAL "y")
    set(COMMON_CFLAGS
        ${COMMON_CFLAGS}
        -Wall
        -nostdinc
        -std=gnu11
    )
    if ("${CONFIG_USER_OPTIMIZATION_Os}" STREQUAL "y")
        set(COMMON_CFLAGS
            ${COMMON_CFLAGS}
            -Oz
        )
    elseif ("${CONFIG_USER_OPTIMIZATION_O0}" STREQUAL "y")
        set(COMMON_CFLAGS
            ${COMMON_CFLAGS}
            -O0
        )
    elseif ("${CONFIG_USER_OPTIMIZATION_O1}" STREQUAL "y")
        set(COMMON_CFLAGS
            ${COMMON_CFLAGS}
            -O1
        )
    elseif ("${CONFIG_USER_OPTIMIZATION_O3}" STREQUAL "y")
        set(COMMON_CFLAGS
            ${COMMON_CFLAGS}
            -O3
        )
    elseif ("${CONFIG_USER_OPTIMIZATION_O2}" STREQUAL "y")
        set(COMMON_CFLAGS
            ${COMMON_CFLAGS}
            -O2
        )
    endif()
    if ("${CONFIG_LINK_TIME_OPTIMIZATIONS}" STREQUAL "y")
        set(COMMON_CFLAGS
            ${COMMON_CFLAGS}
            -flto
        )
    endif()

    set(COMMON_CFLAGS
        ${COMMON_CFLAGS}
        ${COMMON_NK_CFLAGS}
    )
else()
    set(COMMON_CFLAGS
        ${COMMON_CFLAGS}
        ${CONFIG_USER_CFLAGS}
    )
endif()

if (NOT DEFINED "${TARGET_IS_HOST}")
    if ("${CONFIG_LLVM_LTO}" STREQUAL "y")
        if (NOT DEFINED "${CONFIG_GCOV}")
            set(COMMON_CFLAGS
                ${COMMON_CFLAGS}
                -flto
                -fsplit-lto-unit
            )
        endif()
    endif()
endif()

set(COMMON_CFLAGS
    ${COMMON_CFLAGS}
    -fno-omit-frame-pointer
    -fno-builtin-aligned_alloc
    -fno-builtin-alloca
    -fno-builtin-calloc
    -fno-builtin-fwrite
    -fno-builtin-fread
    -fno-builtin-fseek
    -fno-builtin-fclose
    -fno-builtin-malloc
    -fno-builtin-memcpy
    -fno-builtin-memcmp
    -fno-builtin-memset
    -fno-builtin-memmove
    -fno-builtin-realloc
    -fno-builtin-strncmp
    -fno-builtin-strlen
    -fno-builtin-strncpy
    -fno-builtin-strncat
    -fno-builtin-posix_memalign
    -fno-builtin-printf
    -fno-builtin-snprintf
    -fno-builtin-vsnprintf
    -fno-builtin-fwrite_unlocked
    -fno-builtin-memchr
    -fno-builtin-strcspn
    -fno-builtin-strspn
    -fno-builtin-bcmp
    -fno-builtin-bcopy
    -fno-builtin-bzero
    -fno-builtin-strncasecmp
    -fno-builtin-stpncpy
    -fno-builtin-strndup
)

set(COMMON_A32_CFLAGS
    ${COMMON_A32_CFLAGS}
    -march=${ARMV}
    -nostdinc
    -nodefaultlibs
    -fno-short-enums
    -fno-builtin-aligned_alloc
    -fno-builtin-alloca
    -fno-builtin-calloc
    -fno-builtin-fwrite
    -fno-builtin-fread
    -fno-builtin-fseek
    -fno-builtin-fclose
    -fno-builtin-malloc
    -fno-builtin-memcpy
    -fno-builtin-memcmp
    -fno-builtin-memset
    -fno-builtin-memmove
    -fno-builtin-realloc
    -fno-builtin-strncmp
    -fno-builtin-strlen
    -fno-builtin-strncpy
    -fno-builtin-strncat
    -fno-builtin-posix_memalign
    -fno-builtin-printf
    -fno-builtin-snprintf
    -fno-builtin-vsnprintf
    -fno-builtin-fwrite_unlocked
    -fno-builtin-memchr
    -fno-builtin-strcspn
    -fno-builtin-strspn
    -fno-builtin-bcmp
    -fno-builtin-bcopy
    -fno-builtin-bzero
    -fno-builtin-strncasecmp
    -fno-builtin-stpncpy
    -fno-builtin-strndup
    -fno-omit-frame-pointer
    -fPIC
)

if ("${CONFIG_USER_LINKER_GC_SECTIONS}" STREQUAL "y")
    set(COMMON_A32_CFLAGS
        ${COMMON_A32_CFLAGS}
        -ffunction-sections
        -fdata-sections
    )
    set(COMMON_A32_LDFLAGS
        ${COMMON_A32_LDFLAGS}
        --gc-sections
    )
endif()

if ("${CONFIG_UNALIGNED_ACCESS}" STREQUAL "y")
    set(COMMON_A32_CFLAGS
        ${COMMON_A32_CFLAGS}
        -munaligned-access
        -fmax-type-align=1
    )
endif()

if ("${CONFIG_CC_STACKPROTECTOR_STRONG}" STREQUAL "y")
    set(COMMON_A32_CFLAGS
        ${COMMON_A32_CFLAGS}
        -fstack-protector-strong
    )
endif()

if ("${CONFIG_WHOLE_PROGRAM_OPTIMIZATIONS_USER}" STREQUAL "y")
    set(COMMON_LDFLAGS
        ${COMMON_LDFLAGS}
        -Wl,-fwhole-program
    )
endif()

if ("${USE_LIBC}" STREQUAL "y")
    set(COMMON_CFLAGS
        ${COMMON_CFLAGS}
        -march=armv8-a
    )
endif()

if ("${CONFIG_HW_SECUREC_MIN_MEM}" STREQUAL "y")
    set(COMMON_CFLAGS
        ${COMMON_CFLAGS}
        -DSECUREC_WARP_OUTPUT=1 -DSECUREC_WITH_PERFORMANCE_ADDONS=0
    )
endif()

if ("${CONFIG_UBSAN}" STREQUAL "y")
    set(COMMON_A32_CFLAGS
        ${COMMON_A32_CFLAGS}
        -fsanitize=bounds-strict
        -fsanitize-address-use-after-scope
        -fsanitize-undefined-trap-on-error
    )
endif()

set(COMMON_A32_CFLAGS
    ${COMMON_A32_CFLAGS}
    -Oz
)

if (NOT "${TARGET_NO_LIBLOG}" STREQUAL "y")
    set(COMMON_LIBS
        ${COMMON_LIBS}
        hmlog
    )
endif()

if ("${CONFIG_KASAN}" STREQUAL "y")
    if (NOT "${NO_KASAN}" STREQUAL "y")
        set(COMMON_LIBS
            ${COMMON_LIBS}
            asan
        )
    endif()
endif()

if ("${TARGET_IS_ARM32}" STREQUAL "y")
    if ("${CONFIG_THUMB_SUPPORT}" STREQUAL "y")
        set(COMMON_CFLAGS
            ${COMMON_CFLAGS}
            -mthumb
        )
    endif()
endif()

if ("${CONFIG_USE_RUST}" STREQUAL "y")
    set(COMMON_LDFLAGS
        ${COMMON_LDFLAGS}
        -Wl,-lcompiler-rt
    )
endif()

set(GENERAL_OPTIONS
    -Wdate-time
    -Wfloat-equal
    -Wshadow
    -Wformat=2
    -fsigned-char
    -fno-strict-aliasing
    -pipe
    -fno-common
    -Wextra
    -Wall
    -Werror
)

set(PAGE_SIZE 0x1000)
set(COMMON_LDFLAGS
    ${COMMON_LDFLAGS}
    -L${HMSDKLIB}
    -nostdlib
    -Wl,-z,max-page-size=${PAGE_SIZE}
)

if ("${CONFIG_USER_FULL_RELRO}" STREQUAL "y")
    set(COMMON_LDFLAGS
        ${COMMON_LDFLAGS}
        -Wl,-z,relro
        -Wl,-z,now
    )
endif()


if ("${ARCH}" STREQUAL "arm")
    set(COMMON_CFLAGS
        ${COMMON_A32_CFLAGS}
    )
endif()

set(COMMON_CFLAGS
    ${COMMON_CFLAGS}
    -DARM_PAE=1
)

if ("${CONFIG_GCOV}" STREQUAL "y")
    set(COMMON_LDFLAGS
        ${COMMON_LDFLAGS}
        -Wl,-lgcov
    )
endif()

set(COMMON_ASFLAGS
    ${COMMON_ASFLAGS}
    -march=armv8-a
    -mcpu=cortex-a53
)

if ("${CONFIG_DEBUG_SYMBOLS}" STREQUAL "y")
    set(COMMON_CFLAGS
        ${COMMON_CFLAGS}
        -g
    )
    set(COMMON_ASFLAGS
        ${COMMON_ASFLAGS}
        -g
    )
endif()

if (NOT "${CONFIG_SCRAMBLE_SYMS}" STREQUAL "y" AND
    NOT "${CONFIG_USER_DEBUG_BUILD}" STREQUAL "y")
    set(COMMON_LDFLAGS
        ${COMMON_LDFLAGS}
        -s
    )
endif()

set(COMMON_FLAG_CFLAGS
    ${COMMON_FLAG_CFLAGS}
    -fno-builtin
    -Wall
)
if ("${CONFIG_LIBFUZZER_SERVICE_64BIT}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TEE_SUPPORT_LIBFUZZER
    )
endif()

set(COMMON_FLAG_INCLUDES
    ${COMMON_FLAG_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/kernel/include/uapi
    ${CMAKE_CURRENT_SOURCE_DIR}/kernel/include/plat/uapi
    ${CMAKE_CURRENT_SOURCE_DIR}/kernel/include/arch/arm/uapi
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/syslib/libutils/include
)

set(COMMON_NWEFLAG_INCLUDES
    ${COMMON_NWEFLAG_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/kernel/include/uapi
    ${CMAKE_CURRENT_SOURCE_DIR}/kernel/include/plat/uapi
    ${CMAKE_CURRENT_SOURCE_DIR}/kernel/include/arch/arm/uapi
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/syslib/libutils/include
)

set(BOOTSTRAP_INCLUDES
    ${BOOTSTRAP_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/syslib/libc/include
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/syslib/libc/include/hm
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/syslib/libc/include/arch/${ARCH}
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/syslib/libc/musl/arch/generic
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/syslib/libc/musl/arch/${ARCH}
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/syslib/libc/musl/include
)

set(COMMON_LIBC_INCLUDES
    ${COMMON_LIBC_INCLUDES}
    ${HMLIBCINCLUDE}
    ${HMLIBCINCLUDE}/arch/generic
    ${HMLIBCARCH}
)

set(KERNEL_SPECIAL_CFLAGS)
list(FIND CFLAGS "-march=armv8-a+nofp" index)
if (index GREATER -1)
    list(REMOVE_ITEM CFLAGS "-march=armv8-a+nofp")
    list(APPEND CFLAGS "-march=armv8-a")
    set(KERNEL_SPECIAL_CFLAGS "-march=armv8-a+nofp")
endif()
set(COMMON_CFLAGS
    ${COMMON_CFLAGS}
    ${CFLAGS}
)

set(LIBHWSECUREC_CFLAGS
    ${COMMON_CFLAGS}
)

set(COMMON_CFLAGS
    ${GENERAL_OPTIONS}
    ${COMMON_CFLAGS}
)
