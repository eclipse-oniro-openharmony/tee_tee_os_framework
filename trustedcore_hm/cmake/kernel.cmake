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
    -Werror
    -Wall
)

set(LINK_OPTIONS
    -Wl,--no-undefined
    -Wl,-Bsymbolic
    -rdynamic
)

if ("${USE_LIBC}" STREQUAL "y")
    set(CFLAGS -march=${ARMV})
endif()

set(KERNEL_COMPILER_DEFINITIONS
    HAVE_AUTOCONF
    __IN_KERNEL__
)

if("${ARCH}" STREQUAL "aarch64")
    set(KERNEL_CFLAGS
        ${KERNEL_CFLAGS}
        -march=${ARMV}
        -mgeneral-regs-only
    )
    set(KERNEL_ASFLAGS
        ${KERNEL_ASFLAGS}
        -march=${ARMV}
    )
    set(KERNEL_COMPILER_DEFINITIONS
        ${KERNEL_COMPILER_DEFINITIONS}
        __KERNEL_64__
        AARCH64
    )
else()
    set(KERNEL_CFLAGS
        ${KERNEL_CFLAGS}
        -mtune=${CPU}
        -march=${ARMV}
        -Wformat
    )
    set(KERNEL_ASFLAGS
        ${KERNEL_AFLAGS}
        -mcpu=${CPU}
        -march=${ARMV}
    )
    string(TOUPPER ${ARMV} DARMV)
    string(REPLACE "-" "_" DARMV DARMV)
    set(KERNEL_COMPILER_DEFINITIONS
        ${KERNEL_COMPILER_DEFINITIONS}
        ARCH_ARM
        ${DARMV}
    )
endif()

if ("${CONFIG_ARCH_AARCH32}" STREQUAL "y")
    set(KERNEL_CFLAGS
        ${KERNEL_CFLAGS}
        -march=${ARMV}
    )
    set(KERNEL_ASFLAGS
        ${KERNEL_AFLAGS}
        -march=${ARMV} -mfpu=neon
    )
endif()

if ("${PLAT}" STREQUAL "kirin")
    set(KERNEL_COMPILER_DEFINITIONS
        ${KERNEL_COMPILER_DEFINITIONS}
        KIRIN
    )
endif()
set(KERNEL_CFLAGS
    ${KERNEL_CFLAGS}
    --std=c11
    -nostdinc
    -nostdlib
    -ffreestanding
    -Wstrict-prototypes
    -Wmissing-prototypes
    -Wnested-externs
    -Wmissing-declarations
    -Wundef
    -fpie
    -march=${ARMV}
)
set(KERNEL_ASFLAGS
    ${KERNEL_ASFLAGS}
    -march=${ARMV}
)

if ("${CONFIG_DEBUG_BUILD}" STREQUAL "y")
    set(KERNEL_ASFLAGS
        ${KERNEL_ASFLAGS}
        -g
    )
    set(KERNEL_CFLAGS
        ${KERNEL_CFLAGS}
        -g
    )
endif()

if("${CONFIG_WHOLE_PROGRAM_OPTIMIZATIONS_KERNEL}" STREQUAL "y")
    set(KERNEL_CFLAGS
        ${KERNEL_CFLAGS}
        -fwhole-program
    )
endif()

set(KERNEL_LDFLAGS
    ${KERNEL_LDFLAGS}
    -nostdlib
    -pie
    -z noexecstack
    -z relro
    -z now
    --build-id=none
)

if("${CONFIG_OPTIMIZATION_O0}" STREQUAL "y")
    set(KERNEL_CFLAGS
        ${KERNEL_CFLAGS}
        -O0
    )
    set(KERNEL_LDFLAGS
        ${KERNEL_LDFLAGS}
        -O0
    )
else()
    if("${CONFIG_OPTIMIZATION_O1}" STREQUAL "y")
        set(KERNEL_CFLAGS
            ${KERNEL_CFLAGS}
            -O1
        )
        set(KERNEL_LDFLAGS
            ${KERNEL_LDFLAGS}
            -O1
        )
    else()
        if("${CONFIG_OPTIMIZATION_O2}" STREQUAL "y")
            set(KERNEL_CFLAGS
                ${KERNEL_CFLAGS}
                -O2
            )
            set(KERNEL_LDFLAGS
                ${KERNEL_LDFLAGS}
                -O2
            )
        else()
            if("${CONFIG_OPTIMIZATION_O3}" STREQUAL "y")
                set(KERNEL_CFLAGS
                    ${KERNEL_CFLAGS}
                    -O3
                )
                set(KERNEL_LDFLAGS
                    ${KERNEL_LDFLAGS}
                    -O3
                )
            else()
                set(KERNEL_CFLAGS
                    ${KERNEL_CFLAGS}
                    -Oz
                )
                set(KERNEL_LDFLAGS
                    ${KERNEL_LDFLAGS}
                    -Oz
                )
            endif()
        endif()
    endif()
endif()

if (NOT "${CONFIG_DEBUG_BUILD}" STREQUAL "y")
    set(KERNEL_LDFLAGS
        ${KERNEL_LDFLAGS}
        -s
    )
endif()
