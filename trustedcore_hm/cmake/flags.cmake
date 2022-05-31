set(DEFS)
if ("${CONFIG_ARCH_ARM}" STREQUAL "y")
    set(DEFS
        ${DEFS}
        ARCH_ARM
    )
endif()

if ("${CONFIG_ARCH_AARCH32}" STREQUAL "y")
    set(DEFS
        ${DEFS}
        AARCH32
        __KERNEL_32__
    )
    set(__ARM_32__ y)
    set(KERNEL_32 y)
    set(TEE_ARCH arm)
    set(ENV{TEE_ARCH} arm)
    if ("${CONFIG_ARM_HYPERVISOR_SUPPORT}" STREQUAL "y")
        set(HM_ARCH arm_hyp)
        set(ARM_HYP 1)
        set(DEFS
            ${DEFS}
            ARM_HYP
        )
    else()
        set(HM_ARCH aarch32)
    endif()
endif()

if ("${CONFIG_ARCH_AARCH64}" STREQUAL "y")
    set(DEFS
        ${DEFS}
        AARCH64
        __KERNEL_64__
    )
    set(TEE_ARCH aarch64)
    set(ENV{TEE_ARCH} aarch64)
    set(__ARM_64__ y)
    set(KERNEL_64 y)
    set(HM_ARCH aarch64)
endif()

if ("${CONFIG_ARM_CORTEX_A15}" STREQUAL "y")
    set(DEFS
        ${DEFS}
        ARMV7_A
        ARM_CORTEX_A15
    )
    set(ARMV armv7ve)
    set(CPU cortex-a15)
endif()

if ("${CONFIG_ARM_CORTEX_A53}" STREQUAL "y")
    set(CFLAGS
        ${CFLAGS}
        -mtune=cortex-a53
    )
    if ("${CONFIG_ARCH_AARCH64}" STREQUAL "y")
        set(CFLAGS
            ${CFLAGS}
            -march=armv8-a+nofp
        )
        set(ASFLAGS
            ${ASFLAGS}
            -march=armv8-a
            -mcpu=cortex-a53
        )
    endif()
    set(DEFS
        ${DEFS}
        ARMV8_A
        ARM_CORTEX_A53
    )
    set(ARMV
        armv8-a
    )
    set(CPU
        cortex-a53
    )
endif()

set(DEFS
    ${DEFS}
    KIRIN
)
set(PLAT kirin)
set(ENV{PLAT} kirin)

if ("${CONFIG_GIC_V3}" STREQUAL "y")
    set(GIC V3)
else()
    set(GIC V2)
endif()

if ("${CONFIG_IMAGE_EFI}" STREQUAL "y")
    set(DEFS
        ${DEFS}
        EFI
    )
    set(__EFI__ y)
endif()

if ("${CONFIG_IMAGE_BINARY}" STREQUAL "y")
    set(DEFS
        ${DEFS}
        BINARY
    )
    set(__binary__ y)
endif()

if ("${CONFIG_CC_STACKPROTECTOR_STRONG}" STREQUAL "y")
    set(CFLAGS
        ${CFLAGS}
        -fstack-protector-strong
    )
    set(NK_CFLAGS
        ${NK_CFLAGS}
        -fstack-protector-strong
    )
endif()

if ("${CONFIG_SMP_ARM_MPCORE}" STREQUAL "y")
    set(DEFS
        ${DEFS}
        CONFIG_SMP_ARM_MPCORE
    )
endif()

if ("${CONFIG_DEBUG_BUILD}" STREQUAL "y")
    set(CFLAGS
        ${CFLAGS}
        -g
    )
    set(DEFS
        ${DEFS}
        DEBUG
        HM_DEBUG_KERNEL
    )
    set(DEBUG 1)
endif()

if ("${CONFIG_USER_DEBUG_INFO}" STREQUAL "y")
    set(NK_CCFLAGS
        ${NK_CCFLAGS}
        -g3,-g
        -ggdb3,-ggdb
        -save-temps
    )
endif()

if ("${CONFIG_USER_LINKER_GC_SECTIONS}" STREQUAL "y")
    set(NK_CCFLAGS
        ${NK_CCFLAGS}
        -ffunction-sections
        -fdata-sections
    )
    set(NK_LDFLAGS
        ${NK_LDFLAGS}
        -Wl,--gc-sections
    )
endif()

if ("${CONFIG_UBSAN}" STREQUAL "y")
    set(CFLAGS
        ${CFLAGS}
        -fsanitize=bounds-strict
        -fsanitize-address-use-after-scope
        -fsanitize-undefined-trap-on-error
    )
    set(NK_CFLAGS
        ${NK_CFLAGS}
        -fsanitize=bounds-strict
        -fsanitize-address-use-after-scope
        -fsanitize-undefined-trap-on-error
    )
endif()

if ("${CONFIG_USER_DYNAMIC_ELF}" STREQUAL "y")
    set(NK_CCFLAGS
        ${NK_CCFLAGS}
        -fPIC
    )
    set(NK_LDFLAGS
        ${NK_LDFLAGS}
        -Wl,-pie
    )
else()
    set(NK_LDFLAGS
        ${NK_LDFLAGS}
        -Wl,-static
    )
endif()

if ("${CONFIG_DANGEROUS_CODE_INJECTION}" STREQUAL "y")
    set(DEFS
        ${DEFS}
        DANGEROUS_CODE_INJECTION
        HM_DANGEROUS_CODE_INJECTION_KERNEL
    )
endif()

if ("${CONFIG_IOMMU}" STREQUAL "y")
    set(DEFS
        ${DEFS}
        IOMMU
    )
endif()

if ("${CONFIG_VTX}" STREQUAL "y")
    set(DEFS
        ${DEFS}
        VTX
    )
endif()

if ("${CONFIG_FASTPATH}" STREQUAL "y")
    set(DEFS
        ${DEFS}
        FASTPATH
    )
endif()

set(CFLAGS
    ${CFLAGS}
    -DHAVE_AUTOCONF
)
