if (NOT DEFINED ENTRY_POINT)
    set(ENTRY_POINT "_hm_start")
endif()
set(TARGET_IS_DRV y)

set(LLVM_INC ${PREBUILD_DIR}/headers/libc++)

list(APPEND TEE_C_FLAGS
    -I${PREBUILD_LIBC_INC}
    -I${PREBUILD_LIBC_INC}/arch/generic
    -I${PREBUILD_LIBC_INC}/arch/${ARCH}
    -I${PREBUILD_HEADER}/gen/arch/${ARCH}
    -I${PREBUILD_LIBC_INC}/hm
    -I${PREBUILD_LIBC_INC}/arch/${ARCH}/bits
)

list(APPEND TEE_C_FLAGS
    -fPIC
    -fdata-sections
    -ffunction-sections
    -fstack-protector-strong
    -nodefaultlibs
    -DARM_PAE=1
    -DARCH_ARM
    -DAARCH64
    -D__KERNEL_64__
    -DARMV8_A
    -DARM_CORTEX_A53
    -DDEBUG
    -DHM_DEBUG_KERNEL
    -DNDEBUG
    -include${PREBUILD_DIR}/headers/autoconf.h
)

if ("${CONFIG_LLVM_LTO}" STREQUAL "y")
    list(APPEND TEE_C_FLAGS
        -flto
        -fsplit-lto-unit
    )
endif()

include(cxx)

list(APPEND TEE_LINKER_FLAGS
    -Wl,--undefined=__vsyscall_ptr
    -Wl,--gc-sections
    -pie
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-L${LIB_DIR}
    -Wl,-L${PREBUILD_ARCH_PLAT_LIBS}
    -nostdlib
    -Wl,--undefined=${ENTRY_POINT}
    -Wl,--entry=${ENTRY_POINT}
    -Wl,-z,max-page-size=0x1000
)

if (NOT "${CONFIG_SCRAMBLE_SYMS}" STREQUAL "y" AND
    NOT "${CONFIG_USER_DEBUG_BUILD}" STREQUAL "y")
    list(APPEND DRV_LDFLAGS -s)
endif()
