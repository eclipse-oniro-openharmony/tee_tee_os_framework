# hm entrypoint
if (NOT DEFINED ENTRY_POINT)
    set(ENTRY_POINT "_hm_start")
endif()
set(TARGET_IS_SYS "y")

set(LLVM_INC "${PREBUILD_DIR}/headers/libc++")

# use musl lib c headers.
list(APPEND TEE_INCLUDE_PATH
    ${PREBUILD_LIBC_INC}
    ${PREBUILD_LIBC_INC}/hm
    ${PREBUILD_LIBC_INC}/arch/generic
)
# because LIB_HOST use lib 64 headers
if(DEFINED ARCH)
    list(APPEND TEE_INCLUDE_PATH
        ${PREBUILD_LIBC_INC}/arch/${ARCH}
        ${PREBUILD_HEADER}/gen/arch/${ARCH}
        ${PREBUILD_LIBC_INC}/arch/${ARCH}/bits
    )
else()
    list(APPEND TEE_INCLUDE_PATH
        ${PREBUILD_LIBC_INC}/arch/aarch64
        ${PREBUILD_HEADER}/gen/arch/aarch64
        ${PREBUILD_LIBC_INC}/arch/aarch64/bits
    )
endif()
list(APPEND TEE_INCLUDE_PATH
    ${INCLUDE_PATH}
    ${PROJECT_SOURCE_DIR}/thirdparty/huawei/libhwsecurec/include/libhwsecurec/
    ${PROJECT_SOURCE_DIR}/thirdparty/huawei/libhwsecurec/include/
)
# end if use musl libc headers

list(APPEND TEE_C_FLAGS
    -march=armv8-a
    -fPIC
    -fdata-sections
    -ffunction-sections
    -fstack-protector-strong
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
    ${TRUSTEDCORE_PLATFORM_FLAGS}
)

if ("${CONFIG_LLVM_LTO}" STREQUAL "y")
    list(APPEND TEE_C_FLAGS
	-flto
	-fsplit-lto-unit
    )
endif()

if(NOT "${CMAKE_TOOLCHAIN_BASEVER}" STREQUAL "8.0.1")
    list(APPEND DRV_LDFLAGS
        -Wl,-z,separate-loadable-segments
    )
endif()

if ("${SVC_PARTITIAL_LINK}" STREQUAL "y")
    if ("${ARCH}" STREQUAL "aarch64")
        list(APPEND DRV_LDFLAGS
            -Wl,-x
            -Wl,-z,text
            -Wl,-z,now
            -Wl,-z,relro
            -Wl,-shared
            -Wl,-z,noexecstack
            -Wl,-z,max-page-size=4096
            -Wl,-T${PROJECT_SOURCE_DIR}/cmake/ta_link_64.ld
        )
        list(APPEND TEE_C_FLAGS
            -fvisibility=hidden
        )
    else()
        if ("${CONFIG_DYNLINK}" STREQUAL "y")
            list(APPEND DRV_LDFLAGS
                -Wl,-x
                -Wl,-z,text
                -Wl,-z,now
                -Wl,-z,relro
                -Wl,-shared
                -Wl,-z,noexecstack
                -Wl,-T${PROJECT_SOURCE_DIR}/cmake/ta_link_new.ld
            )
            list(APPEND TEE_C_FLAGS
                -fvisibility=hidden
            )
        else()
            list(APPEND DRV_LDFLAGS
                -Wl,-r
                -Wl,-d
                -Wl,-T${PROJECT_SOURCE_DIR}/cmake/ta_link.ld
            )
        endif()
    endif()
    list(APPEND DRV_LDFLAGS
        -Wl,-L${PREBUILD_ARCH_PLAT_LIBS}
    )
else()
    list(APPEND DRV_LDFLAGS
        -Wl,--undefined=__vsyscall_ptr
        -Wl,--gc-sections
        -Wl,-pie
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,-L${PREBUILD_ARCH_PLAT_LIBS}
        -nostdlib
        -Wl,--undefined=${ENTRY_POINT}
        -Wl,--entry=${ENTRY_POINT}
        -Wl,-z,max-page-size=4096
    )
endif()

list(APPEND DRV_LDFLAGS -Wl,--build-id=none)
list(APPEND DRV_LDFLAGS -Wl,-hash-style=sysv)

list(APPEND DRV_LDFLAGS
    -s
)
