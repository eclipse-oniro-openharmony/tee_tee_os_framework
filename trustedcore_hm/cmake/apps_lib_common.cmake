include(apps_common)
set(TARGET_IS_SYS y)
set(LLVM_INC ${PREBUILD_DIR}/headers/libc++)

list(APPEND TEE_C_FLAGS
    -I${PREBUILD_LIBC_INC}
    -I${PREBUILD_LIBC_INC}/arch/generic
    -I${PREBUILD_LIBC_INC}/arch/${ARCH}
    -I${PREBUILD_HEADER}/gen/arch/${ARCH}
    -I${PREBUILD_LIBC_INC}/hm
    -I${PROJECT_SOURCE_DIR}/thirdparty/huawei/libhwsecurec/include/libhwsecurec
    -I${PROJECT_SOURCE_DIR}/thirdparty/huawei/libhwsecurec/include
)

list(APPEND TEE_C_FLAGS
    -fPIC
    -fdata-sections
    -ffunction-sections
    -fstack-protector-strong
    -nodefaultlibs
    -nostdinc
    -DARM_PAE=1
    -DHAVE_AUTOCONF
    -include${PREBUILD_DIR}/headers/autoconf.h
    -DARM_PAE=1
    -DARCH_ARM
    -DAARCH64
    -D__KERNEL_64__
    -DARMV8_A
    -DARM_CORTEX_A53
    -DDEBUG
    -DHM_DEBUG_KERNEL
    -DNDEBUG
)

if(NOT "${CMAKE_TOOLCHAIN_BASEVER}" STREQUAL "8.0.1")
    list(APPEND LIB_VENDOR_FLAGS
        -Wl,-z,separate-loadable-segments
    )
endif()

if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS -DDX_ENABLE)
endif()

if ("${CONFIG_TRNG_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS -DTRNG_ENABLE)
endif()

if ("${CONFIG_EPS_FOR_MSP}" STREQUAL "true" OR "${CONFIG_EPS_FOR_990}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS -DEPS_ENABLE)
endif()

if ("${CONFIG_SSA_SHRINK_MEMORY}" STREQUAL "y")
    list(APPEND TEE_C_FLAGS -DSSA_SHRINK_MEMORY)
endif()

list(APPEND TEE_C_FLAGS ${TRUSTEDCORE_PLATFORM_FLAGS})

list(APPEND TEE_CXX_FLAGS -nostdinc++ -static-libstdc++)
list(APPEND TEE_CXX_FLAGS -I${LLVM_INC})
