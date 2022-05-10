list(APPEND HOST_C_FLAGS
    -Wall
    -Wextra
    -Werror
    -Wl,-z,relro
    -Wl,-z,noexecstack
    -Wl,-z,now
    -fstack-protector-all
)

if ("${CONFIG_HW_SECUREC_MIN_MEM}" STREQUAL "y")
    list(APPEND HOST_C_FLAGS
        -DSECUREC_WARP_OUTPUT=1
        -DSECUREC_WITH_PERFORMANCE_ADDONS=0
    )
endif()

list(APPEND HOST_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libvfs_host/include
    ${PROJECT_SOURCE_DIR}/libs/libramfs_host/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PREBUILD_HEADER}/host
    ${PREBUILD_HEADER}/ddk/hmapi
    ${PREBUILD_HEADER}/inner_sdk/hmapi
    ${PROJECT_SOURCE_DIR}/thirdparty/huawei/libhwsecurec/include/libhwsecurec
    ${PREBUILD_HEADER}/libc/hm
    ${PREBUILD_HEADER}/kernel/uapi
    ${PREBUILD_HEADER}/kernel/arch/arm/uapi
    ${PREBUILD_HEADER}
    ${PREBUILD_HEADER}/libc
    ${PREBUILD_HEADER}/libc/arch/aarch64
    ${PREBUILD_HEADER}/libc/arch/generic
)

list(APPEND HOST_C_DEFINITIONS
    DEBUG_USE_STDIO=1
    HM_HOST_BUILD=1
    __IN_KERNEL__
)

tee_add_executable(ramfsmkimg
    SOURCES
    src/main.c

    COMPILE_TOOL
    host

    COMPILER_FLAGS
    ${HOST_C_FLAGS}

    COMPILER_DEFINITIONS
    ${HOST_C_DEFINITIONS}

    PRIVATE_INCLUDES
    ${HOST_INCLUDE_PATH}

    LIBRARIES
    hwsecurec_host

    LD_FLAGS
    -L/usr/lib/x86_64-linux-gnu

    INSTALL_DIR
    ${OUTPUTDIR}

    DO_INSTALL
)
