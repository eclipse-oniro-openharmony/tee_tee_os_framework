if ("${CONFIG_HW_SECUREC_MIN_MEM}" STREQUAL "y")
    list(APPEND TEE_C_DEFINITIONS
        SECUREC_WARP_OUTPUT=1
        SECUREC_WITH_PERFORMANCE_ADDONS=0
    )
endif()
tee_add_executable(cpio-strip STATIC
    SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/huawei/libhwsecurec/src/memcpy_s.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/huawei/libhwsecurec/src/memset_s.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/huawei/libhwsecurec/src/snprintf_s.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/huawei/libhwsecurec/src/vsnprintf_s.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/huawei/libhwsecurec/src/secureprintoutput_a.c
    cpio_strip.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../sys_libs/libcpio/src/cpio.c

    COMPILE_TOOL
    host

    PRIVATE_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/huawei/libhwsecurec/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/huawei/libhwsecurec/include/libhwsecurec
    ${CMAKE_CURRENT_SOURCE_DIR}/../../sys_libs/libcpio
    ${CMAKE_CURRENT_SOURCE_DIR}/../../sys_libs/libcpio/include

    COMPILER_FLAGS
    -Wall
    -Werror
    -Wextra
    -Wfloat-equal
    -Wshadow
    -Wtrampolines
    -fno-common
    -fno-strict-aliasing
    -fsigned-char
    -pipe
    -fstack-protector-all
    -fPIE

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    LD_FLAGS
    -fPIC
    -Wl,-z,relro
    -Wl,-z,noexecstack
    -Wl,-z,now
    -pie
    -Wl,-Bsymbolic
    -rdynamic
    -Wl,--no-undefined
    -Wl,-z,notext

    INSTALL_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}

    DO_INSTALL
)
