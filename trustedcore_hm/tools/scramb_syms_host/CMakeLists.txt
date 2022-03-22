if ("${CONFIG_HW_SECUREC_MIN_MEM}" STREQUAL "y")
    list(APPEND TEE_C_DEFINITIONS
        SECUREC_WARP_OUTPUT=1
        SECUREC_WITH_PERFORMANCE_ADDONS=0
    )
endif()
if ("${BUILD_TOOL}" STREQUAL "host")
tee_add_executable(scramb_syms_host
    SOURCES
    scramb_syms.c

    COMPILE_TOOL
    host

    PRIVATE_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/huawei/libhwsecurec/include/libhwsecurec
    /usr/local/ssl/include

    COMPILER_FLAGS
    -Wall
    -Wextra
    -Werror
    -fPIC
    -Wl,-z,relro
    -Wl,-z,noexecstack
    -Wl,-z,now
    -fstack-protector-all
    -fPIE

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    LIBRARIES
    crypto
    dl
    hwsecurec_host

    LIBRARY_PATHS
    /usr/local/ssl/lib
    /usr/lib/x86_64-linux-gnu

    INSTALL_DIR
    ${OUTPUTDIR}

    DO_INSTALL
)
add_dependencies(scramb_syms_host hwsecurec_host)
endif()
