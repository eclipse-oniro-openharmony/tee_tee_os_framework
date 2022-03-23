include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -Wno-unused-parameter
    -fno-builtin
    -Wall
    -Wextra
)

set(LOCAL_HEADER ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers)
set(LOCAL_LIBC_INC ${LOCAL_HEADER}/libc_32)
set(LOCAL_HM_INC ${LOCAL_HEADER}/hm_32)
set(LOCAL_KERNEL_INC ${LOCAL_HEADER}/kernel)
set(LOCAL_TOOLCHAINS ${PROJECT_SOURCE_DIR}/prebuild/toolchains)

list(APPEND TEE_INCLUDE_PATH
    ${LOCAL_KERNEL_INC}
    ${LOCAL_KERNEL_INC}/uapi
    ${LOCAL_KERNEL_INC}/arch/arm/uapi
    ${LOCAL_KERNEL_INC}/kirin
    ${LOCAL_LIBC_INC}
    ${LOCAL_LIBC_INC}/arch/generic
    ${LOCAL_LIBC_INC}/arch/${ARCH}
    ${LOCAL_LIBC_INC}/hm
    ${LOCAL_HM_INC}/kernel
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include/TEE_ext
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include/kernel
    ${PROJECT_SOURCE_DIR}/sys_libs/libhmdrv_stub/include
)
if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/pal/include
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/crys
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/pal
    )
endif()
list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libccmgr/include
    ${LOCAL_TOOLCHAINS}/gcc-linaro-7.4.1-2019.02-x86_64_arm-linux-gnueabi/bin
    ${LOCAL_TOOLCHAINS}/gcc-linaro-7.4.1-2019.02-x86_64_arm-linux-gnueabi/arm-linux-gnueabi/libc/usr/include
    ${PROJECT_SOURCE_DIR}/libs/libsec_modem/old_header
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot
)

list(APPEND TEE_C_DEFINITIONS
    CONFIG_MODEM_PLATDRV_64BIT_BBIT
)

if ("${chip_type}" STREQUAL "es2")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/../../../../vendor/hisi/ap/platform/${TARGET_BOARD_PLATFORM}_es2
    )
elseif ("${chip_type}" STREQUAL "es")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/../../../../vendor/hisi/ap/platform/${TARGET_BOARD_PLATFORM}_es
    )
else()
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/../../../../vendor/hisi/ap/platform/${TARGET_BOARD_PLATFORM}
    )
endif()

#[[
tee_add_library(sec_modem STATIC
    SOURCES
    src/art_api.c

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    ${TEE_C_FLAGS}

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}
)
]]#
