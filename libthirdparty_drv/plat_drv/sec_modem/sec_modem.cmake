set(SECURE_OS_DIR ${PROJECT_SOURCE_DIR})

set(LOCAL_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/prebuild/hm-teeos-release/headers)
set(LOCAL_LIBC_INC ${LOCAL_HEADER}/libc_32)
set(LOCAL_HM_INC ${LOCAL_HEADER}/hm_32)
set(LOCAL_KERNEL_INC ${LOCAL_HEADER}/kernel)
set(LOCAL_TOOLCHAINS ${CMAKE_CURRENT_SOURCE_DIR}/prebuild/toolchains)

list(APPEND PLATDRV_INCLUDE_PATH
    ${LOCAL_KERNEL_INC}
    ${LOCAL_KERNEL_INC}/uapi
    ${LOCAL_KERNEL_INC}/arch/arm/uapi
    ${LOCAL_KERNEL_INC}/kirin
    ${LOCAL_LIBC_INC}
    ${LOCAL_LIBC_INC}/arch/generic
    ${LOCAL_LIBC_INC}/arch/${ARCH}
    ${LOCAL_LIBC_INC}/hm
    ${LOCAL_HM_INC}
    ${LOCAL_HEADER}/hm
    ${LOCAL_HM_INC}/kernel
    ${CMAKE_CURRENT_SOURCE_DIR}/sys_libs/libteeconfig/include/TEE_ext
    ${CMAKE_CURRENT_SOURCE_DIR}/sys_libs/libteeconfig/include/kernel
    ${CMAKE_CURRENT_SOURCE_DIR}/sys_libs/libhmdrv_stub/include
    ${CMAKE_CURRENT_SOURCE_DIR}/drivers/platdrv/platform/common/crypto
)
if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/vendor/libdxcc/pal/include
    ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/crys
    ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/pal
)
endif()
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/secureboot
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/secureboot/bspatch
    ${CMAKE_CURRENT_SOURCE_DIR}/drivers/platdrv/include
    ${CMAKE_CURRENT_SOURCE_DIR}/drivers/include
    ${CMAKE_CURRENT_SOURCE_DIR}/sys_libs/libccmgr/include

    ${CMAKE_CURRENT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/secureboot
)

list(APPEND TEE_C_DEFINITIONS
    CONFIG_MODEM_PLATDRV_64BIT_BBIT
)

if ("${chip_type}" STREQUAL "cs2")
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../vendor/hisi/ap/platform/${TARGET_BOARD_PLATFORM}_cs2
)
else()
if ("${chip_type}" STREQUAL "es")
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../vendor/hisi/ap/platform/${TARGET_BOARD_PLATFORM}_es
)
else()
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../vendor/hisi/ap/platform/${TARGET_BOARD_PLATFORM}
)
endif()
endif()

include (${CMAKE_CURRENT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/sec_modem/teeos/modem_build.cmake)