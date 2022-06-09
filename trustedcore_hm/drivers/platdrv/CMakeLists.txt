set(ENTRY_POINT main)
include(apps_drv_flags)
include(apps_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_C_SOURCES
    src/main.c
    src/tc_drv.c
    src/stub.c
    src/drv_pal.c
    src/sre_dev_relcb.c
    src/sre_hwi_ipc.c
    src/platdrv.c
    src/param_check.c
    src/sys_modem.c
    src/sre_hwi.c
    src/drv_cache_flush.c
    src/platdrv_hash.c
    src/rand_update.c
    ${PROJECT_SOURCE_DIR}/drivers/common/drv_call_check.c
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/platdrv/drv_hash_init.c
    ${PROJECT_SOURCE_DIR}/drivers/common/drv_pm_check.c
    ${PROJECT_SOURCE_DIR}/sys_libs/libdrv_shared/src/io_operations.c
)

if ("${CONFIG_DRIVER_DYN_MOD}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        src/drv_mod.c
    )
endif()

list(APPEND TEE_C_SOURCES
    platform/common/crypto/crypto_syscall.c
    platform/common/crypto/crypto_syscall_ae.c
    platform/common/crypto/crypto_syscall_cipher.c
    platform/common/crypto/crypto_syscall_common.c
    platform/common/crypto/crypto_syscall_dh.c
    platform/common/crypto/crypto_syscall_ecc.c
    platform/common/crypto/crypto_syscall_ecdh.c
    platform/common/crypto/crypto_syscall_hash.c
    platform/common/crypto/crypto_syscall_hmac.c
    platform/common/crypto/crypto_syscall_pbkdf2.c
    platform/common/crypto/crypto_syscall_derive_key.c
    platform/common/crypto/crypto_syscall_rsa.c
)

list(APPEND TEE_C_SOURCES
    src/boot_sharedmem.c
    ${PROJECT_SOURCE_DIR}/drivers/base_mgr/tee_misc_driver/src/drv_sharedmem.c
)

if ("${CONFIG_M_DRIVER}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        src/vendor_syscall.c
    )
endif()

include(${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/modules/platdrv_common.cmake)
include(${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/platdrv/cmake/platdrv_config.cmake)
include(${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/platdrv/cmake/platdrv_binary.cmake)

if ("${CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        CRYPTO_MGR_SERVER_ENABLE
    )
endif()

if ("${CONFIG_EPS_FOR_MSP}" STREQUAL "true" OR "${CONFIG_EPS_FOR_990}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        EPS_ENABLE
    )
endif()

if ("${CONFIG_EPS_FOR_990}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        EPS_FOR_990
    )
endif()

if ("${CONFIG_TEE_MISC_DRIVER_64BIT}" STREQUAL "true" OR "${CONFIG_TEE_MISC_DRIVER_64BIT}" STREQUAL "false")
    list(APPEND TEE TEE_C_DEFINITIONS
        CONFIG_TEE_MISC_DRIVER
    )
endif()

list(APPEND TEE_C_FLAGS
    -Wno-implicit-fallthrough
)

if ("${CONFIG_DRIVER_DYN_MOD}" STREQUAL "true")
    list(APPEND PLATDRV_LDFLAGS
        -Wl,--dynamic-list=${CMAKE_CURRENT_SOURCE_DIR}/export.txt
    )
endif()

if ("${CONFIG_PLATDRV_64BIT}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        PLATDRV_64
    )
    list(APPEND PLATDRV_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${PREBUILD_DIR}/headers/ddk
    ${PREBUILD_DIR}/headers/ddk/hmapi
    ${PREBUILD_DIR}/headers/ddk/legacy
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${PROJECT_SOURCE_DIR}/drivers/common
    ${PROJECT_SOURCE_DIR}/platform/common/tee_config
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/platform/common/crypto
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/src
    ${PROJECT_SOURCE_DIR}/drivers/base_mgr/tee_misc_driver/src
    ${PROJECT_SOURCE_DIR}/sys_libs/libdrv_frame/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libdrv_shared/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include/kernel
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/include
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/platdrv/include
    ${PROJECT_SOURCE_DIR}/../../hm-teeos/libs/syslib/libsyscalls/include
    ${PROJECT_SOURCE_DIR}/vendor/${PLATFORM_NAME}/libvendor_shared/include
    ${PREBUILD_HEADER}/sys/stackprotect
)

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND PLATDRV_LIBRARIES
        agent
        hwi
        c_shared
        io
        agent_base
        crypto
        timer
        ac
        hongmeng
        syscalls
        ipc
        teemem
        teeconfig
        teeos
        crypto_hal
        fileio
    )
    if ("${TARGET_BOARD_PLATFORM}" STREQUAL "mt6885")
        list(APPEND PLATDRV_LIBRARIES
            openssl
            ccmgr
            hmdrv
        )
    endif()
    if ("${CONFIG_LIB_TIMEMGR}" STREQUAL "y")
        list(APPEND PLATDRV_LIBRARIES
            timemgr
    )
    endif()
else()
    list(APPEND PLATDRV_LIBRARIES
        agent_a32
        hwi_a32
        c_shared_a32
        io_a32
        agent_base_a32
        crypto_a32
        timer
        ac_a32
        hongmeng_a32
        syscalls_a32
        ipc_a32
        teemem_a32
        teeconfig
        teeos_a32
        crypto_hal
        fileio_a32
    )
    if ("${TARGET_BOARD_PLATFORM}" STREQUAL "mt6885")
        list(APPEND PLATDRV_LIBRARIES
            openssl
            ccmgr
            hmdrv_a32
        )
    endif()
    if ("${CONFIG_LIB_TIMEMGR}" STREQUAL "y")
        list(APPEND PLATDRV_LIBRARIES
            timemgr_a32
    )
    endif()
endif()

if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    list(APPEND PLATDRV_LIBRARIES
        dx_cc7
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND PLATDRV_LDFLAGS
        -Wl,-z,text
        -Wl,-z,noexecstack
        -Wl,--dynamic-linker=libc_shared.so
    )
else()
    list(APPEND PLATDRV_LDFLAGS
        -Wl,-z,text
        -Wl,-z,noexecstack
        -Wl,--dynamic-linker=libc_shared_a32.so
    )
endif()

list(APPEND PLATDRV_LIBRARIES
    hmdrv_stub
    drv_frame
    ac_policy
)

set(ALIAS_FILE
    alias.txt
)

execute_process(
    COMMAND cat ${CMAKE_CURRENT_SOURCE_DIR}/${ALIAS_FILE}
    COMMAND awk "{ print \"-D\"$$1 }"
    COMMAND tr "\n" " "
    OUTPUT_VARIABLE ALIAS_SYM
)

list(APPEND TEE_C_FLAGS
    ${ALIAS_SYM}
    ${TRUSTEDCORE_LOCAL_CFLAGS}
)

if(NOT "${CMAKE_TOOLCHAIN_BASEVER}" STREQUAL "8.0.1")
    list(APPEND PLATDRV_LDFLAGS
        -Wl,-z,separate-loadable-segments
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND PLATDRV_LDFLAGS
        -Wl,-T${CMAKE_CURRENT_SOURCE_DIR}/linker64.ld
    )
else()
    if ("${CONFIG_ENABLE_XOM32}" STREQUAL "y")
        list(APPEND PLATDRV_LDFLAGS
            -Wl,-T${CMAKE_CURRENT_SOURCE_DIR}/linker.xom.ld
        )
    else()
        list(APPEND PLATDRV_LDFLAGS
            -Wl,-T${CMAKE_CURRENT_SOURCE_DIR}/linker.ld
        )
    endif()
endif()


set(TEE_CPP_FLAGS ${TEE_C_FLAGS})
set(TEE_CPP_INCLUDE_PATH ${TEE_INCLUDE_PATH})

list(REMOVE_ITEM TEE_CPP_FLAGS -I${PREBUILD_LIBC_INC})
list(REMOVE_ITEM TEE_CPP_FLAGS -I${PREBUILD_LIBC_INC}/arch/generic)
list(REMOVE_ITEM TEE_CPP_FLAGS -I${PREBUILD_LIBC_INC}/arch/${ARCH})
list(REMOVE_ITEM TEE_CPP_FLAGS -I${PREBUILD_HEADER}/gen/arch/${ARCH})
list(REMOVE_ITEM TEE_CPP_FLAGS -I${PREBUILD_LIBC_INC}/hm)
list(REMOVE_ITEM TEE_CPP_FLAGS -I${PREBUILD_LIBC_INC}/arch/${ARCH}/bits)

list(REMOVE_ITEM TEE_CPP_INCLUDE_PATH ${PREBUILD_LIBC_INC})
list(REMOVE_ITEM TEE_CPP_INCLUDE_PATH ${PREBUILD_LIBC_INC}/hm)
list(REMOVE_ITEM TEE_CPP_INCLUDE_PATH ${PREBUILD_LIBC_INC}/arch/generic)
list(REMOVE_ITEM TEE_CPP_INCLUDE_PATH ${PREBUILD_LIBC_INC}/arch/${ARCH})
list(REMOVE_ITEM TEE_CPP_INCLUDE_PATH ${PREBUILD_HEADER}/gen/arch/${ARCH})
list(REMOVE_ITEM TEE_CPP_INCLUDE_PATH ${PREBUILD_LIBC_INC}/arch/${ARCH}/bits)

list(REMOVE_ITEM TEE_C_FLAGS "-fno-common")
foreach (f ${TEE_C_SOURCES})
    if (NOT "${f}" MATCHES "modem|secureboot|eSE|libdx")
        set_property(SOURCE ${f} APPEND PROPERTY COMPILE_OPTIONS "-fno-common")
    endif()
endforeach()

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")
list(REMOVE_ITEM TEE_CPP_FLAGS "-Werror")
list(REMOVE_ITEM TEE_CXX_FLAGS "-Werror")

list(REMOVE_ITEM TEE_C_FLAGS "-fstack-protector-strong")
list(REMOVE_ITEM TEE_CPP_FLAGS "-fstack-protector-strong")
list(REMOVE_ITEM TEE_CXX_FLAGS "-fstack-protector-strong")

list(FIND PRODUCT_APPS "platdrv.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

if("${ARCH}" STREQUAL "arm")
set(LINK_COMPILET_RT -lclang_rt.builtins-arm)
else()
set(LINK_COMPILET_RT -lclang_rt.builtins-aarch64)
endif()

tee_add_executable(platdrv.elf
    C_SOURCES
    ${TEE_C_SOURCES}

    CPP_SOURCES
    ${TEE_CPP_SOURCES}

    COMPILE_TOOL
    clang

    C_COMPILER_FLAGS
    ${TEE_C_FLAGS}

    CPP_COMPILER_FLAGS
    ${TEE_CPP_FLAGS}
    ${TEE_CXX_FLAGS}

    C_PRIVATE_INCLUDES
    ${PLATDRV_INCLUDE_PATH}
    ${TEE_INCLUDE_PATH}

    CPP_PRIVATE_INCLUDES
    ${PLATDRV_INCLUDE_PATH}
    ${TEE_CPP_INCLUDE_PATH}

    C_COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    CPP_COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    LD_FLAGS
    ${DRV_LDFLAGS}
    ${PLATDRV_LDFLAGS}
    ${COMMON_LDFLAGS}

    LINKGROUP
    ${CPP_LIBRARIES}
    ${PLATDRV_LIBRARIES}
    ${LINK_COMPILET_RT}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
