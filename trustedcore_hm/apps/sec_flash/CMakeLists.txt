include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

if ("${CONFIG_HISI_SECFLASH}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        src/sec_flash_ext_msg.c
        src/secflash_mm.c
        src/sec_flash_msg.c
        src/secflash_scp03_calc.c
        src/secflash_scp03_comm.c
        src/secflash_service_init.c
        src/secureflash_derived_key.c
        src/secureflash_interface.c
    )
    list(APPEND TEE_C_DEFINITIONS
        CONFIG_HISI_SECFLASH
        CC_DRIVER=1
        SECFLASH_PARTITION_HIGH_HALF_ENABLE
    )
else()
    list(APPEND TEE_C_SOURCES
        src/sec_flash_msg.c
        src/msp/secflash_sa_comm.c
    )
    list(APPEND TEE_C_DEFINITIONS
        SUPPORT_DYN_SECFLASH
        HISI_MSP_SECFLASH
        CONFIG_HISI_MSPC
    )
endif()

if ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "boringssl")
    list(APPEND TEE_C_DEFINITIONS
        BORINGSSL_ENABLE
    )
    list(APPEND TEE_INCLUDE_PATH
        ${PREBUILD_DIR}/headers/boringssl
    )
else ()
    list(APPEND TEE_C_DEFINITIONS
        OPENSSL_ENABLE
    )
    list(APPEND TEE_INCLUDE_PATH
        ${PREBUILD_DIR}/headers/openssl
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND SEC_FLASH_LIBRARIES
        teeagentcommon
    )
else()
    list(APPEND SEC_FLASH_LIBRARIES
        teeagentcommon
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon/src
    ${PROJECT_SOURCE_DIR}/libs/libsec_flash_client_a32/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/libs/libmspcore/include
    ${PROJECT_SOURCE_DIR}/vendor/higeneric/libvendor_shared/src
)

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND TA_LDFLAGS
        -Wl,--entry=tee_task_entry
    )
endif()

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

list(FIND PRODUCT_APPS "sec_flash.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(sec_flash.elf
    SOURCES
    ${TEE_C_SOURCES}

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    ${TEE_C_FLAGS}

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    LD_FLAGS
    ${TA_LDFLAGS}

    LINKGROUP
    ${SEC_FLASH_LIBRARIES}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
