if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -Wall
        -Wextra
        -DCC_DRIVER=1
    )
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/ccdriver_lib/include
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/codesafe/src/crypto_api
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc712
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc712/cc_driver_adapt.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/ccdriver_lib/cc_adapt.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc_driver_hal.c
    )
endif()

list(APPEND TEE_C_FLAGS
	-DDEF_WBITS=0x2f
    -DMY_ZCALLOC
)

list(APPEND TEE_C_DEFINITIONS
    CONFIG_MLOADER_NO_SHARE_MEM
    CONFIG_MODEM_SECBOOT_ES
    MY_ZCALLOC
)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/platform/hi9510_udp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/memory
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/memory/memory_driver.c
)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/memory_layout
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/memory_layout/memory_layout.c
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/sysboot/sysboot_para.c
)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/secureboot/zlib
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/secureboot/zlib/open_source
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/secureboot
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/efuse
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/secureboot/zlib/zmalloc.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/secureboot/zlib/open_source/adler32.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/secureboot/zlib/open_source/crc32.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/secureboot/zlib/open_source/inffast.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/secureboot/zlib/open_source/inflate.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/secureboot/zlib/open_source/inftrees.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/secureboot/zlib/open_source/uncompr.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/secureboot/zlib/open_source/zutil.c
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/sec_call/bsp_modem_call.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/efuse/hisi_efuse.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/sec_dump/sec_modem_dump.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/modem/adp/bsp_param_cfg.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/eicc200/eicc_core.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/eicc200/eicc_driver.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/eicc200/eicc_device.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/eicc200/eicc_proxy.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/eicc200/eicc_pmsr.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/eicc200/eicc_plat_teeos.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/eicc200/eicc_dtsv200.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/msg/msg_core.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/msg/msg_cmsg.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/msg/msg_mem.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/msg/msg_plat_teeos.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/msg/msg_mntn.c
	${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/secureboot/secureboot.c
	${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/secureboot/secureboot_ccore_imgs.c
	${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/secureboot/secureboot_msg.c
	${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/secureboot/secureboot_set_para.c
)

list(APPEND TEE_C_DEFINITIONS
    CONFIG_MODEM_CHECK_IMAGE_SIZE
    CONFIG_CHECK_PUBKEY
)

