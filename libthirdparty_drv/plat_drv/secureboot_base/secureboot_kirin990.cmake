list(APPEND TEE_C_DEFINITIONS
    WITH_IMAGE_LOAD_SUPPORT
    CONFIG_DYNAMIC_MMAP_ADDR
    CONFIG_CHECK_PTN_NAME
    CONFIG_CHECK_PLATFORM_INFO
    CONFIG_CC_CUID
)

list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secureboot
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secureboot/include
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/include/ivp
)

list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/secureboot/secureboot.c
    platform/libthirdparty_drv/plat_drv/secureboot/secboot.c
    platform/libthirdparty_drv/plat_drv/secureboot/sec_derive_cuid.c
    platform/libthirdparty_drv/plat_drv/secureboot/process_hifi_info.c
    platform/libthirdparty_drv/plat_drv/secureboot/process_isp_info.c
    platform/libthirdparty_drv/plat_drv/secureboot/zlib/adler32.c
    platform/libthirdparty_drv/plat_drv/secureboot/zlib/inffast.c
    platform/libthirdparty_drv/plat_drv/secureboot/zlib/inflate.c
    platform/libthirdparty_drv/plat_drv/secureboot/zlib/inftrees.c
    platform/libthirdparty_drv/plat_drv/secureboot/zlib/uncompr.c
    platform/libthirdparty_drv/plat_drv/secureboot/zlib/zutil.c
)

if ("${WITH_MODEM}" STREQUAL "true")
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/secureboot/process_modem_info.c
)

if ("${chip_type}" STREQUAL "cs2")
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/secureboot/hisi_secboot_modem_aslr.c
    platform/libthirdparty_drv/plat_drv/secureboot/hisi_secboot_modem_patch.c
    platform/libthirdparty_drv/plat_drv/modem/adp/sec_modem_dump_plat.c
)
list(APPEND TEE_C_DEFINITIONS
    CONFIG_MLOADER
    CONFIG_MODEM_COLD_PATCH
    CONFIG_COLD_PATCH_BORROW_DDR
    CONFIG_MODEM_ASLR_5G_CORE
)
else()
list(APPEND TEE_C_DEFINITIONS
    CONFIG_COLD_PATCHDR
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/modem/adp/sec_modem_dump.c
)
endif()

else()
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/modem/adp/bsp_modem_stub.c
    platform/libthirdparty_drv/plat_drv/secureboot/process_modem_info_stub.c
)
endif()

if (NOT "${product_type}" STREQUAL "armpc")
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/secureboot/process_ivp_info.c
)
list(APPEND TEE_C_DEFINITIONS
    CONFIG_HISI_NVIM_SEC
    CONFIG_HISI_IVP_SEC_IMAGE
)
endif()

list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secureboot/bspatch
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secureboot/bspatch/include
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secureboot/bspatch/include/bsdiff
)
list(APPEND TEE_CPP_SOURCES
    platform/libthirdparty_drv/plat_drv/secureboot/bspatch/bspatch.cpp
    platform/libthirdparty_drv/plat_drv/secureboot/bspatch/buffer_file.cpp
    platform/libthirdparty_drv/plat_drv/secureboot/bspatch/extents.cpp
    platform/libthirdparty_drv/plat_drv/secureboot/bspatch/extents_file.cpp
    platform/libthirdparty_drv/plat_drv/secureboot/bspatch/file.cpp
    platform/libthirdparty_drv/plat_drv/secureboot/bspatch/memory_file.cpp
    platform/libthirdparty_drv/plat_drv/secureboot/bspatch/sink_file.cpp
    platform/libthirdparty_drv/plat_drv/secureboot/bspatch/secure_bspatch.cpp
)

list(APPEND TEE_C_DEFINITIONS
    CONFIG_HISI_EIIUS
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/secureboot/eiius_interface.c
)

if (NOT "${cust_config}" STREQUAL "cust_modem_asan")
list(APPEND TEE_C_DEFINITIONS
    CONFIG_MODEM_BALONG_ASLR
)
endif()
