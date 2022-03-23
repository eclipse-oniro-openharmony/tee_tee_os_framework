# secmem
# TEE_SUPPORT_TZMP2 must be true
list(APPEND TEE_C_DEFINITIONS
    TEE_SUPPORT_TZMP2
    CONFIG_HISI_SION_RECYCLE
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secmem/include
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secmem/driver/sec
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secmem/driver/include
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/secmem/driver/sion/sion.c
    platform/libthirdparty_drv/plat_drv/secmem/driver/iommu/siommu.c
    platform/libthirdparty_drv/plat_drv/secmem/driver/lib/genalloc.c
    platform/libthirdparty_drv/plat_drv/secmem/driver/lib/bitmap.c
    platform/libthirdparty_drv/plat_drv/secmem/driver/sion/sion_recycling.c
)

if ("${WITH_ENG_VERSION}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        platform/libthirdparty_drv/plat_drv/secmem/driver/sion/sion_test.c
    )
endif()