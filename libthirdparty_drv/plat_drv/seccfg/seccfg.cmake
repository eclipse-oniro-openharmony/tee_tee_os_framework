# secmem_ddr
if ("${TARGET_BOARD_PLATFORM}" STREQUAL "kirin990")
if ("${chip_type}" STREQUAL "es")
list(APPEND TEE_C_DEFINITIONS
    KIRIN990_DDR_ES
)
endif()
endif()

list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/seccfg/hisi_hwspinlock.c
)
