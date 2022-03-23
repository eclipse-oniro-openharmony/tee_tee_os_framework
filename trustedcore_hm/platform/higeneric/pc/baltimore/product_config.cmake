set(CONFIG_TA_64BIT true)
set(CONFIG_SSA_64BIT true)
set(CONFIG_GTASK_64BIT true)
set(CONFIG_RPMB_64BIT true)
set(ENABLE_CPP true)
set(ENABLE_CPP_STATIC true)
set(CONFIG_RESUME_FREE_TIMER true)
set(CONFIG_PLATDRV_64BIT false)
set(CONFIG_DRV_TIMER_64BIT false)
set(CONFIG_DRV_64BIT false)
set(CONFIG_GMLIB_IMPORT true)
set(CONFIG_DX_ENABLE true)
set(CONFIG_HUK_SERVICE_64BIT true)
set(CONFIG_HUK_PLAT_COMPATIBLE true)
set(CONFIG_SSA_64BIT true)
set(CONFIG_TIMER_S3_ADJUST_FREQ true)
set(CONFIG_PERMSRV_64BIT true)
#export ENABLE_TA_LOAD_WHITE_BOX_KEY := true

if ("${CONFIG_DRV_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_32
        file_encry.elf
        bdkernel.elf
    )
else()
    list(APPEND PRODUCT_RELEASE_64
        file_encry.elf
        bdkernel.elf
    )
endif()

if ("${CONFIG_DRV_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_APPS_32
        file_encry.elf
		bdkernel.elf
    )
else()
    list(APPEND PRODUCT_APPS_64
        file_encry.elf
        bdkernel.elf
    )
endif()

include(${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/modules/modules.cmake)
