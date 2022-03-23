if ("${FEATURE_HISI_HIEPS}" STREQUAL "true")
    if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
        set(SEC_DFT_ENABLE ${WITH_ENG_VERSION})
        set(SEC_PRODUCT ${TARGET_BOARD_PLATFORM})
        set(PROJECT_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
        include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/crypto_enhance/hieps.cmake)
        list(APPEND TEE_C_DEFINITIONS ${HIEPS_C_DEFINITIONS})
        list(APPEND TEE_C_SOURCES ${HIEPS_C_SOURCES})
        list(APPEND PLATDRV_INCLUDE_PATH ${HIEPS_INCLUDE_PATH})
        list(APPEND PLATDRV_INCLUDE_PATH
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include/api
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include/common/hieps
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include/common
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/host/include/pal
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/host/include/adapter
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/driver/agent/include
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include/cdrmr
            ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/crypto_enhance/include
        )
    endif()
    if ("${chip_type}" STREQUAL "cs2")
        list(APPEND TEE_C_DEFINITIONS
            CONFIG_HIEPS_BYPASS_TEST
        )
    endif()
endif()