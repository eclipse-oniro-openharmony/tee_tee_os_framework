if ("${CONFIG_FEATURE_SEPLAT}" STREQUAL "true")
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/data_link
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/gpio
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/log
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/spi
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/thread
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/timer \
    ${PROJECT_SOURCE_DIR}/../../../../hisi/hise/include/common
    ${PROJECT_SOURCE_DIR}/../../../../hisi/hise/include/common/data_link
)

list(APPEND TEE_C_DEFINITIONS
    CONFIG_FEATURE_SEPLAT
    CONFIG_FEATURE_SEPLAT_GP
)

list(APPEND TEE_C_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/seplat.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/seplat_power.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/seplat_status.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/spi/seplat_hal_spi.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/thread/seplat_hal_thread.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/timer/seplat_hal_timer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/gpio/seplat_hal_gpio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/data_link/seplat_data_link.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/log/seplat_external_log.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/log/seplat_hal_log.c
)

if ("${TARGET_BUILD_VARIANT}" STREQUAL "eng")
list(APPEND TEE_C_DEFINITIONS
    CONFIG_FEATURE_SEPLAT_TEST
    CONFIG_SEPLAT_TEST
)
list(APPEND TEE_C_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/seplat_test.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/data_link/test/seplat_dl_test_entry.c
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/data_link/test
)

endif()
endif()