list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/platform/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/timer/include
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/balong/include
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/balong/hardware
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/balong/rtc
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/balong
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/balong/hardware/timer_hw.c
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/balong/rtc/timer_rtc.c
)
