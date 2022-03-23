list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/huanglong/include
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/huanglong/hardware
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/huanglong/rtc
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/huanglong
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/huanglong/hardware/timer_hw.c
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/huanglong/rtc/timer_rtc.c
)
