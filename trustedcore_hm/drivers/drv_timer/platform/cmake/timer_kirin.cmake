list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/higeneric/include
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/higeneric/hardware
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/higeneric/rtc
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/higeneric
)

list(APPEND TEE_C_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/higeneric/hardware/timer_hw.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/higeneric/rtc/timer_rtc.c
)
