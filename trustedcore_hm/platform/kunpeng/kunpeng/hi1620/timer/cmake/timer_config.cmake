list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/kunpeng/include
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/kunpeng/hardware
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/kunpeng
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/kunpeng/hardware/timer_hw.c
)
