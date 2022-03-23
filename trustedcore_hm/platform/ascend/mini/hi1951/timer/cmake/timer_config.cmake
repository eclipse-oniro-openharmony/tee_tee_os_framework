list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/ascend/include
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/ascend/hi1951/hardware
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/ascend/hi1951
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/ascend/hi1951/hardware/timer_hw.c
)
