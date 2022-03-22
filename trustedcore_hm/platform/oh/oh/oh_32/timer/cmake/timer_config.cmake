list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/ipc/include
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/ipc/hardware
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/ipc
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/ipc/hardware/timer_hw.c
)
