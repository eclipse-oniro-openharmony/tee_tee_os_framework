list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/platform/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/timer/include
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/ct/include
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/ct/hardware
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/ct
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/ct/hardware/timer_hw.c
)
