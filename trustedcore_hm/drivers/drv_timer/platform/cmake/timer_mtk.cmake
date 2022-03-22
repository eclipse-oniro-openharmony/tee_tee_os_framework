list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/mtk/include
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/mtk/hardware
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/mtk
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/mtk/rtc
)
list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/drivers/drv_timer/platform/mtk/hardware/timer_hw.c
)

include(${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/timer/cmake/timer_rtc.cmake)
