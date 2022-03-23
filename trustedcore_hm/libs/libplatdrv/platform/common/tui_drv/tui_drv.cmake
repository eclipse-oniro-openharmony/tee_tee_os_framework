list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common
)
list(APPEND TEE_C_SOURCES
    platform/common/tui_drv/drv_hal.c
    platform/common/tui_drv/mem_cfg.c
    platform/common/tui_drv/tui_drv.c
    platform/common/tui_drv/tui_timer.c
)