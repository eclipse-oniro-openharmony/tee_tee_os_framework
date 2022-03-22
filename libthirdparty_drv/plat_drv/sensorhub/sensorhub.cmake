# sensorhub
if ("${TARGET_BOARD_PLATFORM}" STREQUAL "baltimore")
list(APPEND TEE_C_DEFINITIONS
    BALTIMORE_SFD_CONVERT
)
endif()

list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/sensorhub
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/sensorhub/sensorhub_ipc.c
)