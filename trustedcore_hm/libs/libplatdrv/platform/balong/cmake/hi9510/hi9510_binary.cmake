list(APPEND PLATDRV_LIBRARIES
    dx_9500_sbrom
    dx_9500_dmpu
)
if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    list(APPEND PLATDRV_LDFLAGS
        -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/ccdriver_lib/hi9500
    )
endif()
