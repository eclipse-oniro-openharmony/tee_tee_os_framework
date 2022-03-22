if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    list(APPEND PLATDRV_LDFLAGS
        -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/balong/ccdriver_lib
    )
endif()
