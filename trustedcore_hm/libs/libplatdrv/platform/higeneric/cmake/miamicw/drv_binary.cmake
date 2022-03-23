list(APPEND PLATDRV_LIBRARIES
    dx_cc3670_sbrom
)
list(APPEND PLATDRV_LDFLAGS
    -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib
)
