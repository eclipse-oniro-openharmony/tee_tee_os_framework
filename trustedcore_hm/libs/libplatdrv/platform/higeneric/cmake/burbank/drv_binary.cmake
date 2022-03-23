list(APPEND PLATDRV_LIBRARIES
    dx_burbank_sbrom
)
list(APPEND PLATDRV_LDFLAGS
    -L${PROJECT_SOURCE_DIR}/libs/hisi-platdrv/platform/kirin/ccdriver_lib
)