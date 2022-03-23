list(APPEND PLATDRV_LIBRARIES
    dx_cc6260_sbrom
    sec_decoder
)

list(APPEND PLATDRV_LDFLAGS
    -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib
    -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/hi6260
)
