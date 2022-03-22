list(APPEND PLATDRV_LIBRARIES
    dx_orlando_sbrom
    sec_decoder
)
list(APPEND PLATDRV_LDFLAGS
    -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib
)
if ("${chip_type}" STREQUAL "es")
    list(APPEND PLATDRV_LDFLAGS
        -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/orlando/ES
    )
else()
    list(APPEND PLATDRV_LDFLAGS
        -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/orlando/CS
    )
endif()
