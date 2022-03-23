list(APPEND PLATDRV_LIBRARIES
    dx_laguna_sbrom
    sec_decoder
)
list(APPEND PLATDRV_LDFLAGS
    -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib
)
if ("${chip_type}" STREQUAL "es")
    list(APPEND PLATDRV_LDFLAGS
        -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/laguna/ES
    )
else()
    list(APPEND PLATDRV_LDFLAGS
        -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/laguna/CS
    )
endif()

if ("${WITH_MODEM}" STREQUAL "true")
    list(APPEND PLATDRV_LIBRARIES
        sec_modem
    )
endif()
