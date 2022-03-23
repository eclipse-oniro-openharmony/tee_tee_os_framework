list(APPEND PLATDRV_LIBRARIES
    dx_baltimore_sbrom
    sec_decoder
    teeagentcommon_client
)
list(APPEND PLATDRV_LDFLAGS
    -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib
)

if ("${chip_type}" STREQUAL "es")
    list(APPEND PLATDRV_LDFLAGS
        -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/baltimore/ES
    )
else()
    list(APPEND PLATDRV_LDFLAGS
        -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/baltimore/CS
    )
endif()

if ("${WITH_MODEM}" STREQUAL "true")
    list(APPEND PLATDRV_LIBRARIES
        sec_modem
    )
endif()

if ("${FEATURE_HISI_MSP_ENGINE_LIBCRYPTO}" STREQUAL "true")
    if ("${TARGET_BUILD_VARIANT}" STREQUAL "eng")
        list(APPEND PLATDRV_LIBRARIES
            seceng_eng
        )
    else()
        list(APPEND PLATDRV_LIBRARIES
            seceng
        )
    endif()

    if ("${chip_type}" STREQUAL "es")
        list(APPEND PLATDRV_LDFLAGS
            -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/msp_engine/libseceng/baltimore_es/libs
        )
    else()
        list(APPEND PLATDRV_LDFLAGS
            -L${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/msp_engine/libseceng/baltimore_cs/libs
        )
    endif()
endif()
