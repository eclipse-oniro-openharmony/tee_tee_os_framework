# face_recognize
if (NOT "${product_type}" STREQUAL "armpc")
    list(APPEND TEE_C_DEFINITIONS
        SWING_SUPPORTED
    )
    list(APPEND TEE_C_SOURCES
        platform/libthirdparty_drv/huawei_drv/face_recognize/tee_face_recognize.c
    )
endif()