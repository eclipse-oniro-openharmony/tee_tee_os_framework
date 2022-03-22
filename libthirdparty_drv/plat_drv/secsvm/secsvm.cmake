# secsvm
if ("${WITH_ENG_VERSION}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TEE_SVM_DEBUG
    )
endif()

if (NOT "${product_type}" STREQUAL "lite")
list(APPEND TEE_C_DEFINITIONS
    TEE_SUPPORT_SVM
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secsvm/include
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secsvm/includeplat/${TARGET_BOARD_PLATFORM}
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secsvm/driver
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/secsvm/driver/hisi_teesvm.c
    platform/libthirdparty_drv/plat_drv/secsvm/driver/hisi_teesvm_helper.c
)
endif()