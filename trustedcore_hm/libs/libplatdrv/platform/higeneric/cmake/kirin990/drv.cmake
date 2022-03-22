
# modem start
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../../vendor/hisi/modem/config/product/${OBB_PRODUCT_NAME}/config
)
# modem end

include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/npu_v100/npu_v100.cmake)

# c++
set(USE_GNU_CXX y)
list(APPEND PLATDRV_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/thirdparty/opensource/libbz_hm/src
)
list(APPEND PLATDRV_LIBRARIES
    bz_hm
)

# kirin990
# hisi common includes
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/include
)
if ("${chip_type}" STREQUAL "cs2")
    list(APPEND PLATDRV_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/kirin/include/platform/kirin990_cs2
    )
    list(APPEND TEE_C_DEFINITIONS
        WITH_CHIP_CS2
        MODEM_SOCP_3_0
    )
else()
    list(APPEND PLATDRV_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/kirin/include/platform/kirin990
    )
    list(APPEND TEE_C_DEFINITIONS
        WITH_CHIP_CS
    )
endif()

# spi i2c i3 test
if ("${WITH_ENG_VERSION}" STREQUAL "true")
    list(APPEND PLATDRV_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/kirin/driver_test
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/kirin/spi
    )
    list(APPEND TEE_C_SOURCES
        platform/kirin/driver_test/i2c_test.c
        platform/kirin/driver_test/i3c_test.c
        platform/kirin/driver_test/spi_test.c
        platform/kirin/driver_test/bus_test.c
    )
endif()

# i2c
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/i2c/i2c.cmake)

# i3c
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/i3c/i3c.cmake)

# spi
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/spi/spi.cmake)

# hisi_mailbox
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/mailbox/mailbox.cmake)

# gpio
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/gpio/gpio.cmake)

# dma
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/dma/dma.cmake)

# tzpc
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/tzpc/tzpc.cmake)

# oemkey
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.cmake)

# tzarch
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/tzarch/tzarch.cmake)

# ddr seccfg
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/seccfg/seccfg.cmake)

# secmem
# TEE_SUPPORT_TZMP2 must be true
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secmem/secmem.cmake)

# secmem_ddr
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secmem/secmem_ddr.cmake)

# secsvm
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secsvm/secsvm.cmake)

# isp
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv_key/isp/isp.cmake)

# ivp
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/ivp/ivp.cmake)

# ccdriver_lib
if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    # ccdriver_lib
    include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/ccdriver_lib/ccdriver_kirin990.cmake)
    # eima2.0+rootscan
    include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/antiroot/antiroot.cmake)
endif()

list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/kirin/modem/icc
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/kirin/modem/include
)

# modem trng
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/modem/modem_kirin990.cmake)

# secureboot
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secureboot/secureboot_kirin990.cmake)

# hifi
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/hifi/hifi.cmake)

# hdcp for wifidisplay(wfd)
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/hdcp_wfd/hdcp_wfd.cmake)

# display, from trustedcore/platform/common/display/Android.mk
# TUI_FEATURE must be true
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/display2.0/display2.0.cmake)

# touchscheen
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/touchscreen/touchscreen.cmake)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common
)

include(${CMAKE_CURRENT_SOURCE_DIR}/platform/common/tui_drv/tui_drv.cmake)

# fingerprint
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/fingerprint/fingerprint.cmake)

# inse
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/eSE_kirin990.cmake)

if (NOT "${cust_config}" STREQUAL "cust_modem_asan")
    list(APPEND TEE_C_DEFINITIONS
        CONFIG_MODEM_BALONG_ASLR
    )
endif()

# file encry
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/file_encry/file_encry.cmake)

# face_recognize
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/face_recognize/face_recognize.cmake)

#vdec_vfmw
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/kirin/vcodec/hi_vcodec/sec_decoder.cfg
)

# video_decrypt
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/video_decrypt/video_decrypt.cmake)

# vdec-video_decoder
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/kirin/video_decrypt
)

#vcodec
set(VCODEC_TARGET_PLATFORM VCodecV500)
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv_key/vcodec/vcodec.cmake)

# sensorhub
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/sensorhub/sensorhub.cmake)

# crypto_enhance
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/crypto_enhance/crypto_enhance.cmake)

# teeos shared memmory
include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/tee_sharedmem/tee_sharedmem.cmake)
