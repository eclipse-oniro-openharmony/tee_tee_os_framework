#NPU //hi3690 enable compile

#modem start
BALONG_TOPDIR := $(SOURCE_DIR)/../../../../../../../vendor/hisi

inc-flags += -I$(BALONG_TOPDIR)/modem/config/product/$(OBB_PRODUCT_NAME)/config
#modem end

include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/npu_v100.mk

# c++
USE_GNU_CXX = y
inc-flags += -I$(TOPDIR)/thirdparty/opensource/libbz_hm/src
LIBS += bz_hm

# kirin990
# hisi common includes
inc-flags += -I$(SOURCE_DIR)/platform \
	    -I$(SOURCE_DIR)/platform/common/include
ifneq ($(chip_type),cs2)
inc-flags += -I$(SOURCE_DIR)/platform/kirin/include/platform/kirin990
inc-flags += -DWITH_CHIP_CS
else
inc-flags += -DWITH_CHIP_CS2
inc-flags += -I$(SOURCE_DIR)/platform/kirin/include/platform/kirin990_cs2
inc-flags += -DMODEM_SOCP_3_0
endif

# spi i2c i3 test
ifeq ($(WITH_ENG_VERSION), true)
inc-flags += -I$(SOURCE_DIR)/platform/kirin/driver_test
inc-flags += -I$(SOURCE_DIR)/platform/kirin/spi
CFILES += platform/kirin/driver_test/i2c_test.c
CFILES += platform/kirin/driver_test/i3c_test.c
CFILES += platform/kirin/driver_test/spi_test.c
CFILES += platform/kirin/driver_test/bus_test.c
endif

# i2c
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/i2c/i2c.mk

# I3C
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/i3c/i3c.mk

# spi
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/spi/spi.mk

#hisi_mailbox
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/mailbox/mailbox.mk

# gpio
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/gpio/gpio.mk

# dma
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/dma/dma.mk

# tzpc
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/tzpc/tzpc.mk

# oemkey
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.mk

# tzarch
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/tzarch/tzarch.mk

# hisi_hwspinlock
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seccfg/seccfg.mk

# secmem
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secmem/secmem.mk

# secmem
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secmem/secmem_ddr.mk

# secsvm
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secsvm/secsvm.mk

# isp
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv_key/isp/isp.mk

# ivp
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/ivp/ivp.mk

ifeq ($(CONFIG_DX_ENABLE), true)
# ccdriver_lib
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/ccdriver_lib/ccdriver_lib.mk

# eima2.0+rootscan
include $(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/antiroot/antiroot.mk
endif

# modem trng
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/modem/modem_kirin990.mk

# secureboot
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot/secureboot_kirin990.mk


# hifi
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/hifi/hifi.mk

# hdcp for wifidisplay(wfd)
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/hdcp_wfd/hdcp_wfd.mk

# TUI_FEATURE must be true
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/display2.0/display2.0.mk



# touchscheen
include $(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/touchscreen/touchscreen.mk


inc-flags += -I$(SOURCE_DIR)/platform/common
include $(SOURCE_DIR)/platform/common/tui_drv/tui_drv.mk

# fingerprint
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/fingerprint/fingerprint.mk

# inse
include $(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/eSE_kirin990.mk

ifneq ($(cust_config), cust_modem_asan)
inc-flags += -DCONFIG_MODEM_BALONG_ASLR
endif
# file encry
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/file_encry/file_encry.mk

# face_recognize
include $(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/face_recognize/face_recognize.mk

# video_decrypt
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/video_decrypt/video_decrypt.mk

#vcodec
VCODEC_TARGET_PLATFORM := VCodecV500
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv_key/vcodec/vcodec.mk

# sensorhub
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/sensorhub/sensorhub.mk

# crypto_enhance
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/crypto_enhance/crypto_enhance.mk

# teeos shared memmory
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/tee_sharedmem/tee_sharedmem.mk

