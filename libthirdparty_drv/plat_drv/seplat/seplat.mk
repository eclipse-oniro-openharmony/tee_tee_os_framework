ifeq ($(CONFIG_FEATURE_SEPLAT), true)
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/libseplat_external/libseplat_external.mk

inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat \
	-I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/data_link \
	-I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/gpio \
	-I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/log \
	-I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/spi \
	-I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/thread \
	-I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/timer \
	-I$(TOPDIR)/../../../../hisi/hise/include/common \
	-I$(TOPDIR)/../../../../hisi/hise/include/common/data_link \

inc-flags += -DCONFIG_FEATURE_SEPLAT \
	-DCONFIG_FEATURE_SEPLAT_GP

CFILES += $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/seplat.c \
	$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/seplat_power.c \
	$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/seplat_status.c \
	$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/spi/seplat_hal_spi.c \
	$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/thread/seplat_hal_thread.c \
	$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/timer/seplat_hal_timer.c \
	$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/gpio/seplat_hal_gpio.c \
	$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/data_link/seplat_data_link.c \
	$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/log/seplat_external_log.c \
	$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/log/seplat_hal_log.c \

ifeq ($(TARGET_BUILD_VARIANT),eng)
inc-flags += -DCONFIG_FEATURE_SEPLAT_TEST \
	-DCONFIG_SEPLAT_TEST

CFILES += $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/seplat_test.c \
	$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/data_link/test/seplat_dl_test_entry.c

inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/seplat/interface_adaptation/data_link/test
endif #TARGET_BUILD_VARIANT

endif #CONFIG_FEATURE_SEPLAT

