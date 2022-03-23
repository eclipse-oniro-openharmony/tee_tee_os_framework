
ifeq ($(WITH_ENG_VERSION), true)
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/driver_test
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/spi
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/spi/plat/${TARGET_BOARD_PLATFORM}

CFILES += platform/libthirdparty_drv/plat_drv/driver_test/i2c_test.c
CFILES += platform/libthirdparty_drv/plat_drv/driver_test/i3c_test.c
CFILES += platform/libthirdparty_drv/plat_drv/driver_test/spi_test.c
CFILES += platform/libthirdparty_drv/plat_drv/driver_test/bus_test.c
endif
