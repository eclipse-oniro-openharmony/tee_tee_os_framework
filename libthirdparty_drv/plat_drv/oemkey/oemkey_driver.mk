#oem key
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/derive_teekey
inc-flags += -I$(SOURCE_DIR)/platform/common/plat_cap

CFILES += platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.c
CFILES += platform/common/plat_cap/plat_cap_hal.c
