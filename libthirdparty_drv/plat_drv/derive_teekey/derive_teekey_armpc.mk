
# derive tee key
inc-flags += -DCONFIG_DERIVE_TEEKEY
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/derive_teekey
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/derive_teekey/$(TARGET_BOARD_PLATFORM)/armpc
CFILES += platform/libthirdparty_drv/plat_drv/derive_teekey/cc_derive_teekey.c
