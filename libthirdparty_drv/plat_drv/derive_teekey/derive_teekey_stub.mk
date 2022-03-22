
# derive tee key
inc-flags += -DCONFIG_DERIVE_TEEKEY
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/derive_teekey
CFILES += platform/libthirdparty_drv/plat_drv/derive_teekey/derive_teekey_stub.c
