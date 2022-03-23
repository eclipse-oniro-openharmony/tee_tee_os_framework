inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/tzpc
CFILES += platform/libthirdparty_drv/plat_drv/tzpc/tzpc_cfg.c

ifeq ($(PRODUCT_RANGE), base)
        inc-flags += -DCONFIG_TZPC_BASE
        inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/tzpc/$(TARGET_BOARD_PLATFORM)
endif
