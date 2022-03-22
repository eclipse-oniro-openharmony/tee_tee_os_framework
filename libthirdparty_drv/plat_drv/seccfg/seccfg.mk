# ddr seccfg
ifneq ($(filter $(TARGET_BOARD_PLATFORM), kirin990), )
ifeq ($(chip_type),es)
inc-flags += -DKIRIN990_DDR_ES
endif
endif

CFILES += platform/libthirdparty_drv/plat_drv/seccfg/hisi_hwspinlock.c
