SOURCE_DIR := $(TOPDIR)/drivers/drv_timer

inc-flags += -I$(SOURCE_DIR)/platform/ascend/include
inc-flags += -I$(SOURCE_DIR)/platform/ascend/hi1951/hardware
inc-flags += -I$(SOURCE_DIR)/platform/ascend/hi1951

CFILES += platform/ascend/hi1951/hardware/timer_hw.c
