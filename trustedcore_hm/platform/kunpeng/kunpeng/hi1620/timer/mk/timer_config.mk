SOURCE_DIR := $(TOPDIR)/drivers/drv_timer

inc-flags += -I$(SOURCE_DIR)/platform/kunpeng/include
inc-flags += -I$(SOURCE_DIR)/platform/kunpeng/hardware
inc-flags += -I$(SOURCE_DIR)/platform/kunpeng

CFILES += platform/kunpeng/hardware/timer_hw.c
