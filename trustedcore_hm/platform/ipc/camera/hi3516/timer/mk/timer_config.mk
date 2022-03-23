SOURCE_DIR := $(TOPDIR)/drivers/drv_timer

inc-flags += -I$(SOURCE_DIR)/platform/ipc/include
inc-flags += -I$(SOURCE_DIR)/platform/ipc/hardware
inc-flags += -I$(SOURCE_DIR)/platform/ipc

CFILES += platform/ipc/hardware/timer_hw.c
