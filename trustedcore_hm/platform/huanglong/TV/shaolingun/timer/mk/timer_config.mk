SOURCE_DIR := $(TOPDIR)/drivers/drv_timer

inc-flags += -I$(SOURCE_DIR)/platform/huanglong/include
inc-flags += -I$(SOURCE_DIR)/platform/huanglong/hardware
inc-flags += -I$(SOURCE_DIR)/platform/huanglong/rtc
inc-flags += -I$(SOURCE_DIR)/platform/huanglong

CFILES += platform/huanglong/hardware/timer_hw.c
CFILES += platform/huanglong/rtc/timer_rtc.c
