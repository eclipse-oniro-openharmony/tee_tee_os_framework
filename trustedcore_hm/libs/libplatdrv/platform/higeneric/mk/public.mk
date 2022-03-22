# kirin platform public

CFILES += platform/kirin/antiroot/device_status.c
CFILES += platform/kirin/antiroot/sre_rwroot.c
ifeq ($(CONFIG_DX_ENABLE), true)
# cc syscall
CFILES += platform/kirin/ccdriver_lib/cc_driver_syscall.c

ifneq ($(product_type), armpc)
CFILES += platform/kirin/ccdriver_lib/eps_syscall.c
endif
endif

ifneq ($(findstring true, $(CONFIG_SE_SERVICE_32BIT)$(CONFIG_SE_SERVICE_64BIT)),)
CFILES += platform/kirin/eSE/se_syscall.c
endif

ifneq ($(product_type), armpc)
CFILES += platform/kirin/secmem/driver/sion/dynion.c
endif

#gatekeeper syscall
include $(SOURCE_DIR)/platform/common/gatekeeper/gatekeeper_drv.mk

# rtc timer
ifeq ($(CONFIG_OFF_DRV_TIMER), y)
inc-flags += -I$(SOURCE_DIR)/platform/common/rtc_timer/platform/generic/include
inc-flags += -I$(SOURCE_DIR)/platform/common/rtc_timer/platform/generic/src
inc-flags += -I$(SOURCE_DIR)/platform/common/rtc_timer/src
CFILES += platform/common/rtc_timer/src/rtc_timer_event.c
CFILES += platform/common/rtc_timer/src/rtc_timer_init.c
CFILES += platform/common/rtc_timer/src/rtc_timer_pm.c
CFILES += platform/common/rtc_timer/src/rtc_timer_syscall.c
CFILES += platform/common/rtc_timer/platform/generic/src/timer_rtc.c
endif
