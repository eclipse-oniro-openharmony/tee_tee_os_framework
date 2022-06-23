# driver_timer compile rule
# Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
DRIVER := drv_timer.elf

# Use gnueabi toolchain to support relro
ifeq (${TARG},_a32)
USE_GNU_CXX=y
endif
include $(TOPDIR)/mk/feature-macro.mk
include $(TOPDIR)/mk/var.mk
include $(TOPDIR)/mk/plat.mk

inc-flags += -I$(TOPDIR)/drivers/include
inc-flags += -I$(PREBUILD_DIR)/headers/ddk
inc-flags += -I$(TOPDIR)/drivers/common
inc-flags += -I$(LIBS_DIR)/libplatdrv/platform/common/include
inc-flags += -I$(LIBS_DIR)/libplatdrv/platform/common/crypto
inc-flags += -I$(TOPDIR)/drivers/drv_timer/src
inc-flags += -I$(TOPDIR)/drivers/platdrv/include/
inc-flags += -I$(TOPDIR)/sys_libs/libdrv_frame/include/
inc-flags += -I$(PREBUILD_HEADER)/sys/stackprotect
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/timer/include

ifeq ($(chip_type), es)
    inc-flags += -I$(TOPDIR)/../../../../hisi/ap/platform/$(TARGET_BOARD_PLATFORM)_es
else
    ifeq ($(chip_type), cs2)
        inc-flags += -I$(TOPDIR)/../../../../hisi/ap/platform/$(TARGET_BOARD_PLATFORM)_cs2
    else
        inc-flags += -I$(TOPDIR)/../../../../hisi/ap/platform/$(TARGET_BOARD_PLATFORM)
    endif
endif

ifeq ($(CONFIG_SOFT_RTC_TICK), true)
flags += -DSOFT_RTC_TICK -DSOFT_RTC_IRQ_DISABLE
endif

ifeq ($(CONFIG_SOFT_RTC_TICK), false)
flags += -DSOFT_RTC_IRQ_DISABLE
endif

ifeq ($(CONFIG_DX_ENABLE), true)
flags += -DDX_ENABLE=1
endif

ifeq ($(CONFIG_TIMER_S3_ADJUST_FREQ), true)
flags += -DTIMER_S3_ADJUST_FREQ
endif

ifeq ($(CONFIG_RESUME_FREE_TIMER), true)
flags += -DRESUME_FREE_TIMER_FEATURE
endif

ifeq ($(CONFIG_TIMER_PERMISSION_DISABLE), true)
flags += -DTIMER_PERMISSION_DISABLE
endif

# Source files required to build the target
drv_timer_c_files := src/main.c \
                     src/timer_init.c \
                     src/timer_irq.c \
                     src/timer_pm.c \
                     src/timer_sys.c \
                     src/timer_desc.c \
                     src/timer_interrupt.c \
                     $(TOPDIR)/drivers/common/drv_call_check.c \
                     $(TOPDIR)/drivers/common/drv_pm_check.c

ifeq ($(CONFIG_TIMER_FREERUNNING_FIQ_DISABLE), true)
flags += -DTIMER_FREE_RUNNING_FIQ_DISABLE
endif

ifeq ($(CONFIG_TIMER_EVENT), true)
drv_timer_c_files += src/timer_event.c
c-flags += -DTIMER_EVENT_SUPPORT
endif

# include platform driver makefile
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/timer/mk/timer_config.mk
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/timer_common.mk
drv_timer_c_files += $(CFILES)

LIBS := c_shared${TARG} \
    io${TARG} \
    teeos${TARG} \
    teemem${TARG} \
    hwi${TARG} \
    ac${TARG} \
    crypto_hal${TARG} \
    teeconfig${TARG} \
    hmdrv${TARG} \
    hmdrv_stub${TARG} \
    ac_policy${TARG}

# sanitity will disable gc-section, need to add all dependence libs
ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl)
LIBS += openssl${TARG}
endif

ENTRY_POINT := main
DRV_LDFLAGS += -z text -z noexecstack --dynamic-linker=libc_shared${TARG}.so

# for DECLARE_TC_DRV, prevent ".tc_drv_descs" section from being merged
ifeq (${TARG},)
drv_timer_LDFLAGS += -T$(SOURCE_DIR)/linker64.ld
endif

# drv makefile will fully link a binary.
include $(TOPDIR)/mk/drv-common.mk

ifeq (${TARG},_a32)
ifeq ($(xom32_enable),y)
drv_timer_LDFLAGS += -T$(SOURCE_DIR)/linker.xom.ld
else
drv_timer_LDFLAGS += -T$(SOURCE_DIR)/linker.ld
endif
endif
