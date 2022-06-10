# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.

# TARGET is an app

DRIVER := gtask${TARG}.elf

include $(TOPDIR)/mk/var.mk
include $(TOPDIR)/mk/plat.mk
ifeq ($(CONFIG_DYN_TA_FORMAT),1)
flags += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),2)
flags += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),3)
flags += -DDYN_TA_SUPPORT_V3
else
$(error "dynamic TA format not supported, please check CONFIG_DYN_TA_FORMAT")
endif

gtask_c_files := $(wildcard src/*.c)
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/gtask/include
inc-flags += -I$(TOPDIR)/framework/gtask/src/
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/src/tee_config
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include
inc-flags += -I$(PLATFORM_DIR)/common/include
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include

ifeq ($(product_type), cdc)
$(info product type is cdc)
flags += -DCONFIG_TA_SIGN_CDC
else ifeq ($(product_type), cdc_ace)
$(info product type is cdc_ace)
flags += -DCONFIG_TA_SIGN_CDC
else ifeq ($(product_name), mdc)
$(info product type is mdc)
flags += -DCONFIG_TA_SIGN_MDC
else ifeq ($(product_name), mini)
$(info product type is mini)
flags += -DCONFIG_TA_SIGN_MINI
else ifeq ($(CONFIG_TA_SIGN_KEY_CBG),true)
flags += -DCONFIG_TA_SIGN_CBG
else ifeq ($(CONFIG_HUANGLONG_LOAD_KEY_3072),y)
flags += -DCONFIG_TA_SIGN_HUANGLONG
endif

ifeq ($(CONFIG_PLAT_HUANGLONG),y)
gtask_c_files += ../../platform/huanglong/ta_load/tee_ta_load.c
endif

gtask_c_files := $(filter-out $(FILTEROUT_CFILES), $(gtask_c_files))

LIBS := gtask${TARG}       \
    c_shared${TARG}        \
    tee_shared${TARG}      \
    permission_service${TARG} \
    teemem${TARG}          \
    hmdrv${TARG}           \
    ac${TARG}              \
    teeconfig${TARG}       \
    ac_policy${TARG}       \
    dynconfmgr${TARG}      \
    dynconfbuilder${TARG}  \
    spawn_common${TARG}

ifneq ($(CONFIG_NO_VENDOR_LIB_EMBEDDED), true)
LIBS += vendor_static${TARG}
endif

LIBS += base_shared${TARG}

ifeq ($(findstring y, $(CONFIG_APP_TEE_PERM)$(CONFIG_APP_TEE_PERM_A32)),)
LIBS += elf_verify${TARG} \
    elf_verify_key${TARG} \
    whitebox${TARG}
endif

ifeq ($(CONFIG_TERMINAL_DRV_SUPPORT),y)
LIBS += devchip_api${TARG}
endif

DRV_LDFLAGS += -z text -z noexecstack --dynamic-linker=libc_shared${TARG}.so

ENTRY_POINT := main

# drv makefile will fully link a binary.
include $(TOPDIR)/mk/svc-common.mk
include $(TOPDIR)/mk/feature-macro.mk

ifeq ($(xom32_enable),y)
DRV_LDFLAGS += -T $(XOM_LDS)
endif

ifeq ($(DRIVER),gtask_a32.elf)
flags := $(filter-out -flto -fsplit-lto-unit,$(flags))
endif

flags += -fstack-protector-all
## gtask will only link here, so so object folder, need to create it.
$(shell mkdir -p $(BUILD_DIR))

ifneq ($(findstring true, $(CONFIG_TEST_INNER_SERVICE_32BIT)$(CONFIG_TEST_INNER_SERVICE_64BIT)),)
ifeq (${TARG}, ) #64
DRV_LDFLAGS += -L$(TOPDIR)/../../tee_os_kernel/build/arm/libtest_service -ltest_service
else
DRV_LDFLAGS += -L$(TOPDIR)/../../tee_os_kernel/build/arm/libtest_service_a32 -ltest_service_a32
endif
endif
