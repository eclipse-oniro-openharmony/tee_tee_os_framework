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

PWD := $(shell pwd)

gtask_c_files := $(wildcard src/*.c)
gtask_c_files   += $(wildcard src/*/*.c)
gtask_c_files   += $(wildcard src/*/*/*.c)

inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/gtask/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/src/tee_config
inc-flags += -I$(PLATFORM_DIR)/common/include
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include

inc-flags += -I$(PREBUILD_HEADER)/openssl
inc-flags += -I$(PREBUILD_SYS)/irqmgr
inc-flags += -I$(PREBUILD_SYS)/ssa
inc-flags += -I$(PREBUILD_SYS)/se_service
inc-flags += -I$(PREBUILD_SYS)/mmgr
inc-flags += -I$(PREBUILD_SYS)/mmgr_sysmgr
inc-flags += -I$(PREBUILD_SYS)/huk
inc-flags += -I$(PREBUILD_SYS)/elf_verify
inc-flags += -I$(PWD)/../teesmcmgr/src
inc-flags += -I$(PWD)/src/init
inc-flags += -I$(PWD)/src/include
inc-flags += -I$(PWD)/src/app_load
inc-flags += -I$(PWD)/src/framework
inc-flags += -I$(PWD)/src/task_adaptor
inc-flags += -I$(PWD)/src/manager
inc-flags += -I$(TOPDIR)/sys_libs/libac_policy/include
inc-flags += -I$(PWD)/src
inc-flags += -I$(TOPDIR)/sys_libs/libdynconfmgr/include
inc-flags += -I$(TOPDIR)/sys_libs/libdynconfbuilder/include
inc-flags += -I$(PWD)/../drvmgr/src
inc-flags += -I$(TOPDIR)/drivers/include
inc-flags += -I$(TOPDIR)/sys_libs/libspawn_common/include/
inc-flags += -I$(TOPDIR)/lib/teelib/libagent_base/include/
inc-flags += -I$(TOPDIR)/lib/teelib/libhmdrv/include/

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

gtask_c_files := $(filter-out $(FILTEROUT_CFILES), $(gtask_c_files))

LIBS := c_shared${TARG}        \
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

LIBS += base_shared${TARG}

ifeq ($(findstring y, $(CONFIG_APP_TEE_PERM)$(CONFIG_APP_TEE_PERM_A32)),)
LIBS += elf_verify${TARG} \
    elf_verify_key${TARG} \
    whitebox${TARG}
endif

ifeq ($(CONFIG_TERMINAL_DRV_SUPPORT),y)
LIBS += devchip_api${TARG}
endif

LDFLAGS += -z text -z noexecstack --dynamic-linker=libc_shared${TARG}.so

ENTRY_POINT := main

# drv makefile will fully link a binary.
include $(TOPDIR)/mk/svc-common.mk
include $(TOPDIR)/mk/feature-macro.mk

ifeq ($(xom32_enable),y)
LDFLAGS += -T $(XOM_LDS)
endif

ifeq ($(DRIVER),gtask_a32.elf)
flags := $(filter-out -flto -fsplit-lto-unit,$(flags))
endif

flags += -fstack-protector-all
## gtask will only link here, so so object folder, need to create it.
$(shell mkdir -p $(BUILD_DIR))

#gtask need to print tlogi info log
flags += -DTA_LOG_LEVEL=2

# Suppress Wimplicit-fall-through warning: gtask heavily uses it

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),openssl)
flags += -DOPENSSL_ENABLE
endif

ifneq ($(findstring true, $(CONFIG_TEST_INNER_SERVICE_32BIT)$(CONFIG_TEST_INNER_SERVICE_64BIT)),)
ifeq (${TARG}, ) #64
LDFLAGS += -L$(TOPDIR)/../../tee_os_kernel/build/arm/libtest_service -ltest_service
else
LDFLAGS += -L$(TOPDIR)/../../tee_os_kernel/build/arm/libtest_service_a32 -ltest_service_a32
endif
endif
