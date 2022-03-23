# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.

# TARGET is an app

DRIVER := gtask${TARG}.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

include $(TOPDIR)/mk/var.mk

ifeq ($(CONFIG_DYN_TA_FORMAT),1)
flags += -DDYN_TA_SUPPORT_V1
flags += -DDYN_TA_SUPPORT_V2
flags += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),2)
flags += -DDYN_TA_SUPPORT_V2
flags += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),3)
flags += -DDYN_TA_SUPPORT_V3
else
$(error "dynamic TA format not supported, please check CONFIG_DYN_TA_FORMAT")
endif

gtask_c_files := $(wildcard src/*.c)
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/gtask/include
inc-flags += -I$(TOPDIR)/framework/gtask/src/
inc-flags += -I$(PLATFORM_DIR)/common/tee_config
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include

ifeq ($(product_type), cdc)
$(info product type is cdc)
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

ifeq ($(shell test $(CONFIG_DYN_TA_FORMAT) -gt 2; echo $$?),0)
FILTEROUT_CFILES += src/tee_img_v2_allowed_table.c
endif
gtask_c_files := $(filter-out $(FILTEROUT_CFILES), $(gtask_c_files))

LIBS := gtask${TARG}       \
    c_shared${TARG}        \
    tee_shared${TARG}      \
    teeos${TARG}           \
    teemem${TARG}          \
    hmdrv${TARG}           \
    ac${TARG}              \
    teeconfig${TARG}       \
    ac_policy${TARG}       \
    vendor_static${TARG}   \
    dynconfmgr${TARG}      \
    dynconfbuilder${TARG}  \
    spawn_common${TARG}

LIBS += base_shared${TARG}

ifeq ($(findstring y, $(CONFIG_APP_TEE_PERM)$(CONFIG_APP_TEE_PERM_A32)),)
LIBS += elf_verify${TARG} \
    elf_verify_key${TARG} \
    whitebox${TARG}
endif

ifeq ($(CONFIG_SMCMGR_EMBEDDED), y)
LIBS += teesmcmgr${TARG}
endif

ifeq ($(CONFIG_SSA_EMBEDDED), y)
LIBS += ssagent${TARG}
endif

ifeq ($(CONFIG_CMS_CAHASH_AUTH),y)
LIBS += tee_cmscbb${TARG} cmscbb${TARG}
gtask_c_files += $(wildcard src/ascend/auth/tee_auth_sign_cms.c)
inc-flags += -I$(TOPDIR)/framework/gtask/src/ascend/auth
inc-flags += -I$(TOPDIR)/sys_libs/libtee_cmscbb/include
inc-flags += -I$(PREBUILD_HEADER)/openssl
else
gtask_c_files += $(wildcard src/higeneric/auth/tee_auth_sign_rsa.c)
inc-flags += -I$(TOPDIR)/framework/gtask/src/higeneric/auth/tee_auth_sign_rsa.h
endif

ifeq ($(CONFIG_SSA_EMBEDDED), y)
gtask_c_files += $(wildcard ../huk_service/src/huk_service_config.c)
inc-flags += -I$(TOPDIR)/framework/huk_service/include
endif

ifeq ($(CONFIG_TERMINAL_DRV_SUPPORT),y)
LIBS += devchip_api${TARG}
endif

DRV_LDFLAGS += -z text -z noexecstack --dynamic-linker=libc_shared${TARG}.so
ifeq ($(CONFIG_GCOV), y)
flags += --coverage -g
DRV_LDFLAGS += --no-gc-sections --start-group $(EH_FILE) --end-group
LIBS += llvm_gcov${TARG}
endif

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
