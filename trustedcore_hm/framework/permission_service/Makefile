# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.

# TARGET is an app
TARGET := permission_service${TARG}.elf

include $(TOPDIR)/mk/var.mk

permission_service_c_files :=  $(wildcard src/*.c)

LIBS += permsrv${TARG}

# these libs are for elf verify
LIBS += elf_verify${TARG} \
    elf_verify_key${TARG} \
    whitebox${TARG}       \
    dynconfmgr${TARG}     \
    dynconfbuilder${TARG}

ifeq ($(findstring true, $(CONFIG_REMOTE_ATTESTATION_32BIT) $(CONFIG_REMOTE_ATTESTATION_64BIT)), true)
LIBS += tcmgr$(TARG)
endif

ifeq ($(CONFIG_LIVEPATCH_ENABLE), y)
LIBS += livepatch${TARG}
endif

ifeq ($(CONFIG_TA_CMS_SIGNATURE),y)
ifeq (${TARG}, )
LIBS += cmscbb tee_cmscbb${TARG}
endif
endif

LIBS += base_shared${TARG}

inc-flags += -I$(PLATFORM_DIR)/common/include
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(TOPDIR)/drivers/base_mgr/tee_misc_driver/src
c-flags += -I$(TOPDIR)/framework/permission_service/src

ifeq ($(CONFIG_CMS_CAHASH_AUTH),y)
LIBS += tee_cmscbb${TARG} cmscbb${TARG}
permission_service_c_files += $(wildcard src/auth/tee_auth_sign_cms.c)
c-flags += -I$(TOPDIR)/framework/permission_service/src/auth/tee_auth_sign_cms.h
inc-flags += -I$(TOPDIR)/sys_libs/libtee_cmscbb/include
inc-flags += -I$(PREBUILD_HEADER)/openssl
else
permission_service_c_files += $(wildcard src/auth/tee_auth_sign_rsa.c)
c-flags += -I$(TOPDIR)/framework/permission_service/src/auth/tee_auth_sign_rsa.h
endif

include $(TOPDIR)/mk/ta-common.mk
include $(TOPDIR)/mk/feature-macro.mk

ifeq ($(CONFIG_DYNLINK),y)
TA_LDFLAGS += -e tee_task_entry
endif
