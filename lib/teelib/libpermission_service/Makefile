#
# Copyright 2022, Huawei Co. Ltd.
#
# See "HUAWEI_LICENSE" for details.
#

# Targets
MODULE := libpermission_service${TARG}.a

# This library only provides 32-bit headers of libbteeos.
# If we want 64-bit headers of libteeos, we should depend on libac temporarily.

CPPFLAGS += -I$(TEELIB)/libpermission_service/include
CPPFLAGS += -I$(TEELIB)/libpermission_service/src
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/include
CPPFLAGS += -I$(TEELIB)/libswcrypto_engine/include
CPPFLAGS += -I$(TEELIB)/libteeagentcommon_client/include
CPPFLAGS += -I$(TEELIB)/libcrypto/include
CPPFLAGS += -I$(TOPDIR)/prebuild/hm-teeos-local-release/headers/sys/elf_verify

CFILES   := $(wildcard src/permsrv_api_imp.c)

ifeq ($(CONFIG_APP_TEE_PERM),y)
    CFILES += $(wildcard src/permsrv_api.c)
    ifeq ($(CONFIG_DYN_IMPORT_CERT),y)
        CPPFLAGS += -DDYN_IMPORT_CERT=1
        CFILES += $(wildcard src/permsrv_api_cert.c)
    endif
endif

include $(TOPDIR)/mk/lib-common.mk
