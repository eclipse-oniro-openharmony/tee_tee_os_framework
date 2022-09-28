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
CPPFLAGS += -I$(TOPDIR)/sys_libs/libswcrypto_engine/include
CPPFLAGS += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
CPPFLAGS += -I$(TOPDIR)/prebuild/hm-teeos-local-release/headers/sys/elf_verify

CFILES   := $(wildcard src/permsrv_api_imp.c)

ifeq ($(CONFIG_APP_TEE_PERM),y)
    CFILES += $(wildcard src/permsrv_api.c)
    ifeq ($(CONFIG_DYN_IMPORT_CERT),y)
        CPPFLAGS += -DDYN_IMPORT_CERT=1
        CFILES += $(wildcard src/permsrv_api_cert.c)
    endif
else
    CFILES += $(wildcard src/stub/permsrv_api_stub.c)
    ifeq ($(CONFIG_DYN_IMPORT_CERT),y)
        CPPFLAGS += -DDYN_IMPORT_CERT=1
        CFILES += $(wildcard src/stub/permsrv_api_cert_stub.c)
    endif
endif

CFILES += $(wildcard src/stub/permsrv_api_cms_stub.c)

include $(TOPDIR)/mk/lib-common.mk
