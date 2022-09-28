#
# Copyright 2022, Huawei Co. Ltd.
#
# See "HUAWEI_LICENSE" for details.
#

# Targets
TARGETS := libpermission_service${TARG}.a

# This library only provides 32-bit headers of libbteeos.
# If we want 64-bit headers of libteeos, we should depend on libac temporarily.

CPPFLAGS += -I$(PWD)/libs/teelib/libpermission_service/include
CPPFLAGS += -I$(PWD)/libs/teelib/libpermission_service/src
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(PWD)/libs/teelib/libcrypto/include
CPPFLAGS += -I$(PWD)/libs/teelib/libelf_verify/include
CPPFLAGS += -I$(PWD)/libs/syslib/libipc/include
CPPFLAGS += -I$(PWD)/libs/syslib/libteemem/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/include
CPPFLAGS += -I$(PWD)/ext_apps/hm-apps/trustedcore_hm/sys_libs/libswcrypto_engine/include
CPPFLAGS += -I$(PWD)/ext_apps/hm-apps/trustedcore_hm/sys_libs/libteeagentcommon_client/include

include $(HM_COMMON)/common-nwe-flags.mk
include $(HM_COMMON)/bootstrap-flags.mk

CFILES   := $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/permsrv_api_imp.c))

ifeq ($(CONFIG_APP_TEE_PERM),y)
    CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/permsrv_api.c))
    ifeq ($(CONFIG_DYN_IMPORT_CERT),y)
        CPPFLAGS += -DDYN_IMPORT_CERT=1
        CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/permsrv_api_cert.c))
    endif
else
    CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/stub/permsrv_api_stub.c))
    ifeq ($(CONFIG_DYN_IMPORT_CERT),y)
        CPPFLAGS += -DDYN_IMPORT_CERT=1
        CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/stub/permsrv_api_cert_stub.c))
    endif
endif

CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/stub/permsrv_api_cms_stub.c))

include $(HM_COMMON)/common.mk

