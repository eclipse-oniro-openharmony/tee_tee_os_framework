#
#
# See "HUAWEI_LICENSE" for details.
#
#

# Targets
TARGETS := libteemem${TARG}.a

# String prototypes prevent this from being turned on


include $(HM_COMMON)/common-nwe-flags.mk
include $(HM_COMMON)/bootstrap-flags.mk

CPPFLAGS += -I$(STAGE_DIR)/include/debug
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(PWD)/libs/syslib/libhmlog/include
CPPFLAGS += -I$(PWD)/libs/syslib/libhongmeng/include
CPPFLAGS += -I$(PWD)/libs/syslib/libmmgr/include
CPPFLAGS += -I$(TEELIB)/libhmdrv/include
CPPFLAGS += -I$(PWD)/libs/syslib/libipc/include
CPPFLAGS += -I$(PWD)/ext_apps/hm-apps/trustedcore_hm/drivers/include
CPPFLAGS += -I$(TEELIB)/libteeconfig/include

# Source files required to build the target
CFILES := $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/*.c))

# Header files/directories this library provides
HDRFILES := $(wildcard $(SOURCE_DIR)/include/*)


include $(HM_COMMON)/common.mk

