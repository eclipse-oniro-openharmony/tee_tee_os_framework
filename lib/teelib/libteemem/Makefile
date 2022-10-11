MODULE := libteemem${TARG}.a

CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libhmdrv/include
CPPFLAGS += -I$(TEELIB)/libteeconfig/include
CPPFLAGS += -I$(TEELIB)/libteemem/include
CPPFLAGS += -I$(PREBUILD_HEADER)/sys/mmgr_sysmgr
CPPFLAGS += -I$(PREBUILD_HEADER)/sys/mmgr

# Source files required to build the target
CFILES := $(wildcard src/*.c)

include $(TOPDIR)/mk/lib-common.mk
