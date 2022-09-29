# Target is a TA app

MODULE := libteeagentcommon_client${TARG}.a

libteeagentcommon_client_c_files += $(wildcard src/*.c)

inc-flags += -I$(TEELIB)/libteeagentcommon_client/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
#c-flags += -Wno-unused-parameter
flags += -fno-builtin

#c-flags += -Wall -Wno-parentheses -Wno-unused-parameter

include $(TOPDIR)/mk/lib-common.mk

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard include/*)
