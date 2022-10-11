# MODULE is a lib

MODULE := libhmdrv_stub${TARG}.a

flags += -fno-builtin

flags += -I$(TEELIB)/libteeconfig/include/kernel/
flags += -I$(TOPDIR)/sys_libs/libhmdrv_stub/include/
flags += -I$(TEELIB)/libteeos/include/tee
flags += -I$(TEELIB)/libteeos/include/legacy
flags += -I$(TEELIB)/libteemem/include

# Source files required to build the target
libhmdrv_stub_c_files += $(wildcard src/*.c)

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard $(TOPDIR)/sys_libs/libhmdrv_stub/include/*)

include $(TOPDIR)/mk/lib-common.mk
