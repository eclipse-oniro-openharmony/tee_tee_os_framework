
MODULE := libchinadrm_a32.a

c-flags += -Wno-unused-parameter -Wno-pointer-to-int-cast
c-flags += -fno-builtin

inc-flags += -I$(TOPDIR)/libs/libchinadrm/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include

# Source files required to build the target
libchinadrm_a32_c_files += $(wildcard src/*.c)

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard $(TOPDIR)/libs/libchinadrm/include/*)

include $(TOPDIR)/mk/lib-common.mk
