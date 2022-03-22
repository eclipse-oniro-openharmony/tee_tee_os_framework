# MODULE is a lib

MODULE := libhmdrv_stub${TARG}.a

flags += -fno-builtin

ifeq ($(CONFIG_SRE_AUDIT),y)
flags += -DSRE_AUDIT
endif

flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/kernel/
flags += -I$(TOPDIR)/sys_libs/libhmdrv_stub/include/
flags += -I$(TOPDIR)/drivers/platdrv/include/

# Source files required to build the target
libhmdrv_stub_c_files += $(wildcard src/*.c)

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard $(TOPDIR)/sys_libs/libhmdrv_stub/include/*)

include $(TOPDIR)/mk/lib-common.mk
