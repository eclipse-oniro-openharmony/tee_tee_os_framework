MODULE := libdrv_frame${TARG}.a

include $(TOPDIR)/mk/var.mk

flags += -fno-builtin
flags += -I$(TOPDIR)/sys_libs/libdrv_frame/include/
flags += -I$(TOPDIR)/sys_libs/libtimer/include/
flags += -I$(TOPDIR)/sys_libs/libccmgr/include/
flags += -I$(TOPDIR)/drivers/platdrv/include/
flags += -I$(TOPDIR)/drivers/common
flags += -I$(TOPDIR)/drivers/include
flags += -I$(TOPDIR)/platform/common/tee_config
flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/
flags += -I$(PREBUILD_HEADER)/sys/hmapi

# Source files required to build the target
all_c_files := $(wildcard src/*.c)

ifneq ($(CONFIG_DRIVER_DYN_MOD), true)
filter_c_files := src/drv_mod.c
libdrv_frame_c_files += $(filter-out $(filter_c_files), $(all_c_files))
else
libdrv_frame_c_files += $(all_c_files)
endif

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard $(TOPDIR)/sys_libs/libdrv_frame/include/*)

include $(TOPDIR)/mk/drv-common.mk
