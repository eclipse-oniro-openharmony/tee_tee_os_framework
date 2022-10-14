MODULE := libdrv_frame${TARG}.a

include $(TOPDIR)/mk/var.mk

flags += -fno-builtin
flags += -I$(DRVLIB)/common/libdrv_frame/include/
flags += -I$(TEELIB)/libtimer/include/
flags += -I$(TEELIB)/libhmdrv/include
flags += -I$(TEELIB)/libteeos/include/legacy
flags += -I$(TEELIB)/libteeos/include/tee
flags += -I$(TEELIB)/libteeos/src/log/
flags += -I$(TEELIB)/libteemem/include

flags += -I$(DRIVERS_PATH)/include
flags += -I$(TEELIB)/libteeconfig/include/
flags += -I$(PREBUILD_HEADER)/sys/hmapi

# Source files required to build the target
libdrv_frame_c_files := $(wildcard src/*.c)

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard $(DRVLIB)/common/libdrv_frame/include/*)

include $(TOPDIR)/mk/drv-common.mk
