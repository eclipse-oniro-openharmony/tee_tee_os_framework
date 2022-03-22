
MODULE := libccmgr${TARG}.a

flags += -fno-builtin

ifeq ($(MTK_CC_FEATURE), true)
inc-flags += -DSUPPORT_M_CC
endif

ifeq ($(CONFIG_CIPHER_ENABLE), true)
flags += -DDX_ENABLE=1
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/host/src/cclib
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/ccdriver_lib/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/host/src/cclib
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/shared/include/pal
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/pal/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/shared/include/crys
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/shared/include/dx_util
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/host/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/shared/include
endif

inc-flags += -I$(TOPDIR)/sys_libs/libccmgr/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include

# Source files required to build the target
libccmgr_c_files += $(wildcard src/*.c)

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard $(TOPDIR)/sys_libs/libccmgr/include/*)

include $(TOPDIR)/mk/lib-common.mk
