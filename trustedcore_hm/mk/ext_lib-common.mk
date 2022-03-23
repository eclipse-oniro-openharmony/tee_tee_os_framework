# setup toolchain
TARGET_IS_TA := y
TARGET_IS_EXT_LIB := y
include $(TOPDIR)/mk/cfg.mk
include $(TOPDIR)/mk/toolchain.mk
include $(TOPDIR)/mk/llvm-apps-xom.mk
include $(TOPDIR)/mk/common.mk
# use musl lib c headersn.
inc-flags += -I$(PREBUILD_LIBC_INC) -I$(PREBUILD_LIBC_INC)/arch/generic -I$(PREBUILD_LIBC_INC)/arch/$(ARCH) -I$(PREBUILD_LIBC_INC)/arch/$(ARCH)
inc-flags += -I$(PREBUILD_LIBC_INC)/arch/$(ARCH)/bits
inc-flags += $(INCLUDE_PATH:%=-I%)

# c & cpp flags:
flags += -Wall -Wextra -fPIC -fdata-sections -ffunction-sections
flags += -nostdinc -nodefaultlibs -fno-omit-frame-pointer -fstack-protector-strong -fno-short-enums
flags += -DARM_PAE=1
flags += -include$(PREBUILD_DIR)/headers/autoconf.h
