## initheaders
inc-flags += -I$(PREBUILD_HEADER)/libinitheaders/include

ifeq ($(ARCH),arm)
inc-flags += -I$(PREBUILD_HEADER)/libinitheaders/include/arch/arm32
else
inc-flags += -I$(PREBUILD_HEADER)/libinitheaders/include/arch/aarch64
endif
