# MODULE is a lib
MODULE := libthp_afe_3660_6250.a

c-flags += -fno-builtin
c-flags += -Wall -Wextra
c-flags += -mfloat-abi=softfp -mfpu=neon

inc-flags += -I$(LIBS_DIR)/libthp_afe_3660_6250/include

# Source files required to build the target
libthp_afe_3660_6250_c_files += $(wildcard src/*.c)

EXPORT_HDRS += $(wildcard include/thp_afe.h)

include $(TOPDIR)/mk/lib-common.mk