# MODULE is a lib
MODULE := libthp_afe_baltimore.a

c-flags += -fno-builtin
c-flags += -Wall -Wextra
c-flags += -mfloat-abi=softfp -mfpu=neon

inc-flags += -I$(LIBS_DIR)/libthp_common/include

# Source files required to build the target
libthp_afe_baltimore_c_files += $(wildcard src/*.c)
libthp_afe_baltimore_c_files += $(wildcard ../libthp_common/src/*.c)

EXPORT_HDRS += $(wildcard ../libthp_common/include/thp_afe.h)

include $(TOPDIR)/mk/lib-common.mk
