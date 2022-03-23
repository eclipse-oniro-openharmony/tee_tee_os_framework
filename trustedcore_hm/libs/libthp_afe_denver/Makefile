# MODULE is a lib
MODULE := libthp_afe_denver.a

c-flags += -Wno-unused-parameter
c-flags += -fno-builtin
c-flags += -Wall -Wextra

inc-flags += -I$(LIBS_DIR)/libthp_common/include

c-flags += -mfloat-abi=softfp -mfpu=neon

# Source files required to build the target
libthp_afe_denver_c_files += $(wildcard src/*.c)
libthp_afe_denver_c_files += $(wildcard ../libthp_common/src/*.c)

EXPORT_HDRS += $(wildcard ../libthp_common/include/thp_afe.h)

include $(TOPDIR)/mk/lib-common.mk


