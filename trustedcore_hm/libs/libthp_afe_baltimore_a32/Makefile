# tui compile rule, modified by t00292236
# Copyright Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

MODULE := libthp_afe_baltimore_a32.a

c-flags += -fno-builtin
c-flags += -Wall -Wextra
c-flags += -mfloat-abi=softfp -mfpu=neon

inc-flags += -I$(LIBS_DIR)/libthp_common/include

# Source files required to build the target
libthp_afe_baltimore_a32_c_files += $(wildcard src/*.c)
libthp_afe_baltimore_a32_c_files += $(wildcard ../libthp_common/src/*.c)

EXPORT_HDRS += $(wildcard ../libthp_common/include/*.h)

include $(TOPDIR)/mk/lib-common.mk
