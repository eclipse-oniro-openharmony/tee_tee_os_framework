# kunpeng img encrypt compile rule.
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

TUR_PATH := $(dir $(lastword $(MAKEFILE_LIST)))
CFLAGS := -Wall -Werror -fPIC -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -pie -fstack-protector-all
CFLAGS += -Wextra -Wfloat-equal -Wformat=2 -Wshadow -Wtrampolines -pipe -fno-strict-aliasing -fsigned-char -fno-common

GCC_VERSION := $(shell expr `gcc -dumpversion | cut -f1 -d.` \>= 5)

ifeq ($(GCC_VERSION), 1)
CFLAGS += -Wdate-time
endif

img_encry: $(TUR_PATH)/img_encry.c
	gcc $(CFLAGS) -Wl,-Bsymbolic -rdynamic -Wl,--no-undefined $< -o  $(TUR_PATH)/$@ -lcrypto

clean:
	rm -rf $(TUR_PATH)/img_encry
