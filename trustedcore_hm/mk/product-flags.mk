CHOOSE_OPTIONS:=tee_ecies_ext.c
CHOOSE_OPTIONS += ta_magic.c
ROOT_PATH:=$(abspath $(lastword $(MAKEFILE_LIST))../../../)

CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/framework/gtask/src/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/sys_apps/storage/src/task_storage/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/sys_libs/libta_magic_a32/src/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/core/decode/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/core/decode/hal/v5r7b5/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/core/stream/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/osal/tee/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/core/stream/hal/v3r3/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/product/HiVCodecV600/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/intf/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/intf/sec_smmu/*.c)

CHOOSE_OPTIONS_2 := ta_magic.c
CHOOSE_OPTIONS_2 += $(wildcard $(ROOT_PATH)/sys_libs/libta_magic_a32/src/*.c)

FILTER_MODULE := open_source openssl austin
FILTER_MODULE += secisp kds bdkernel task_secboot sre_dev_relcb eSE touchscreen npu_v100 video_decrypt

GENERAL_OPTIONS := -Wdate-time -Wfloat-equal -Wshadow -Wformat=2 -fsigned-char -fno-strict-aliasing \
                   -pipe
WARNING_OPTIONS := -Wall -Wextra -Werror
BLOCKLIST += softcrys secmem eSE
BLOCKLIST += libthp task_antiroot task_ukey hieps codesafe austin/host adp hieps secureflash npu_v100
BLOCKLIST += secureboot fingerprint modem_secboot libfdt touchscreen msp_ta_channel npu_v100 secsvm vcodec pal/src tvp

# we need function is_filter_module to remove open source files
is_filter_module = $(strip $(foreach module,$(FILTER_MODULE),$(findstring $(module),$1)))

# we need function checklist to add blocklist
check_list = $(strip $(foreach module,$(BLOCKLIST),$(findstring $(module),$1)))

last_component = $(shell echo $1 | awk -F '//' '{print $$NF}')
