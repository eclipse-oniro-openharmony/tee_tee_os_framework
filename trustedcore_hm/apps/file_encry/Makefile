# TARGET is a TA app
TARGET := file_encry.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

file_encry_c_files += $(wildcard src/*.c)
ifeq ($(TEE_SUPPORT_FILE_ENCRY_V3),true)
file_encry_c_files += src/task_file_encry_v3/sec_fbe3_derive_key.c \
		      src/task_file_encry_v3/sec_fbe3_drv.c \
		      src/task_file_encry_v3/sec_fbe3_interface.c \
		      src/task_file_encry_v3/sec_fbe3_ta.c
# This is for MSP enable
ifeq ($(CONFIG_HISI_MSPC),true)
file_encry_c_files += src/task_file_encry_v3/msp_fbe.c
flags += -DFILE_ENCRY_MSP_ENABLE
endif
ifeq ($(CONFIG_FILE_ENCRY_USING_RPMB),true)
file_encry_c_files += src/task_file_encry_v3/sec_fbe3_rpmb.c
flags += -DFILE_ENCRY_USING_RPMB
endif
# This is for FBE2
else
file_encry_c_files += $(wildcard src/task_file_encry/*.c)
endif

ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(CONFIG_GCOV), y)
file_encry_c_files += ../../sys_libs/libta_magic_a32/src/ta_magic.c
else
file_encry_c_files += $(TOPDIR)/sys_libs/libta_magic_a32/src/ta_magic.c
endif
endif
flags_UNSUPPORTED += -Wno-unused-function
flags += -Wdate-time
flags += -Wextra
flags += -Wfloat-equal
flags += -Wformat=2
flags += -Wshadow
# Libraries
LIBS :=
ifeq ($(TEE_SUPPORT_FILE_ENCRY_V3), true)
inc-flags += -I$(APPS_DIR)/file_encry/src/task_file_encry_v3
inc-flags += -I$(TOPDIR)/libs/libmspcore_a32/include
inc-flags += -I$(TOPDIR)/libs/libsec_flash_client_a32/src/
inc-flags += -I$(TOPDIR)/libs/libmspcore/include
else
inc-flags += -I$(APPS_DIR)/file_encry/src/task_file_encry
endif

include $(TOPDIR)/mk/ta-common.mk
