# TARGET is keyslot TA app
TARGET := task_hisi_keyslot.elf

c_files := $(wildcard *.c)
c_files += $(wildcard ../../libdevchip_api/common/log/hi_tee_log.c)

# Libraries
LIBS :=

c-flags += -I$(HI_TEE_API_DIR)/keyslot

include $(HI_TEE_TA_DIR)/itrustee_ta.mk
