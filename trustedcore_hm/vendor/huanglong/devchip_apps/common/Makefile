# TARGET is common TA app
TARGET := task_hisi_common.elf

c_files := $(wildcard *.c)

# Libraries
LIBS :=

c-flags += -I$(HI_TEE_API_DIR)/common

include $(HI_TEE_TA_DIR)/itrustee_ta.mk
