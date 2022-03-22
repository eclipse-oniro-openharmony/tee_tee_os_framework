# TARGET is pvr TA app
TARGET := task_hisi_pvr.elf

c_files := $(wildcard ./*.c)

# Libraries
LIBS :=

c-flags += -I$(HI_TEE_API_DIR)/pvr

include $(HI_TEE_TA_DIR)/itrustee_ta.mk
