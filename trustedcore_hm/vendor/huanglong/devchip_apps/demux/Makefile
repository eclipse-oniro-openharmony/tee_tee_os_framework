# TARGET is demux TA app
TARGET := task_hisi_dmx.elf

c_files := $(wildcard ./*.c)

# Libraries
LIBS :=

c-flags += -I$(HI_TEE_API_DIR)/demux

include $(HI_TEE_TA_DIR)/itrustee_ta.mk
