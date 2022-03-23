# TARGET is a TA app
TARGET := task_hisi_hdmitx.elf

c_files := $(wildcard ./*.c)

# Libraries
LIBS :=

c-flags += -I$(HI_TEE_API_DIR)/hdmitx

include $(HI_TEE_TA_DIR)/itrustee_ta.mk
