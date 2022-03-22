# TARGET is a TA app
TARGET := task_hisi_demo.elf

c_files := $(wildcard ./*.c) \
           $(wildcard ./test/*.c)

# Libraries
LIBS :=

c-flags += -I$(HI_TEE_API_DIR)/demo/ \
           -I./test/

include $(HI_TEE_TA_DIR)/itrustee_ta.mk
