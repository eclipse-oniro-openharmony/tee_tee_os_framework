# TARGET is a TA app
TARGET := smmu_task.elf

c_files := $(wildcard *.c)

# Libraries
LIBS :=

c-flags += -I$(HI_TEE_API_DIR)/mem/include

include $(HI_TEE_TA_DIR)/itrustee_ta.mk
