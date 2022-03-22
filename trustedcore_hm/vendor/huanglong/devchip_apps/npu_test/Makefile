# TARGET is a TA app
TARGET := task_hisi_npu_test.elf

c_files := $(wildcard *.c)

# Libraries
LIBS :=

c-flags += -I$(HI_TEE_API_DIR)/npu/include
c-flags += -I$(HI_TEE_API_DIR)/npu/npu_test
c-flags += -I$(HI_TEE_API_DIR)/ta_al/itrustee
ifeq ($(strip $(CFG_HI_TEE_NPU_TEST_SUPPORT)), y)
c-flags += -I$(HI_TEE_API_DIR)/npu/npu_test
endif

include $(HI_TEE_TA_DIR)/itrustee_ta.mk
