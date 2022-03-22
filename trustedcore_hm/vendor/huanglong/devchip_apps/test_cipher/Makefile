# TARGET is a TA app
TARGET := task_hisi_test_cipher.elf

c_files := hisi_test_cipher_task.c task_hash.c task_symc.c task_cenc.c task_cenc_asyn.c

SRC_DIR := ../../../../../test/cipher/tee/test_cipher_ta
$(shell test -f hisi_test_cipher_task.c || ln -s $(SRC_DIR)/hisi_test_cipher_task.c ./)
$(shell test -f hisi_test_cipher_task.h || ln -s $(SRC_DIR)/hisi_test_cipher_task.h ./)
$(shell test -f task_hash.c || ln -s $(SRC_DIR)/task_hash.c ./)
$(shell test -f task_hash.h || ln -s $(SRC_DIR)/task_hash.h ./)
$(shell test -f task_symc.c || ln -s $(SRC_DIR)/task_symc.c ./)
$(shell test -f task_symc.h || ln -s $(SRC_DIR)/task_symc.h ./)
$(shell test -f task_cenc.c || ln -s $(SRC_DIR)/task_cenc.c ./)
$(shell test -f task_cenc.h || ln -s $(SRC_DIR)/task_cenc.h ./)
$(shell test -f task_cenc_asyn.c || ln -s $(SRC_DIR)/task_cenc_asyn.c ./)

# Libraries
LIBS :=

c-flags += -I$(TEE_DIR)/devchip_drv/cipher/test \
           -I$(TEE_DIR)/devchip_drv/include

include $(HI_TEE_TA_DIR)/itrustee_ta.mk
