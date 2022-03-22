# copy tee_pvr.h to ta_dev_dir for pvr TA
global-incdirs-y += .

srcs-y += tee_pvr_utils.c

cflags-y += -Wno-error -Wno-implicit-function-declaration
cflags-y += -I$(HI_TEE_DRV_DIR)/include
