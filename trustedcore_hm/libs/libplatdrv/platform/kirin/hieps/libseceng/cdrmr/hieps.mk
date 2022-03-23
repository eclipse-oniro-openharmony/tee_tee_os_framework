#########################################################
# module initialize
#########################################################
MODULE_DIR := $(call module-dir)
MODULE_LIB-y := libhieps_cdrmr.a

#########################################################
# module configure
#########################################################
MODULE_CFLAGS :=

MODULE_INCLUDES := \
	-I$(MODULE_DIR)/include

MODULE_COBJS-y := \
	cdrmr_cipher.o \
	cdrmr_hash.o \
	cdrmr_hmac.o \
	cdrmr_sm2.o

#########################################################
# module make
#########################################################
$(eval $(call module-make))
