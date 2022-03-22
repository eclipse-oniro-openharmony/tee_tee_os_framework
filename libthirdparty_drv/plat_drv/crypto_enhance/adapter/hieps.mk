#########################################################
# module initialize
#########################################################
MODULE_DIR := $(call module-dir)
MODULE_LIB-y := libdx_adapt.a

#########################################################
# module configure
#########################################################
MODULE_CFLAGS :=

MODULE_INCLUDES := \
	-I$(MODULE_DIR)/include

MODULE_COBJS-y := \
	adapt_rsa.o \
	adapt_cipher.o \
	adapt_hash.o \
	adapt_hmac.o \
	adapt_km.o

ifeq ($(SEC_DFT_ENABLE),true)
MODULE_COBJS-y += adapt_dft.o
endif

#########################################################
# module make
#########################################################
$(eval $(call module-make))
