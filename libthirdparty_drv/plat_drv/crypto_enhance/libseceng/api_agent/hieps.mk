#########################################################
# module initialize
#########################################################
MODULE_DIR := $(call module-dir)
MODULE_LIB-y := libhieps_agent.a

#########################################################
# module configure
#########################################################
MODULE_CFLAGS :=

MODULE_INCLUDES := \
	-I$(MODULE_DIR)/include

MODULE_COBJS-y := \
	api_cipher.o \
	api_mac.o \
	api_hash.o \
	api_hmac.o \
	api_km.o \
	api_rsa.o \
	api_sm2.o

ifeq ($(SEC_DFT_ENABLE),true)
MODULE_COBJS-y += api_symm_dft.o
endif

#########################################################
# module make
#########################################################
$(eval $(call module-make))
