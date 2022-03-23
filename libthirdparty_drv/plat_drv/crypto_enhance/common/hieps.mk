#########################################################
# module initialize
#########################################################
MODULE_DIR := $(call module-dir)
MODULE_LIB-y := libhieps_common.a

#########################################################
# module configure
#########################################################
MODULE_CFLAGS :=

MODULE_INCLUDES := -I$(call get-chip-dir) \
			-I$(SEC_ROOT_DIR)/include

ifeq ($(WITH_ENG_VERSION),true)
MODULE_CFLAGS += -DFEATURE_CDRM_TEST
endif

#$(error MODULE_INCLUDES = $(MODULE_INCLUDES))

MODULE_COBJS-y := hieps_common.o \
                  hieps_smc.o

ifeq ($(WITH_ENG_VERSION),true)
MODULE_COBJS-y += msptest_interface.o

endif

#########################################################
# module make
#########################################################
$(eval $(call module-make))
