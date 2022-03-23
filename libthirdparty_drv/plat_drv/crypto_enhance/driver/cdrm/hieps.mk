#########################################################
# module initialize
#########################################################
MODULE_DIR := $(call module-dir)
MODULE_LIB-y := libhieps_cdrm.a

#########################################################
# module configure
#########################################################
MODULE_CFLAGS :=

MODULE_INCLUDES := \
	-I$(call get-chip-dir)

MODULE_COBJS-y := hieps_cdrm_cmd.o

#########################################################
# module make
#########################################################
$(eval $(call module-make))
