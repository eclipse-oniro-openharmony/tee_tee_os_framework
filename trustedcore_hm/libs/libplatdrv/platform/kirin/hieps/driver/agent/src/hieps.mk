#########################################################
# module initialize
#########################################################
MODULE_DIR := $(call module-dir)
MODULE_LIB-y := libhieps_agent.a

#########################################################
# module configure
#########################################################
MODULE_CFLAGS :=

MODULE_INCLUDES :=

MODULE_COBJS-y := \
	hieps_memory.o \
	hieps_run_func.o

#########################################################
# module make
#########################################################
$(eval $(call module-make))
