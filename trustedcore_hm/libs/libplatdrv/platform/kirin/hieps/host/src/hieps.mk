#########################################################
# module initialize
#########################################################
MODULE_DIR := $(call module-dir)
MODULE_LIB-y := libhieps_pal.a

#########################################################
# module configure
#########################################################
MODULE_CFLAGS :=

MODULE_INCLUDES :=

MODULE_COBJS-y := \
	pal_libc.o \
	pal_timer.o \
	pal_log.o \
	pal_memory.o

#########################################################
# module make
#########################################################
$(eval $(call module-make))
