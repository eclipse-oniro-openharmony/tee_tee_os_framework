
HOST_PROJ_ROOT ?= $(shell pwd)/../..
include $(TOPDIR)/mk/plat.mk
include $(HOST_PROJ_ROOT)/Makefile.defs

CFLAGS += $(TRUSTEDCORE_PLATFORM_FLAGS)

include project_cc7x_teelib.mk

include $(HOST_PROJ_ROOT)/Makefile.rules

