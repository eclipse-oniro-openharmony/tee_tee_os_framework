# Makefile for "cclib"
# This is the top-level Makefile - it just selects the relevant sub-directory
HOST_PROJ_ROOT ?= $(shell pwd)/../..
include $(HOST_PROJ_ROOT)/Makefile.defs

default: cclib4$(DX_CONFIG_CC_LIB_ENV)

cclib4$(DX_CONFIG_CC_LIB_ENV):
	@make -C $(DX_CONFIG_CC_LIB_ENV)

clean clean_intermediate:
	@make -C $(DX_CONFIG_CC_LIB_ENV) $@

.PHONY: cclib4$(DX_CONFIG_CC_LIB_ENV) clean clean_intermediate
	
