# "Root" Makefile for Host domain
# This makefile invokes the relevant target specific makefile to build it (e.g., cclib)

INCDIRS_EXTRA:=$(CURDIR)/../../../libc $(CURDIR)/../../../include
export INCDIRS_EXTRA

.PHONY: clean default
default:
	export
	@$(MAKE) -C host/src/ ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
clean:
	@$(MAKE) -C host/src/ ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- clean

