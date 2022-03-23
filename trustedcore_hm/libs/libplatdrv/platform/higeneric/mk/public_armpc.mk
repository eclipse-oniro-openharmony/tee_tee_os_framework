# kirin platform public

CFILES += platform/kirin/antiroot/device_status.c
CFILES += platform/kirin/antiroot/sre_rwroot.c
ifeq ($(CONFIG_DX_ENABLE), true)
# cc syscall
CFILES += platform/kirin/ccdriver_lib/cc_driver_syscall.c

ifneq ($(product_type), armpc)
CFILES += platform/kirin/ccdriver_lib/eps_syscall.c
endif

endif
