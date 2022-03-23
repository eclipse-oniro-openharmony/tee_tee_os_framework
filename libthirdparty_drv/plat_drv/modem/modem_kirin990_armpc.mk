inc-flags += -I$(SOURCE_DIR)/platform/kirin/modem/icc \
        -I$(SOURCE_DIR)/platform/kirin/modem/include
ifeq ($(WITH_MODEM), true)

CFILES += platform/kirin/modem/adp/adp_icc.c \
      platform/kirin/modem/adp/bsp_modem_call.c \
      platform/kirin/modem/adp/bsp_param_cfg.c \
      platform/kirin/modem/adp/bsp_secboot_adp.c

ICC_CFILES = platform/kirin/modem/icc/ipc_core.c \
      platform/kirin/modem/icc/icc_core.c \
      platform/kirin/modem/icc/icc_debug.c \
      platform/kirin/modem/icc/icc_secos.c

CFILES += $(ICC_CFILES)

# modem trng
inc-flags += -DCONFIG_MODEM_TRNG
CFILES += platform/kirin/modem/trng/trng_seed.c
endif

