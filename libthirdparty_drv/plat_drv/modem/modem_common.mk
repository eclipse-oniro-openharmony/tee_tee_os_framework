ifeq ($(WITH_MODEM), true)

inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/modem/icc \
			 -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/modem/include

CFILES += platform/libthirdparty_drv/plat_drv/modem/adp/adp_icc.c \
		  platform/libthirdparty_drv/plat_drv/modem/adp/bsp_modem_call.c \
		  platform/libthirdparty_drv/plat_drv/modem/adp/bsp_param_cfg.c \
		  platform/libthirdparty_drv/plat_drv/modem/adp/bsp_secboot_adp.c

CFILES += platform/libthirdparty_drv/plat_drv/modem/icc/ipc_core.c \
		  platform/libthirdparty_drv/plat_drv/modem/icc/icc_core.c \
		  platform/libthirdparty_drv/plat_drv/modem/icc/icc_debug.c \
		  platform/libthirdparty_drv/plat_drv/modem/icc/icc_secos.c

# trng
inc-flags += -DCONFIG_MODEM_TRNG
CFILES += platform/libthirdparty_drv/plat_drv/modem/trng/trng_seed.c

# secboot
CFILES += platform/libthirdparty_drv/plat_drv/secureboot/process_modem_info.c

# without modem
else

CFILES += platform/libthirdparty_drv/plat_drv/modem/adp/bsp_modem_stub.c
CFILES += platform/libthirdparty_drv/plat_drv/secureboot/process_modem_info_stub.c

endif