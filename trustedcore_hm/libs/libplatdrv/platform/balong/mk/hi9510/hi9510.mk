# hi9510
# # hisi common includes
# # ccdriver_lib
inc-flags += -DDEF_WBITS=0x2f
inc-flags += -DCONFIG_MODEM_SECBOOT_ES
ifeq ($(CONFIG_DX_ENABLE), true)
OPTIONS :=
OPTIONS += $(if $(findstring,$(c-flags)),,-Wall)
OPTIONS += $(if $(findstring -Wall,$(c-flags)),,-Wall)
OPTIONS += $(if $(findstring -Wextra,$(c-flags)),,-Wextra)
OPTIONS += $(if $(findstring -DCC_DRIVER=1,$(c-flags)),,-DCC_DRIVER=1)
c-flags += $(OPTIONS)

inc-flags += -I$(SOURCE_DIR)/platform/balong/ccdriver_lib/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/codesafe/src/crypto_api
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver/cc712
CFILES += platform/common/cc_driver/cc712/cc_driver_adapt.c
CFILES += platform/balong/ccdriver_lib/cc_adapt.c
CFILES += platform/common/cc_driver/cc_driver_hal.c
endif

inc-flags += -DCONFIG_MLOADER_NO_SHARE_MEM
inc-flags += -I$(SOURCE_DIR)/platform/common/include \
			 -I$(SOURCE_DIR)/platform/balong/platform/hi9510_udp

inc-flags += -I$(SOURCE_DIR)/platform/balong/memory/
CFILES += platform/balong/memory/memory_driver.c

# memory layout
inc-flags += -I$(SOURCE_DIR)/platform/balong/memory_layout/
CFILES += platform/balong/memory_layout/memory_layout.c
#
# # sysboot para
CFILES +=  platform/balong/sysboot/sysboot_para.c

inc-flags += -I$(SOURCE_DIR)/platform/balong/include/
inc-flags += -I$(SOURCE_DIR)/platform/balong/secureboot/
inc-flags += -I$(SOURCE_DIR)/platform/balong/efuse/
inc-flags += -I$(SOURCE_DIR)/platform/balong/secureboot/zlib/open_source/

#zlib
inc-flags += -DMY_ZCALLOC
CFILES += platform/balong/secureboot/zlib/zmalloc.c
CFILES += platform/balong/secureboot/zlib/open_source/adler32.c
CFILES += platform/balong/secureboot/zlib/open_source/crc32.c
CFILES += platform/balong/secureboot/zlib/open_source/inffast.c
CFILES += platform/balong/secureboot/zlib/open_source/inflate.c
CFILES += platform/balong/secureboot/zlib/open_source/inftrees.c
CFILES += platform/balong/secureboot/zlib/open_source/uncompr.c
CFILES += platform/balong/secureboot/zlib/open_source/zutil.c

CFILES += \
		  platform/balong/sec_call/bsp_modem_call.c \
		  platform/balong/efuse/hisi_efuse.c \
		  platform/balong/sec_dump/sec_modem_dump.c \
		  platform/balong/modem/adp/bsp_param_cfg.c

CFILES += \
		  platform/balong/eicc200/eicc_core.c \
		  platform/balong/eicc200/eicc_driver.c \
		  platform/balong/eicc200/eicc_device.c \
		  platform/balong/eicc200/eicc_proxy.c \
		  platform/balong/eicc200/eicc_pmsr.c \
		  platform/balong/eicc200/eicc_plat_teeos.c

CFILES += platform/balong/eicc200/eicc_dtsv200.c

CFILES += \
		  platform/balong/msg/msg_core.c \
		  platform/balong/msg/msg_cmsg.c \
		  platform/balong/msg/msg_mem.c \
		  platform/balong/msg/msg_plat_teeos.c \
		  platform/balong/msg/msg_mntn.c

CFILES += $(wildcard platform/balong/secureboot/*.c)

inc-flags += -DCONFIG_MODEM_CHECK_IMAGE_SIZE

inc-flags += -DCONFIG_CHECK_PUBKEY

