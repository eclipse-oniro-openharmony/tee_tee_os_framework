inc-flags += -DWITH_IMAGE_LOAD_SUPPORT \
	    -DCONFIG_DYNAMIC_MMAP_ADDR
inc-flags += -DCONFIG_CHECK_PTN_NAME
inc-flags += -DCONFIG_CHECK_PLATFORM_INFO

inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot \
	    -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot/include \
	    -I$(SOURCE_DIR)/platform/common/include/ivp

inc-flags += -DCONFIG_CC_CUID
CFILES += platform/libthirdparty_drv/plat_drv/secureboot/secureboot.c \
	  platform/libthirdparty_drv/plat_drv/secureboot/secboot.c \
      platform/libthirdparty_drv/plat_drv/secureboot/sec_derive_cuid.c \
	  platform/libthirdparty_drv/plat_drv/secureboot/process_hifi_info.c \
	  platform/libthirdparty_drv/plat_drv/secureboot/process_isp_info.c \
	  platform/libthirdparty_drv/plat_drv/secureboot/zlib/adler32.c \
	  platform/libthirdparty_drv/plat_drv/secureboot/zlib/inffast.c \
	  platform/libthirdparty_drv/plat_drv/secureboot/zlib/inflate.c \
	  platform/libthirdparty_drv/plat_drv/secureboot/zlib/inftrees.c \
	  platform/libthirdparty_drv/plat_drv/secureboot/zlib/uncompr.c \
	  platform/libthirdparty_drv/plat_drv/secureboot/zlib/zutil.c


ifeq ($(WITH_MODEM), true)
CFILES += platform/libthirdparty_drv/plat_drv/secureboot/process_modem_info.c

ifeq ($(chip_type), cs2)
CFILES += platform/libthirdparty_drv/plat_drv/secureboot/hisi_secboot_modem_aslr.c \
	  platform/libthirdparty_drv/plat_drv/secureboot/hisi_secboot_modem_patch.c \
	  platform/libthirdparty_drv/plat_drv/modem/adp/sec_modem_dump_plat.c
#536ʹ���µ�mloader�Ͷ�Ӧ���䲹��
inc-flags += -DCONFIG_MLOADER
inc-flags += -DCONFIG_MODEM_COLD_PATCH
inc-flags += -DCONFIG_COLD_PATCH_BORROW_DDR
#536��ʼ��5g core
inc-flags += -DCONFIG_MODEM_ASLR_5G_CORE
else
#phoenixʹ���ϵ�loadm���ϵ��䲹��
inc-flags += -DCONFIG_COLD_PATCH
CFILES += platform/libthirdparty_drv/plat_drv/modem/adp/sec_modem_dump.c
endif
else
CFILES += platform/libthirdparty_drv/plat_drv/modem/adp/bsp_modem_stub.c
CFILES += platform/libthirdparty_drv/plat_drv/secureboot/process_modem_info_stub.c
endif

ifneq ($(product_type), armpc)
CFILES  +=  \
          platform/libthirdparty_drv/plat_drv/secureboot/process_ivp_info.c
inc-flags += -DCONFIG_HISI_NVIM_SEC
inc-flags += -DCONFIG_HISI_IVP_SEC_IMAGE
endif

#modem_cold_patch
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot/bspatch/ \
	    -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot/bspatch/include \
	    -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot/bspatch/include/bsdiff
platdrv_cpp_files += platform/libthirdparty_drv/plat_drv/secureboot/bspatch/bspatch.cpp \
	  platform/libthirdparty_drv/plat_drv/secureboot/bspatch/buffer_file.cpp \
	  platform/libthirdparty_drv/plat_drv/secureboot/bspatch/extents.cpp \
	  platform/libthirdparty_drv/plat_drv/secureboot/bspatch/extents_file.cpp \
	  platform/libthirdparty_drv/plat_drv/secureboot/bspatch/file.cpp \
	  platform/libthirdparty_drv/plat_drv/secureboot/bspatch/memory_file.cpp \
	  platform/libthirdparty_drv/plat_drv/secureboot/bspatch/sink_file.cpp \
	  platform/libthirdparty_drv/plat_drv/secureboot/bspatch/secure_bspatch.cpp

# Encrypted Image Incremental Update Service(eiius)
inc-flags += -DCONFIG_HISI_EIIUS
CFILES += platform/libthirdparty_drv/plat_drv/secureboot/eiius_interface.c

ifneq ($(cust_config), cust_modem_asan)
inc-flags += -DCONFIG_MODEM_BALONG_ASLR
endif
