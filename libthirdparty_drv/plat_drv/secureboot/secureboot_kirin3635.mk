# secureboot
inc-flags += -DWITH_IMAGE_LOAD_SUPPORT \
	    -DCONFIG_DYNAMIC_MMAP_ADDR
inc-flags += -DCONFIG_CHECK_PTN_NAME

inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot \
	    -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot/include \
	    -I$(SOURCE_DIR)/platform/common/include/ivp

CFILES += platform/libthirdparty_drv/plat_drv/secureboot/secureboot.c \
	  platform/libthirdparty_drv/plat_drv/secureboot/secboot.c \
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
else
CFILES += platform/libthirdparty_drv/plat_drv/modem/adp/bsp_modem_stub.c
CFILES += platform/libthirdparty_drv/plat_drv/secureboot/process_modem_info_stub.c
endif

#Encrypted Image Incremental Update Service(eiius)

# modem_cold_patch
inc-flags += -DCONFIG_COLD_PATCH
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
