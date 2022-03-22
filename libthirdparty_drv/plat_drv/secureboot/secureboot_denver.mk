# secureboot
inc-flags += -DWITH_IMAGE_LOAD_SUPPORT \
	    -DCONFIG_DYNAMIC_MMAP_ADDR
inc-flags += -DCONFIG_CHECK_PTN_NAME
inc-flags += -DCONFIG_CHECK_PLATFORM_INFO


inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot \
	    -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot/include \
        -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/modem/include \
	    -I$(SOURCE_DIR)/platform/common/include/ivp

# use for baltimore and later platform
inc-flags += -DCONFIG_HISI_SECBOOT_IMG_V2

ifeq ($(WITH_ENG_VERSION), true)
inc-flags += -DCONFIG_HISI_SECBOOT_DEBUG
endif

CFILES += platform/libthirdparty_drv/plat_drv/secureboot/secureboot_v2.c \
	  platform/libthirdparty_drv/plat_drv/secureboot/secboot.c \
	  platform/libthirdparty_drv/plat_drv/secureboot/process_hifi_info.c \
	  platform/libthirdparty_drv/plat_drv/secureboot/process_isp_info.c

CFILES  +=  \
          platform/libthirdparty_drv/plat_drv/secureboot/process_ivp_info.c
inc-flags += -DCONFIG_HISI_NVIM_SEC
inc-flags += -DCONFIG_HISI_IVP_SEC_IMAGE
# Encrypted Image Incremental Update Service(eiius)
inc-flags += -DCONFIG_HISI_EIIUS
CFILES += platform/libthirdparty_drv/plat_drv/secureboot/eiius_interface.c

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
