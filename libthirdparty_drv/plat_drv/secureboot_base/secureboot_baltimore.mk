
# secureboot_base
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot_base \
	    -I$(SOURCE_DIR)/platform/common/include/ivp

# use for baltimore and later platform
inc-flags += -DCONFIG_HISI_SECBOOT_IMG_V2

CFILES += platform/libthirdparty_drv/plat_drv/secureboot_base/secureboot_v2.c \
	  platform/libthirdparty_drv/plat_drv/secureboot_base/process_hifi_info.c \
	  platform/libthirdparty_drv/plat_drv/secureboot_base/process_isp_info.c \
	  platform/libthirdparty_drv/plat_drv/secureboot_base/secboot.c
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot_base/bspatch/ \
		    -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot_base/bspatch/include \
		    -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot_base/bspatch/include/bsdiff
platdrv_cpp_files += platform/libthirdparty_drv/plat_drv/secureboot_base/bspatch/bspatch.cpp \
		     platform/libthirdparty_drv/plat_drv/secureboot_base/bspatch/buffer_file.cpp \
		     platform/libthirdparty_drv/plat_drv/secureboot_base/bspatch/extents.cpp \
		     platform/libthirdparty_drv/plat_drv/secureboot_base/bspatch/extents_file.cpp \
		     platform/libthirdparty_drv/plat_drv/secureboot_base/bspatch/file.cpp \
		     platform/libthirdparty_drv/plat_drv/secureboot_base/bspatch/memory_file.cpp \
		     platform/libthirdparty_drv/plat_drv/secureboot_base/bspatch/sink_file.cpp \
		     platform/libthirdparty_drv/plat_drv/secureboot_base/bspatch/secure_bspatch.cpp

