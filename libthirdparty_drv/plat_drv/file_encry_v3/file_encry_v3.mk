inc-flags += -DCONFIG_FBE_UFS_KEY_WORKAROUND
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/file_encry_v3
CFILES += \
		  platform/libthirdparty_drv/plat_drv/file_encry_v3/sec_fbe3_ufsc.c \
		  platform/libthirdparty_drv/plat_drv/file_encry_v3/sec_fbe3_km.c
