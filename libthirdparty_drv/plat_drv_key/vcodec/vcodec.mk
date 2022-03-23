inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/include/
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv_key/vcodec/hi_vcodec/venc_hivna/
CFILES += platform/libthirdparty_drv/plat_drv_key/vcodec/hi_vcodec/sec_intf.c
CFILES += platform/libthirdparty_drv/plat_drv_key/vcodec/hi_vcodec/venc_hivna/venc_tee.c
CFILES += platform/libthirdparty_drv/plat_drv_key/vcodec/hi_vcodec/venc_hivna/venc_phoenix.c

include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv_key/vcodec/hi_vcodec/sec_decoder.cfg
