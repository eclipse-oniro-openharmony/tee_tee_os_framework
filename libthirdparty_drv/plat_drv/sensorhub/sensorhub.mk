ifneq ($(filter $(TARGET_BOARD_PLATFORM), baltimore), )
	inc-flags += -DBALTIMORE_SFD_CONVERT
endif

inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/sensorhub
CFILES += platform/libthirdparty_drv/plat_drv/sensorhub/sensorhub_ipc.c
