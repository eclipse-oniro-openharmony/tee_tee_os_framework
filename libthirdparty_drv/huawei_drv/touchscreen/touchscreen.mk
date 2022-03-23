
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/touchscreen	\
	    -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/touchscreen/panel \
        -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/touchscreen

CFILES += \
      platform/libthirdparty_drv/huawei_drv/touchscreen/hisi_tui_touchscreen.c	\
	  platform/libthirdparty_drv/huawei_drv/touchscreen/panel/tui_amtel.c		\
	  platform/libthirdparty_drv/huawei_drv/touchscreen/panel/tui_jdi.c		\
	  platform/libthirdparty_drv/huawei_drv/touchscreen/panel/tui_novatek.c	\
	  platform/libthirdparty_drv/huawei_drv/touchscreen/panel/tui_himax.c	\
	  platform/libthirdparty_drv/huawei_drv/touchscreen/panel/tui_parade.c	\
	  platform/libthirdparty_drv/huawei_drv/touchscreen/panel/tui_st.c		\
	  platform/libthirdparty_drv/huawei_drv/touchscreen/panel/tui_st_new.c	\
	  platform/libthirdparty_drv/huawei_drv/touchscreen/panel/tui_sec.c		\
	  platform/libthirdparty_drv/huawei_drv/touchscreen/panel/tui_synaptics.c	\
	  platform/libthirdparty_drv/huawei_drv/touchscreen/panel/tui_synaptics_tcm.c	\
	  platform/libthirdparty_drv/huawei_drv/touchscreen/panel/tui_fts.c		\
	  platform/libthirdparty_drv/huawei_drv/touchscreen/panel/tui_gt1x.c		\
	  platform/libthirdparty_drv/huawei_drv/touchscreen/panel/tui_gtx8.c		\
	  platform/libthirdparty_drv/huawei_drv/touchscreen/panel/tui_ssl.c		\
	  platform/libthirdparty_drv/huawei_drv/touchscreen/panel/tui_elan.c
