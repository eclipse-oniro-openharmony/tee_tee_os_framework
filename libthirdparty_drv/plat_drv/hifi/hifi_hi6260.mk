

ifneq ($(findstring 2g_mem, $(ap_cust_spec)), )
inc-flags += -DCONFIG_AP_CUST_2G_MEM
endif

inc-flags += -DCONFIG_SUPPORT_HIFI_LOAD
inc-flags += -I$(SOURCE_DIR)/platform/common/include/hifi
CFILES += platform/libthirdparty_drv/plat_drv/hifi/hifi_reload.c
