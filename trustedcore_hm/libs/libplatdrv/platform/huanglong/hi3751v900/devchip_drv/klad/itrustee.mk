#drv_flags :=

drv_incs += . \
            rkp

drv_flags += -DHI_KLAD_PERF_SUPPORT
drv_flags += -DHI_INT_SUPPORT
drv_flags += -DKLAD_MODULE_ID_BASIC=\"./data/$(CFG_HI_TEE_CHIP_TYPE)/module_id_basic.txt\"
drv_flags += -fstack-protector-all

drv_srcs += drv_klad_sw.c \
            drv_klad_hw.c \
            drv_klad_hw_func.c \
            drv_klad_timestamp.c \
            drv_klad_bitmap.c \
            drv_klad_intf.c \
            hal_klad.c \
            drv_hkl.c \
            rkp/drv_rkp.c \
            rkp/drv_rkp_dbg.c \
            rkp/hal_rkp.c

ifeq ($(CFG_ADVCA_NAGRA),y)
drv_srcs += nagra/cert/tee_drv_cert.c \
            nagra/cert/tee_drv_cert_intf.c \
            nagra/cert/tee_hal_cert.c

drv_flags += -I$(TOPDIR)/libs/libplatdrv/platform/devchip/hi3751v900/devchip_drv/klad/nagra/cert
drv_flags += -DHI_TEE_KLAD_CERT

drv_flags += -DHI_KLAD_NAGRA_SUPPORT
drv_flags += -DKLAD_MODULE_ID_NAGRA=\"./data/$(CFG_HI_TEE_CHIP_TYPE)/module_id_nagra.txt\"
endif
