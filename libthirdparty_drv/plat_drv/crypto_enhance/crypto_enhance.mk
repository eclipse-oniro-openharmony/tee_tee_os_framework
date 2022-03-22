ifeq ($(FEATURE_HISI_HIEPS), true)
ifeq ($(CONFIG_DX_ENABLE), true)
    export SEC_DFT_ENABLE := $(WITH_ENG_VERSION)
    export SEC_PRODUCT = $(TARGET_BOARD_PLATFORM)
    export PROJECT_ROOT_DIR = $(SOURCE_DIR)
    include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/crypto_enhance/Makefile
    SEC_CFILES := $(patsubst $(SOURCE_DIR)/%,%,$(SEC_CFILES))
    $(info HIEPS SEC_INCS = $(SEC_INCS) -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/crypto_enhance/include)
    $(info HIEPS SEC_CFLAGS = $(SEC_CFLAGS))
    $(info HIEPS SEC_CFILES = $(SEC_CFILES))
    CFILES += $(sort $(SEC_CFILES))
    CFILES := $(addprefix $(TOPDIR)/libs/libplatdrv/,$(CFILES))
    inc-flags += $(SEC_INCS) \
                -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/crypto_enhance/include
    c-flags += $(SEC_CFLAGS)
ifeq ($(chip_type), cs2)
inc-flags += -DCONFIG_HIEPS_BYPASS_TEST
endif

endif
endif


