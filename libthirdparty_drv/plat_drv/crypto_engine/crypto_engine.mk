ifeq ($(FEATURE_HISI_MSP_ENGINE_LIBCRYPTO), true)
    # crypto_engine build
    include $(dir $(lastword $(MAKEFILE_LIST)))Makefile
    inc-flags += -DCONFIG_HISI_MSP_ENGINE_LIBCRYPTO

    # crypto_engine dependencies
    ifneq ($(filter $(TARGET_BOARD_PLATFORM),baltimore lexington),)
        inc-flags += -DCONFIG_HISI_MSPE_SMMUV3
    endif
    ifneq ($(filter $(TARGET_BOARD_PLATFORM),burbank),)
        inc-flags += -DCONFIG_HISI_MSPE_SMMUV2 \
                     -DCONFIG_HISI_MSPE_POWER_SCHEME
    endif

    # HIAI mesp_decrypt
    inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/mesp_decrypt
    inc-flags += -I$(SOURCE_DIR)/platform/common/include/mailbox
    inc-flags += -I$(HI_PLAT_ROOT_DIR)/custom/include
    CFILES += platform/libthirdparty_drv/plat_drv/mesp_decrypt/mesp_decrypt.c
endif
