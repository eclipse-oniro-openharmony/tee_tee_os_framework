ifeq ($(WITH_ENG_VERSION),true)
inc-flags += -DTEE_SVM_DEBUG
endif
ifneq ($(product_type),lite)
inc-flags += -DTEE_SUPPORT_SVM
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secsvm/include
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secsvm/include/plat/$(TARGET_BOARD_PLATFORM)/
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secsvm/driver/
CFILES += platform/libthirdparty_drv/plat_drv/secsvm/driver/hisi_teesvm.c
CFILES += platform/libthirdparty_drv/plat_drv/secsvm/driver/hisi_teesvm_helper.c
endif
