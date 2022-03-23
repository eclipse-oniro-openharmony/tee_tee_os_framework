# hi3650
LIBS += dx_cc3670_sbrom
platdrv_LDFLAGS += -L$(SOURCE_DIR)/platform/kirin/ccdriver_lib
LIBS += sec_decoder
platdrv_LDFLAGS += -L$(SOURCE_DIR)/platform/kirin/vcodec/hi_vcodec/hi3670
